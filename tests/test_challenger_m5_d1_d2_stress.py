"""Adversarial stress and fail-closed security boundary verification for Demo D1 and Demo D2.

Authored by challenger_v6_M5_1 (Gate M5 Challenger 1).
Targets:
- Demo D1 (scripts/demo_d1_evm.py): Re-read branch, manifest corruption, bad proof, commitment mismatch, address/role spoofing.
- Demo D2 (scripts/demo_d2_host.py): First responder safety guardrails, shell injection, encoded PowerShell,
  path traversal, forbidden commands, canonical database write attempts & read-only enforcement.
- 100% bitwise invariance of the 4 canonical database files.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

for _cand_dir in (REPO_ROOT / "tools" / "foundry", Path(os.path.expanduser("~/.foundry/bin"))):
    if _cand_dir.is_dir() and str(_cand_dir) not in os.environ.get("PATH", ""):
        os.environ["PATH"] = f"{_cand_dir}{os.pathsep}{os.environ.get('PATH', '')}"

from scripts.demo_d1_evm import (
    DemoD1Runner,
    verify_canonical_invariance,
    CANONICAL_HASHES,
    compute_file_sha256,
    ALICE_ADDRESS,
    ALICE_PK,
    BOB_ADDRESS,
    BOB_PK,
)
from scripts.demo_d2_host import DemoD2Runner
from forensics.paths import REAL_P4_DB, FORENSICS_DB, BENCHMARK_DB, resolve_foundry_binary
from forensics.integrity import verify_package
from forensics.rules.engine import RuleEngine
from forensics.schemas import init_db
from forensics.zkml import ZKMLProver, ZKMLVerifier
from forensics.did.client import AnvilTestNode, DIDClient, ANVIL_DEFAULT_DEPLOYER, _run_cast
from forensics.did.eip712 import (
    ROLE_COLLECTOR,
    ROLE_ANALYST,
    ROLE_CUSTODIAN,
    build_custody_transfer_typed_data,
    sign_typed_data,
    verify_typed_signature,
)
from forensics.did.resolution import format_did
from forensics.endpoint.first_responder import (
    AIFirstResponder,
    SafetyGuard,
    ForbiddenActionCategory,
    DangerousActionError,
    ActionBlockedResult,
    TriagePlaybookType,
)
from forensics.endpoint.store import EndpointEvidenceStore, get_readonly_endpoint_connection
from forensics.ai.db_readonly import get_readonly_connection


# Test accounts
CHARLIE_ADDRESS = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
CHARLIE_PK = "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a"
EVE_ADDRESS = "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"
EVE_PK = "0x47b642441102935196f06433b3749c6ddbfa32e188921455447125e57d2c0ee1"


@pytest.fixture(scope="module")
def shared_temp_dir():
    d = Path(tempfile.mkdtemp(prefix="challenger_m5_"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


class TestD1ReReadAdversarialStress:
    """Adversarial stress testing against Demo D1 re-read branch, proofs, and custody."""

    def test_d1_reread_corrupted_manifest_fail_closed(self, shared_temp_dir):
        """Verify that any tampering with package manifest or contents fails package verification."""
        pkg_dir = shared_temp_dir / "pkg_d1_tamper_test"
        runner = DemoD1Runner(
            incident="euler",
            workspace_dir=REPO_ROOT,
            temp_dir=shared_temp_dir / "runner_temp_1",
        )
        manifest_file, manifest_sha, status = runner._build_rfc6962_package(pkg_dir)
        assert status == "VALID", "Baseline package should be VALID"

        # Case 1: Tamper with raw_blocks.jsonl on disk without updating manifest
        raw_blocks = pkg_dir / "raw_blocks.jsonl"
        original_blocks_bytes = raw_blocks.read_bytes()
        raw_blocks.write_bytes(original_blocks_bytes + b"\n{\"tampered\": true}")
        pkg_res_tampered_blocks = verify_package(manifest_file)
        assert pkg_res_tampered_blocks.status == "INVALID", "Tampered raw_blocks.jsonl must fail verification"
        raw_blocks.write_bytes(original_blocks_bytes)  # restore

        # Case 2: Tamper with asset_transfers.csv on disk
        asset_csv = pkg_dir / "asset_transfers.csv"
        original_csv_bytes = asset_csv.read_bytes()
        asset_csv.write_bytes(original_csv_bytes + b"\n999999,1,16818000,0x0,1678665600,0x0,0,0x0,0x0,0x0,1000,0")
        pkg_res_tampered_csv = verify_package(manifest_file)
        assert pkg_res_tampered_csv.status == "INVALID", "Tampered asset_transfers.csv must fail verification"
        asset_csv.write_bytes(original_csv_bytes)  # restore

        # Case 3: Tamper with manifest.json package_digest
        manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
        original_digest = manifest_data["package_digest"]
        manifest_data["package_digest"] = "00" * 32
        manifest_file.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
        pkg_res_tampered_digest = verify_package(manifest_file)
        assert pkg_res_tampered_digest.status == "INVALID", "Corrupted package_digest must fail verification"

        # Case 4: Tamper with block_range in manifest.json
        manifest_data["package_digest"] = original_digest
        manifest_data["block_range"]["start_block"] = 999999
        manifest_file.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
        pkg_res_tampered_range = verify_package(manifest_file)
        assert pkg_res_tampered_range.status == "INVALID", "Tampered block_range must fail verification"

    def test_d1_reread_onchain_manifest_mismatch_detection(self, shared_temp_dir):
        """Verify on-chain verifyEvidence strictly rejects tampered manifest hashes fail-closed."""
        with AnvilTestNode(chain_id=31337) as node:
            client = DIDClient(rpc_url=node.rpc_url, chain_id=31337)
            contract_addr = client.deploy_registry(deployer_address=ANVIL_DEFAULT_DEPLOYER)
            client.grant_role(ALICE_ADDRESS, ROLE_COLLECTOR, sender=ANVIL_DEFAULT_DEPLOYER)
            client.grant_role(ALICE_ADDRESS, ROLE_CUSTODIAN, sender=ANVIL_DEFAULT_DEPLOYER)

            genuine_manifest_hash = "0x" + "aa" * 32
            tampered_manifest_hash = "0x" + "bb" * 32
            case_id_b32 = "0x" + hashlib.sha256(b"CASE-D1-TEST").hexdigest()

            ev_id = client.register_evidence(
                case_id_bytes32=case_id_b32,
                manifest_sha256=genuine_manifest_hash,
                storage_uri="evidence://d1/manifest.json",
                sender=ALICE_ADDRESS,
            )
            assert ev_id >= 1

            # Query with genuine manifest hash -> true
            res_valid = _run_cast([
                "call", contract_addr,
                "verifyEvidence(uint256,bytes32)(bool,address,uint256)",
                str(ev_id),
                genuine_manifest_hash,
                "--rpc-url", node.rpc_url,
            ])
            assert "true" in res_valid.lower()

            # Query with tampered manifest hash -> false
            res_tampered = _run_cast([
                "call", contract_addr,
                "verifyEvidence(uint256,bytes32)(bool,address,uint256)",
                str(ev_id),
                tampered_manifest_hash,
                "--rpc-url", node.rpc_url,
            ])
            assert "false" in res_tampered.lower()

    def test_d1_reread_transfers_tampering_diverges_alerts(self, shared_temp_dir):
        """Verify that altering re-read asset transfers changes alert outcomes, proving detection is dynamic."""
        runner = DemoD1Runner(incident="euler", workspace_dir=REPO_ROOT, temp_dir=shared_temp_dir / "reread_engine")
        pkg_dir = shared_temp_dir / "reread_engine" / "pkg"
        runner._build_rfc6962_package(pkg_dir)

        # Baseline alerts from read-only canonical DB
        with sqlite3.connect(f"file:{REAL_P4_DB.as_posix()}?mode=ro&immutable=1", uri=True) as ro_conn:
            engine_base = RuleEngine(db_path_or_conn=ro_conn, chain_id=1)
            baseline_alerts = engine_base.run(
                test_start_block=runner.test_start,
                test_end_block=runner.test_end,
                cal_start_block=runner.cal_start,
                cal_end_block=runner.cal_end,
                persist=False,
            )
        assert len(baseline_alerts) > 0

        # Load transfers and zero out all amounts (simulating evidence alteration attack)
        tampered_db = shared_temp_dir / "tampered_transfers.db"
        conn = init_db(tampered_db)

        # Load genuine blocks
        with open(pkg_dir / "raw_blocks.jsonl", "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    b = json.loads(line)
                    conn.execute(
                        "INSERT INTO blocks (chain_id, number, hash, parent_hash, status, raw_json, raw_sha256) "
                        "VALUES (?, ?, ?, ?, 'canonical', '{}', '0x0')",
                        (b.get("chain_id", 1), b["number"], b["hash"], b.get("parent_hash", "0x0")),
                    )

        # Load tampered transfers where amount_raw is zeroed out
        with open(pkg_dir / "asset_transfers.csv", "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for r in reader:
                conn.execute(
                    "INSERT INTO asset_transfers "
                    "(chain_id, block_number, block_hash, tx_hash, log_index, asset_id, from_addr, to_addr, amount_raw, synthetic, block_timestamp) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        int(r.get("chain_id", 1)),
                        int(r.get("block_number", runner.test_start)),
                        r.get("block_hash", "0xblockhash"),
                        r.get("tx_hash", "0xtxhash"),
                        int(r.get("log_index", 0)),
                        r.get("asset_id", "0x0"),
                        r.get("from_addr", ""),
                        r.get("to_addr", ""),
                        "0",  # Zeroed out amount
                        0,
                        int(r.get("block_timestamp", 1678665600)),
                    ),
                )
        conn.commit()

        engine_tampered = RuleEngine(db_path_or_conn=conn, chain_id=1)
        tampered_alerts = engine_tampered.run(
            test_start_block=runner.test_start,
            test_end_block=runner.test_end,
            persist=False,
        )
        conn.close()

        # The alerts generated from zeroed amounts must diverge from baseline alerts
        baseline_rules = {a.rule_id for a in baseline_alerts}
        tampered_rules = {a.rule_id for a in tampered_alerts}
        assert baseline_rules != tampered_rules or len(tampered_alerts) < len(baseline_alerts), (
            "RuleEngine did not reflect tampered transfer amounts; alerts did not diverge."
        )

    def test_d1_zkml_tampering_offline_and_onchain(self):
        """Verify ZKML proof tampering fails offline verifier and real BN254 Halo2 on-chain verifier."""
        model_path = REPO_ROOT / "models" / "anomaly_detector_v1.onnx"
        assert model_path.exists(), f"ZKML model missing: {model_path}"

        prover = ZKMLProver(model_path=model_path, auto_setup=True)
        dummy_features = [0.5] * 10
        proof_res = prover.prove(dummy_features)
        assert proof_res.is_valid is True
        assert len(proof_res.proof_bytes) == 5504

        verifier = ZKMLVerifier(
            settings_path=prover.settings_path,
            vk_path=prover.vk_path,
            srs_path=prover.srs_path,
            expected_model_hash=prover.model_hash,
        )

        assert verifier.verify(proof_res, feature_vector=dummy_features) is True

        corrupted_bytes = bytearray(proof_res.proof_bytes)
        corrupted_bytes[100] ^= 0xFF
        from forensics.zkml import ProofResult
        corrupted_proof = ProofResult(
            proof_bytes=bytes(corrupted_bytes),
            public_inputs=proof_res.public_inputs,
            output_score=proof_res.output_score,
            input_commitment=proof_res.input_commitment,
            output_commitment=proof_res.output_commitment,
            model_hash=proof_res.model_hash,
            circuit_version=proof_res.circuit_version,
            is_valid=True,
            proof_time_sec=proof_res.proof_time_sec,
        )
        assert verifier.verify(corrupted_proof, feature_vector=dummy_features) is False

        altered_features = [1.0] * 10
        assert verifier.verify(proof_res, feature_vector=altered_features) is False

        with AnvilTestNode(chain_id=31337) as node:
            cast_bin = resolve_foundry_binary("cast")
            forge_bin = resolve_foundry_binary("forge")
            input_comm_hex = "0x" + proof_res.input_commitment.removeprefix("0x")
            output_comm = proof_res.output_commitment
            instances_arg = "[" + ",".join(str(x) for x in proof_res.evm_instances) + "]"

            res_circ = subprocess.run([
                forge_bin, "create", "src/Halo2Verifier.sol:Halo2Verifier",
                "--root", "contracts",
                "--rpc-url", node.rpc_url, "--unlocked", "--from", ANVIL_DEFAULT_DEPLOYER,
                "--broadcast",
            ], capture_output=True, text=True, check=True, cwd=str(REPO_ROOT))
            circuit_verifier_addr = re.search(r"Deployed to:\s*(0x[0-9a-fA-F]{40})", res_circ.stdout).group(1)

            res_inf = subprocess.run([
                forge_bin, "create", "src/InferenceVerifier.sol:InferenceVerifier",
                "--root", "contracts",
                "--rpc-url", node.rpc_url, "--unlocked", "--from", ANVIL_DEFAULT_DEPLOYER,
                "--broadcast", "--constructor-args", circuit_verifier_addr, proof_res.model_hash, "true",
            ], capture_output=True, text=True, check=True, cwd=str(REPO_ROOT))
            inf_verifier_addr = re.search(r"Deployed to:\s*(0x[0-9a-fA-F]{40})", res_inf.stdout).group(1)

            res_ok = subprocess.run([
                cast_bin, "send", inf_verifier_addr,
                "verifyInferenceProofWithInstances(bytes,uint256[],bytes32,bytes32,bytes32,string)",
                proof_res.hex_proof, instances_arg, proof_res.model_hash, input_comm_hex, output_comm, "BASELINE-OK",
                "--rpc-url", node.rpc_url, "--unlocked", "--from", ANVIL_DEFAULT_DEPLOYER,
            ], capture_output=True, text=True)
            assert res_ok.returncode == 0, f"Genuine proof failed on-chain: {res_ok.stderr}"

            tampered_hex = "0x" + ("00" if proof_res.hex_proof[2:4] != "00" else "ff") + proof_res.hex_proof[4:]
            res_tamper_proof = subprocess.run([
                cast_bin, "send", inf_verifier_addr,
                "verifyInferenceProofWithInstances(bytes,uint256[],bytes32,bytes32,bytes32,string)",
                tampered_hex, instances_arg, proof_res.model_hash, input_comm_hex, output_comm, "TAMPER-1",
                "--rpc-url", node.rpc_url, "--unlocked", "--from", ANVIL_DEFAULT_DEPLOYER,
            ], capture_output=True, text=True)
            assert res_tamper_proof.returncode != 0, "Tampered proof bytes must revert on-chain"

            bad_in_comm = "0x" + "11" * 32
            res_tamper_in = subprocess.run([
                cast_bin, "send", inf_verifier_addr,
                "verifyInferenceProofWithInstances(bytes,uint256[],bytes32,bytes32,bytes32,string)",
                proof_res.hex_proof, instances_arg, proof_res.model_hash, bad_in_comm, output_comm, "TAMPER-2",
                "--rpc-url", node.rpc_url, "--unlocked", "--from", ANVIL_DEFAULT_DEPLOYER,
            ], capture_output=True, text=True)
            assert res_tamper_in.returncode != 0, "Tampered input commitment must revert on-chain"

            bad_model_hash = "0x" + "22" * 32
            res_tamper_model = subprocess.run([
                cast_bin, "send", inf_verifier_addr,
                "verifyInferenceProofWithInstances(bytes,uint256[],bytes32,bytes32,bytes32,string)",
                proof_res.hex_proof, instances_arg, bad_model_hash, input_comm_hex, output_comm, "TAMPER-3",
                "--rpc-url", node.rpc_url, "--unlocked", "--from", ANVIL_DEFAULT_DEPLOYER,
            ], capture_output=True, text=True)
            assert res_tamper_model.returncode != 0, "Tampered model hash must revert on-chain"

    def test_d1_custody_address_and_role_spoofing(self):
        """Verify that unauthorized signers and spoofed roles are rejected on-chain and off-chain."""
        with AnvilTestNode(chain_id=31337) as node:
            client = DIDClient(rpc_url=node.rpc_url, chain_id=31337)
            contract_addr = client.deploy_registry(deployer_address=ANVIL_DEFAULT_DEPLOYER)

            # Alice has Collector & Custodian; Bob has Analyst & Custodian; Eve has NO roles
            client.grant_role(ALICE_ADDRESS, ROLE_COLLECTOR, sender=ANVIL_DEFAULT_DEPLOYER)
            client.grant_role(ALICE_ADDRESS, ROLE_CUSTODIAN, sender=ANVIL_DEFAULT_DEPLOYER)
            client.grant_role(BOB_ADDRESS, ROLE_ANALYST, sender=ANVIL_DEFAULT_DEPLOYER)
            client.grant_role(BOB_ADDRESS, ROLE_CUSTODIAN, sender=ANVIL_DEFAULT_DEPLOYER)

            # Attack 1: Eve attempts to register evidence without ROLE_COLLECTOR
            case_id = "0x" + hashlib.sha256(b"CASE-UNAUTH").hexdigest()
            eve_reg_failed = False
            try:
                client.register_evidence(
                    case_id_bytes32=case_id,
                    manifest_sha256="0x" + "aa" * 32,
                    storage_uri="evidence://unauth",
                    sender=EVE_ADDRESS,
                )
            except RuntimeError:
                eve_reg_failed = True
            assert eve_reg_failed is True, "Unauthorized evidence registration by Eve must revert"

            # Alice registers genuine evidence
            ev_id = client.register_evidence(
                case_id_bytes32=case_id,
                manifest_sha256="0x" + "aa" * 32,
                storage_uri="evidence://valid",
                sender=ALICE_ADDRESS,
            )

            # Attack 2: Eve signs custody transfer pretending to be Alice
            alice_nonce = client.get_nonce(ALICE_ADDRESS)
            note_hash = "0x" + hashlib.sha256(b"spoof").hexdigest()
            deadline = int(time.time()) + 3600

            typed_data = build_custody_transfer_typed_data(
                verifying_contract=contract_addr,
                chain_id=31337,
                evidence_id=ev_id,
                from_custodian=ALICE_ADDRESS,
                to_custodian=BOB_ADDRESS,
                artifact_sha256="0x" + "aa" * 32,
                note_hash=note_hash,
                nonce=alice_nonce,
                deadline=deadline,
            )
            # Eve signs typed data with her own private key
            eve_sig = sign_typed_data(typed_data, private_key=EVE_PK)

            # Off-chain signature verification fails
            assert verify_typed_signature(ALICE_ADDRESS, typed_data, eve_sig) is False

            # On-chain custody transfer with Eve's signature fails
            eve_handover_failed = False
            try:
                client.transfer_custody_with_sig(
                    evidence_id=ev_id,
                    from_custodian=ALICE_ADDRESS,
                    to_custodian=BOB_ADDRESS,
                    artifact_sha256="0x" + "aa" * 32,
                    note_hash=note_hash,
                    nonce=alice_nonce,
                    deadline=deadline,
                    signature=eve_sig,
                    sender=BOB_ADDRESS,
                )
            except RuntimeError:
                eve_handover_failed = True
            assert eve_handover_failed is True, "Transfer with spoofed signature must revert on-chain"


class TestD2GuardrailsAdversarialStress:
    """Adversarial stress testing against Demo D2 AI First Responder guardrails and DB protections."""

    def test_d2_guardrails_shell_injection(self, shared_temp_dir):
        """Verify shell injection variants are blocked fail-closed."""
        store_db = shared_temp_dir / "ep_test.db"
        store = EndpointEvidenceStore(db_path=store_db)
        responder = AIFirstResponder(evidence_store=store)

        shell_vectors = [
            ("triage_running_processes", {"name_filter": "svchost.exe; cmd.exe /c whoami"}),
            ("triage_running_processes", {"name_filter": "calc.exe | powershell.exe -Command whoami"}),
            ("triage_running_processes", {"name_filter": "test.exe && calc.exe"}),
            ("triage_running_processes", {"name_filter": "test.exe || cmd /c calc"}),
            ("triage_running_processes", {"name_filter": "proc $(whoami)"}),
            ("triage_running_processes", {"name_filter": "proc `whoami`"}),
            ("triage_hash_verification", {"file_path": "C:\\test.evtx & del /F /Q C:\\Windows\\*"}),
            ("triage_hash_verification", {"file_path": "C:\\test.evtx; calc.exe"}),
            ("triage_hash_verification", {"file_path": "C:\\test.evtx | cmd.exe"}),
            ("triage_hash_verification", {"file_path": "C:\\test.evtx > C:\\pwned.txt"}),
        ]

        for action_name, params in shell_vectors:
            # 1. SafetyGuard evaluation directly
            is_safe, category, reason = SafetyGuard.evaluate(action_name, params)
            assert is_safe is False, f"SafetyGuard failed to block shell vector: {params}"
            assert category == ForbiddenActionCategory.ARBITRARY_SHELL, f"Expected ARBITRARY_SHELL for {params}, got {category}"

            # 2. FirstResponder execute_action
            res = responder.execute_action(action_name, **params)
            assert isinstance(res, ActionBlockedResult), f"Expected ActionBlockedResult for {params}, got {type(res)}"
            assert res.blocked is True
            assert res.category == ForbiddenActionCategory.ARBITRARY_SHELL

    def test_d2_guardrails_encoded_powershell(self, shared_temp_dir):
        """Verify encoded PowerShell commands are blocked fail-closed."""
        store_db = shared_temp_dir / "ep_test_ps.db"
        store = EndpointEvidenceStore(db_path=store_db)
        responder = AIFirstResponder(evidence_store=store)

        ps_vectors = [
            ("triage_running_processes", {"name_filter": "powershell.exe -enc JABhID0A"}),
            ("triage_running_processes", {"name_filter": "pwsh.exe -EncodedCommand JABhID0A"}),
            ("triage_running_processes", {"name_filter": "powershell.exe -e JABhID0A"}),
            ("triage_running_processes", {"name_filter": "powershell.exe -command IEX(New-Object Net.WebClient)"}),
            ("triage_recent_system_events", {"channel": "System -enc JABhID0A"}),
            ("triage_hash_verification", {"file_path": "C:\\script.ps1 -enc JABhID0A"}),
        ]

        for action_name, params in ps_vectors:
            is_safe, category, _ = SafetyGuard.evaluate(action_name, params)
            assert is_safe is False, f"Failed to block encoded powershell: {params}"
            assert category == ForbiddenActionCategory.ARBITRARY_SHELL

            res = responder.execute_action(action_name, **params)
            assert isinstance(res, ActionBlockedResult) and res.blocked is True

    def test_d2_guardrails_path_traversal_and_sensitive_files(self, shared_temp_dir):
        """Verify path traversal and access to sensitive secrets/SAM hives are blocked fail-closed."""
        store_db = shared_temp_dir / "ep_test_paths.db"
        store = EndpointEvidenceStore(db_path=store_db)
        responder = AIFirstResponder(evidence_store=store)

        traversal_vectors = [
            ("triage_hash_verification", {"file_path": "../../../../Windows/System32/config/SAM"}),
            ("triage_hash_verification", {"file_path": "..\\..\\..\\Windows\\System32\\config\\SYSTEM"}),
            ("triage_hash_verification", {"file_path": "/etc/shadow"}),
            ("triage_hash_verification", {"file_path": "/etc/passwd"}),
            ("triage_hash_verification", {"file_path": str(REPO_ROOT / ".env")}),
            ("triage_hash_verification", {"file_path": "C:\\Users\\victim\\.ethereum\\keystore\\key.json"}),
            ("triage_hash_verification", {"file_path": "id_rsa"}),
            ("triage_hash_verification", {"file_path": "private_key.pem"}),
        ]

        for action_name, params in traversal_vectors:
            is_safe, category, _ = SafetyGuard.evaluate(action_name, params)
            assert is_safe is False, f"Failed to block sensitive path access: {params}"
            assert category in (ForbiddenActionCategory.KEY_SIGNING, ForbiddenActionCategory.FILE_MODIFICATION_OR_DELETION), (
                f"Unexpected category {category} for {params}"
            )

            res = responder.execute_action(action_name, **params)
            assert isinstance(res, ActionBlockedResult) and res.blocked is True

    def test_d2_guardrails_forbidden_commands(self, shared_temp_dir):
        """Verify event log clearing, network isolation, ACL alteration, and deletion commands are blocked."""
        store_db = shared_temp_dir / "ep_test_cmds.db"
        store = EndpointEvidenceStore(db_path=store_db)
        responder = AIFirstResponder(evidence_store=store)

        forbidden_vectors = [
            # Event log clearing
            ("triage_recent_system_events", {"channel": "wevtutil cl System"}, ForbiddenActionCategory.EVENT_LOG_CLEARING),
            ("triage_recent_system_events", {"channel": "Clear-EventLog -LogName System"}, ForbiddenActionCategory.EVENT_LOG_CLEARING),
            # Automated network isolation
            ("Disable-NetAdapter -Name Ethernet0", {}, ForbiddenActionCategory.AUTOMATED_NETWORK_ISOLATION),
            ("netsh advfirewall set allprofiles state off", {}, ForbiddenActionCategory.AUTOMATED_NETWORK_ISOLATION),
            # ACL alteration
            ("icacls C:\\Windows /grant Everyone:F", {}, ForbiddenActionCategory.ACL_ALTERATION),
            ("chmod 777 /etc/passwd", {}, ForbiddenActionCategory.ACL_ALTERATION),
            # Destructive file ops
            ("del /F /Q C:\\Windows\\System32\\*", {}, ForbiddenActionCategory.FILE_MODIFICATION_OR_DELETION),
            ("rm -rf /", {}, ForbiddenActionCategory.FILE_MODIFICATION_OR_DELETION),
        ]

        for action_name, params, expected_cat in forbidden_vectors:
            is_safe, category, _ = SafetyGuard.evaluate(action_name, params)
            assert is_safe is False, f"SafetyGuard allowed forbidden command: {action_name} {params}"
            assert category == expected_cat, f"Category mismatch: expected {expected_cat}, got {category}"

            res = responder.execute_action(action_name, **params)
            assert isinstance(res, ActionBlockedResult) and res.blocked is True
            assert res.category == expected_cat

    def test_d2_guardrails_canonical_database_write_prevention(self):
        """Verify that attempts to write, alter, or drop tables on canonical databases fail immediately."""
        canonical_targets = [REAL_P4_DB, FORENSICS_DB, BENCHMARK_DB]
        write_queries = [
            "INSERT INTO blocks (number) VALUES (99999999)",
            "UPDATE blocks SET status = 'corrupted' WHERE number > 0",
            "DELETE FROM blocks WHERE number > 0",
            "DROP TABLE blocks",
            "CREATE TABLE injected_table (id INT)",
            "ALTER TABLE blocks ADD COLUMN pwned TEXT",
        ]

        for db_file in canonical_targets:
            assert db_file.exists(), f"Target DB does not exist: {db_file}"
            with get_readonly_connection(db_file) as ro_conn:
                for sql in write_queries:
                    with pytest.raises(sqlite3.OperationalError):
                        ro_conn.execute(sql)

    def test_canonical_database_invariance_post_stress(self):
        """Verify 100% bitwise invariance of the 4 canonical targets after all stress probes."""
        results = verify_canonical_invariance(REPO_ROOT)
        assert len(results) == 4
        for name, info in results.items():
            assert info["match"] is True, f"CANONICAL INVARIANCE VIOLATED on {name}: {info}"
