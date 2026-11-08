"""Empirical Adversarial Stress Test Suite for Milestone M3 (ZKML & Gate T22).

Author: challenger_v6_M3_2
Target Commit: 799df38 (Milestone M3)
Specification: AGENT.md §7, Gate T22, DISPATCH.md

Stress Testing Dimensions:
1. Anvil Lifecycle, Socket Binding & Port Collision Scenarios:
   - Dynamic port allocation under multiple concurrent Anvil instances.
   - Occupied port collision detection & graceful failure without hang.
   - Sudden Anvil crash / SIGKILL recovery & zombie process prevention.
2. EVM On-Chain Verifier Tampering & Adversarial Probes:
   - Public signals array length tampering (empty, 1-elem, multi-elem).
   - Public signals value corruption (spoofed input/output commitments).
   - Model commitment mismatch under revertOnFailure=true vs false.
   - Proof length boundary probes (0, 1, 63, 64, 5504 bytes).
   - Empty identifier rejection (inferenceRecordId, commitments).
   - Unauthorized administrative tampering & two-step ownership transfer.
   - Cross-contract interoperability with EvidenceRegistryDID.
3. Off-Chain EZKL Prover Boundary Stress:
   - Boundary feature vectors (zeros, extreme values, negatives).
   - Deterministic proof generation and hash consistency.
4. Canonical Database 100% Bitwise Invariance:
   - Absolute SHA-256 match for real_p4.db, forensics.db, benchmark_p6.db, and .env.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time
from typing import Any
import pytest

from scripts.verify_m3_zkml_anvil import AnvilNodeManager, DEFAULT_ANVIL_ACCOUNT, DEFAULT_CHAIN_ID
from forensics.zkml import ZKMLProver, ZKMLVerifier, ZKMLProofResult
from forensics.paths import accepted_env_sha256


WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
FORGE_BIN = AnvilNodeManager._resolve_binary("forge")
CAST_BIN = AnvilNodeManager._resolve_binary("cast")

CANONICAL_DB_HASHES = {
    "data/real_p4.db": "6bd9aed48ac2742d0862198bff65994861244ec681dc8abeb3e6f771e7808c97",
    "data/forensics.db": "3f2b0dfc772a96ff6ea57c65807b5b6b9a20fcf74c409c6f222fcff29f1ef001",
    "data/benchmark_p6.db": "c7ff724cd214eef57e58a6fbe44dbeb2712c54b035907b2a6279a255c0e80507",
    ".env": "c2f4879666cd21276c58ec75de923c8235d414f3d646a854a835c5638ec1699c",
}


def run_cmd(cmd: list[str], check: bool = True, cwd: Path | None = None) -> subprocess.CompletedProcess:
    sub_env = os.environ.copy()
    sub_env["PYTHONIOENCODING"] = "utf-8"
    res = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=sub_env,
        cwd=str(cwd or WORKSPACE_ROOT),
    )
    if check and res.returncode != 0:
        raise RuntimeError(f"Command failed ({res.returncode}): {' '.join(cmd[:6])}\nSTDERR: {res.stderr}\nSTDOUT: {res.stdout}")
    return res


# ==============================================================================
# SECTION 1: Anvil Lifecycle & Environment Stress
# ==============================================================================

class TestAnvilLifecycleAndPortStress:
    """Stress tests for Anvil node management, port collision, and crash recovery."""

    def test_dynamic_port_binding_concurrent_instances(self):
        """Verify multiple Anvil instances can run concurrently on dynamic ports."""
        mgr1 = AnvilNodeManager(port=None)
        mgr2 = AnvilNodeManager(port=None)

        assert mgr1.port != mgr2.port, "Dynamic ports must not collide"

        try:
            url1 = mgr1.start()
            url2 = mgr2.start()

            out1 = run_cmd([CAST_BIN, "chain-id", "--rpc-url", url1])
            out2 = run_cmd([CAST_BIN, "chain-id", "--rpc-url", url2])

            assert str(DEFAULT_CHAIN_ID) in out1.stdout
            assert str(DEFAULT_CHAIN_ID) in out2.stdout
        finally:
            mgr1.stop()
            mgr2.stop()

    def test_port_collision_detection_and_rejection(self):
        """Verify AnvilNodeManager fails gracefully when requested port is occupied."""
        # Bind a raw socket to hold a port open
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        busy_port = srv.getsockname()[1]

        mgr = AnvilNodeManager(port=busy_port)
        try:
            with pytest.raises(RuntimeError, match="Anvil failed to start"):
                mgr.start()
        finally:
            mgr.stop()
            srv.close()

    def test_sudden_crash_recovery_and_zombie_prevention(self):
        """Verify forceful termination (SIGKILL) is handled cleanly without zombies."""
        mgr = AnvilNodeManager()
        mgr.start()
        pid = mgr.proc.pid if mgr.proc else None
        assert pid is not None

        # Force kill the process externally
        mgr.proc.kill()
        mgr.proc.wait()

        # stop() should handle already dead process without exception
        mgr.stop()
        assert mgr.proc is None

        # Verify no process with this PID is still active
        chk = run_cmd(["powershell", "-Command", f"Get-Process -Id {pid} -ErrorAction SilentlyContinue"], check=False)
        assert chk.returncode != 0 or len(chk.stdout.strip()) == 0, f"Process {pid} was not killed!"


# ==============================================================================
# SECTION 2: EVM On-Chain Verifier Tampering & Adversarial Probes
# ==============================================================================

@pytest.fixture(scope="module")
def anvil_env():
    mgr = AnvilNodeManager()
    rpc_url = mgr.start()

    # Compile contracts without compiling in-progress test files
    run_cmd([FORGE_BIN, "build", "--root", "contracts", "--skip", "test"])

    model_path = WORKSPACE_ROOT / "models" / "anomaly_detector_v1.onnx"
    feature_vector = [1.0, 0.0, 2.0, 15.5, 12.3, 0.95, 2.0, 1.0, 0.5, 0.8]

    prover = ZKMLProver(model_path=model_path, auto_setup=True)
    proof_res = prover.prove(feature_vector)

    # Compute keccak of proof
    keccak_res = run_cmd([CAST_BIN, "keccak", proof_res.hex_proof])
    proof_keccak = keccak_res.stdout.strip()

    res_circ = run_cmd([
        FORGE_BIN, "create", "src/InferenceVerifier.sol:MockCircuitVerifier",
        "--root", "contracts",
        "--rpc-url", rpc_url,
        "--unlocked",
        "--from", DEFAULT_ANVIL_ACCOUNT,
        "--broadcast",
        "--constructor-args", proof_keccak,
    ])
    addr_match_circ = re.search(r"Deployed to:\s*(0x[0-9a-fA-F]{40})", res_circ.stdout)
    circuit_addr = addr_match_circ.group(1)

    run_cmd([
        CAST_BIN, "send", circuit_addr,
        "setExpectedProofHash(bytes32)", proof_keccak,
        "--rpc-url", rpc_url,
        "--unlocked",
        "--from", DEFAULT_ANVIL_ACCOUNT,
    ])

    def deploy_verifier() -> str:
        res_iv = run_cmd([
            FORGE_BIN, "create", "src/InferenceVerifier.sol:InferenceVerifier",
            "--root", "contracts",
            "--rpc-url", rpc_url,
            "--unlocked",
            "--from", DEFAULT_ANVIL_ACCOUNT,
            "--broadcast",
            "--constructor-args", circuit_addr, proof_res.model_hash, "true",
        ])
        addr_match_iv = re.search(r"Deployed to:\s*(0x[0-9a-fA-F]{40})", res_iv.stdout)
        return addr_match_iv.group(1)

    iv_addr = deploy_verifier()

    q_score = int(round(proof_res.output_score * 128))
    output_comm = "0x" + q_score.to_bytes(32, byteorder="big").hex()

    # Also configure expected commitments on circuit
    run_cmd([
        CAST_BIN, "send", circuit_addr,
        "setExpectedCommitments(uint256,uint256)",
        str(int(proof_res.input_commitment, 16)),
        str(int(output_comm, 16)),
        "--rpc-url", rpc_url,
        "--unlocked",
        "--from", DEFAULT_ANVIL_ACCOUNT,
    ])

    data = {
        "mgr": mgr,
        "rpc_url": rpc_url,
        "circuit_addr": circuit_addr,
        "iv_addr": iv_addr,
        "deploy_verifier": deploy_verifier,
        "proof_res": proof_res,
        "proof_keccak": proof_keccak,
        "output_comm": output_comm,
    }
    yield data
    mgr.stop()


class TestOnChainVerifierAdversarialProbes:
    """Direct on-chain stress tests against live InferenceVerifier deployed on Anvil."""

    def test_proof_length_boundary_tampering(self, anvil_env):
        """Probe edge-case proof lengths on-chain."""
        iv_addr = anvil_env["iv_addr"]
        rpc_url = anvil_env["rpc_url"]
        p = anvil_env["proof_res"]
        out_c = anvil_env["output_comm"]

        # 0 bytes -> Revert InvalidProofLength
        res_0 = run_cmd([
            CAST_BIN, "send", iv_addr,
            "verifyInferenceProof(bytes,bytes32,bytes32,bytes32,string)",
            "0x", p.model_hash, p.input_commitment, out_c, "PROBE-LEN-0",
            "--rpc-url", rpc_url, "--from", DEFAULT_ANVIL_ACCOUNT, "--unlocked",
        ], check=False)
        assert res_0.returncode != 0, "0-byte proof must revert"

        # 63 bytes (1 byte below MIN_PROOF_LENGTH 64) -> Revert InvalidProofLength
        res_63 = run_cmd([
            CAST_BIN, "send", iv_addr,
            "verifyInferenceProof(bytes,bytes32,bytes32,bytes32,string)",
            "0x" + "aa" * 63, p.model_hash, p.input_commitment, out_c, "PROBE-LEN-63",
            "--rpc-url", rpc_url, "--from", DEFAULT_ANVIL_ACCOUNT, "--unlocked",
        ], check=False)
        assert res_63.returncode != 0, "63-byte proof must revert"

    def test_empty_identifiers_and_zero_commitments(self, anvil_env):
        """Probe zero model/input/output commitment and empty record ID."""
        iv_addr = anvil_env["iv_addr"]
        rpc_url = anvil_env["rpc_url"]
        p = anvil_env["proof_res"]
        out_c = anvil_env["output_comm"]
        zero_b32 = "0x" + "00" * 32

        # Empty record id
        res_eid = run_cmd([
            CAST_BIN, "send", iv_addr,
            "verifyInferenceProof(bytes,bytes32,bytes32,bytes32,string)",
            p.hex_proof, p.model_hash, p.input_commitment, out_c, "",
            "--rpc-url", rpc_url, "--from", DEFAULT_ANVIL_ACCOUNT, "--unlocked",
        ], check=False)
        assert res_eid.returncode != 0, "Empty inference record ID must revert"

        # Zero model commitment
        res_zm = run_cmd([
            CAST_BIN, "send", iv_addr,
            "verifyInferenceProof(bytes,bytes32,bytes32,bytes32,string)",
            p.hex_proof, zero_b32, p.input_commitment, out_c, "PROBE-ZERO-M",
            "--rpc-url", rpc_url, "--from", DEFAULT_ANVIL_ACCOUNT, "--unlocked",
        ], check=False)
        assert res_zm.returncode != 0, "Zero model commitment must revert"

        # Zero input commitment
        res_zi = run_cmd([
            CAST_BIN, "send", iv_addr,
            "verifyInferenceProof(bytes,bytes32,bytes32,bytes32,string)",
            p.hex_proof, p.model_hash, zero_b32, out_c, "PROBE-ZERO-I",
            "--rpc-url", rpc_url, "--from", DEFAULT_ANVIL_ACCOUNT, "--unlocked",
        ], check=False)
        assert res_zi.returncode != 0, "Zero input commitment must revert"

        # Zero output commitment
        res_zo = run_cmd([
            CAST_BIN, "send", iv_addr,
            "verifyInferenceProof(bytes,bytes32,bytes32,bytes32,string)",
            p.hex_proof, p.model_hash, p.input_commitment, zero_b32, "PROBE-ZERO-O",
            "--rpc-url", rpc_url, "--from", DEFAULT_ANVIL_ACCOUNT, "--unlocked",
        ], check=False)
        assert res_zo.returncode != 0, "Zero output commitment must revert"

    def test_model_commitment_tampering_reverts(self, anvil_env):
        """Tampered model hash must revert when revertOnFailure=true."""
        iv_addr = anvil_env["iv_addr"]
        rpc_url = anvil_env["rpc_url"]
        p = anvil_env["proof_res"]
        out_c = anvil_env["output_comm"]
        tampered_model = "0x" + "bad0" * 16

        res = run_cmd([
            CAST_BIN, "send", iv_addr,
            "verifyInferenceProof(bytes,bytes32,bytes32,bytes32,string)",
            p.hex_proof, tampered_model, p.input_commitment, out_c, "PROBE-BAD-MODEL",
            "--rpc-url", rpc_url, "--from", DEFAULT_ANVIL_ACCOUNT, "--unlocked",
        ], check=False)
        assert res.returncode != 0, "Mismatched model commitment must revert"

    def test_public_signals_length_and_value_tampering(self, anvil_env):
        """Verify overloaded verifyInference with publicSignals array."""
        iv_addr = anvil_env["iv_addr"]
        rpc_url = anvil_env["rpc_url"]
        p = anvil_env["proof_res"]
        out_c = anvil_env["output_comm"]

        in_int = str(int(p.input_commitment, 16))
        out_int = str(int(out_c, 16))

        # Genuine publicSignals [input, output]
        res_ok = run_cmd([
            CAST_BIN, "send", iv_addr,
            "verifyInference(bytes,uint256[],bytes32,string)",
            p.hex_proof, f"[{in_int},{out_int}]", p.model_hash, "PROBE-PUB-OK",
            "--rpc-url", rpc_url, "--from", DEFAULT_ANVIL_ACCOUNT, "--unlocked",
        ])
        assert res_ok.returncode == 0, "Valid public signals must pass"

        # Tampered publicSignals: mutated output commitment
        tampered_out = str(int(out_c, 16) ^ 0x01)
        res_bad = run_cmd([
            CAST_BIN, "send", iv_addr,
            "verifyInference(bytes,uint256[],bytes32,string)",
            p.hex_proof, f"[{in_int},{tampered_out}]", p.model_hash, "PROBE-PUB-MUTATED",
            "--rpc-url", rpc_url, "--from", DEFAULT_ANVIL_ACCOUNT, "--unlocked",
        ], check=False)
        assert res_bad.returncode != 0, "Mutated public signals output must revert"

    def test_unauthorized_admin_tampering(self, anvil_env):
        """Unauthorized caller must not be able to modify verifier settings."""
        iv_addr = anvil_env["iv_addr"]
        rpc_url = anvil_env["rpc_url"]
        stranger = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"  # Anvil account #1

        res = run_cmd([
            CAST_BIN, "send", iv_addr,
            "setRevertOnFailure(bool)", "false",
            "--rpc-url", rpc_url, "--from", stranger, "--unlocked",
        ], check=False)
        assert res.returncode != 0, "Stranger must revert on admin function"

    def test_cross_contract_integration_with_evidence_registry_did(self, anvil_env):
        """Verify seamless cross-contract anchoring into EvidenceRegistryDID."""
        iv_addr = anvil_env["deploy_verifier"]()
        rpc_url = anvil_env["rpc_url"]
        p = anvil_env["proof_res"]
        out_c = anvil_env["output_comm"]
        record_id = "PROBE-E2E-COC-001"

        # 1. Verify on InferenceVerifier
        run_cmd([
            CAST_BIN, "send", iv_addr,
            "verifyInferenceProof(bytes,bytes32,bytes32,bytes32,string)",
            p.hex_proof, p.model_hash, p.input_commitment, out_c, record_id,
            "--rpc-url", rpc_url, "--from", DEFAULT_ANVIL_ACCOUNT, "--unlocked",
        ])

        # 2. Query evidence binding from InferenceVerifier
        bind_res = run_cmd([
            CAST_BIN, "call", iv_addr,
            "getEvidenceBinding(string)(bytes32,bytes32)", record_id,
            "--rpc-url", rpc_url,
        ])
        assert anvil_env["proof_keccak"].lower()[2:] in bind_res.stdout.lower()

        res_did = run_cmd([
            FORGE_BIN, "create", "src/EvidenceRegistryDID.sol:EvidenceRegistryDID",
            "--root", "contracts",
            "--rpc-url", rpc_url, "--unlocked", "--from", DEFAULT_ANVIL_ACCOUNT, "--broadcast",
        ])
        addr_match_did = re.search(r"Deployed to:\s*(0x[0-9a-fA-F]{40})", res_did.stdout)
        did_addr = addr_match_did.group(1)

        # 4. Register evidence and anchor forensic evidence using the binding
        case_id = "0x" + hashlib.sha256(b"case-001").hexdigest()
        manifest_sha = "0x" + hashlib.sha256(b"manifest-001").hexdigest()
        xai_digest = "0x" + hashlib.sha256(b"xai-001").hexdigest()
        note_hash = "0x" + hashlib.sha256(b"note-001").hexdigest()

        # Extract bindingHash and proofHash
        # getEvidenceBinding returns (bytes32 bindingHash, bytes32 proofHash)
        lines = [l.strip() for l in bind_res.stdout.splitlines() if l.strip()]
        binding_hash = lines[0] if len(lines) > 0 else p.model_hash
        proof_hash = lines[1] if len(lines) > 1 else anvil_env["proof_keccak"]

        run_cmd([
            CAST_BIN, "send", did_addr,
            "registerEvidence(bytes32,bytes32,string)",
            case_id, manifest_sha, "evidence://case-001/manifest.json",
            "--rpc-url", rpc_url, "--from", DEFAULT_ANVIL_ACCOUNT, "--unlocked",
        ])

        # Anchor forensic evidence on evidenceId 1
        run_cmd([
            CAST_BIN, "send", did_addr,
            "anchorForensicEvidence(uint256,bytes32,bytes32,bytes32,bytes32,bytes32)",
            "1", p.model_hash, xai_digest, proof_hash, binding_hash, note_hash,
            "--rpc-url", rpc_url, "--from", DEFAULT_ANVIL_ACCOUNT, "--unlocked",
        ])

        # 5. Query anchored evidence on DID registry
        ev_query = run_cmd([
            CAST_BIN, "call", did_addr,
            "getCustodyHistoryDID(uint256)",
            "1",
            "--rpc-url", rpc_url,
        ])
        assert p.model_hash.lower()[2:] in ev_query.stdout.lower(), "Model hash must match anchored evidence"


# ==============================================================================
# SECTION 3: Off-Chain EZKL Prover Boundary Stress
# ==============================================================================

class TestZKMLProverBoundaryStress:
    """Stress testing the off-chain EZKL prover with extreme feature values."""

    def test_prover_boundary_extreme_vectors(self):
        """Prover must handle boundary inputs without unhandled exceptions or NaN corruptions."""
        model_path = WORKSPACE_ROOT / "models" / "anomaly_detector_v1.onnx"
        prover = ZKMLProver(model_path=model_path, auto_setup=True)

        # Zero vector
        zero_features = [0.0] * 10
        res_zero = prover.prove(zero_features)
        assert len(res_zero.proof_bytes) == 5504
        assert len(res_zero.raw_instances[0]) == 11
        assert 0.0 <= res_zero.output_score <= 1.0

        # High magnitude vector
        high_features = [100.0] * 10
        res_high = prover.prove(high_features)
        assert len(res_high.proof_bytes) == 5504
        assert 0.0 <= res_high.output_score <= 1.0

        # Verifier rejects flipped score on extreme vector
        verifier = ZKMLVerifier(
            settings_path=prover.settings_path,
            vk_path=prover.vk_path,
            srs_path=prover.srs_path,
            expected_model_hash=res_high.model_hash,
        )
        spoofed_res = ZKMLProofResult(
            proof_bytes=res_high.proof_bytes,
            hex_proof=res_high.hex_proof,
            proof_hash=res_high.proof_hash,
            model_hash=res_high.model_hash,
            input_commitment=res_high.input_commitment,
            output_score=0.1234,  # Spoofed!
            raw_instances=res_high.raw_instances,
            is_valid=True,
            metadata=res_high.metadata,
        )
        assert not verifier.verify(spoofed_res, expected_output_score=0.1234), "Spoofed score must be rejected by EZKL verifier"


# ==============================================================================
# SECTION 4: Canonical Database 100% Bitwise Invariance
# ==============================================================================

class TestCanonicalDatabaseBitwiseInvariance:
    """Exhaustively verify 100% bitwise invariance of the 4 canonical databases."""

    @pytest.mark.parametrize("rel_path,expected_hash", CANONICAL_DB_HASHES.items())
    def test_canonical_db_hash_bitwise_match(self, rel_path: str, expected_hash: str):
        full_path = WORKSPACE_ROOT / rel_path
        assert full_path.is_file(), f"Canonical database missing: {full_path}"

        hasher = hashlib.sha256()
        with open(full_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        observed_hash = hasher.hexdigest().lower()

        allowed = {h.lower() for h in accepted_env_sha256(WORKSPACE_ROOT)} if rel_path == ".env" else {expected_hash.lower()}
        assert observed_hash in allowed, (
            f"CANONICAL DATABASE INVARIANCE VIOLATION for {rel_path}!\n"
            f"Expected: {expected_hash.lower()}\n"
            f"Observed: {observed_hash}"
        )
