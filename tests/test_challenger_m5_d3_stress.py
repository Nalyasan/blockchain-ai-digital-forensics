"""Empirical Adversarial Stress Test Suite for Demo D3 and Evaluation Pipeline.

Author: challenger_v6_M5_2 (Gate M5 Challenger 2 — D3 Multi-Gateway & Anvil Stress)
Scope:
- Gateway 1 to 6 attack vectors under repeated/concurrent execution.
- Anvil ephemeral lifecycle: port collisions, concurrent instances, crash recovery, timeouts.
- Gateway 5 ZKML verifier fuzzing on live Anvil (commitments, boundary proof lengths, public signals).
- Master Report Generator (TraceableReportGenerator) robustness under missing, empty, corrupted, and fuzzed JSON telemetry.
- 100% bitwise invariance of the 4 canonical databases.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any
import pytest

from forensics.paths import resolve_foundry_binary
from forensics.did.client import AnvilTestNode, ANVIL_DEFAULT_DEPLOYER, _run_cast
from scripts.demo_d3_adversarial import (
    DemoD3Runner,
    verify_canonical_invariance,
    CANONICAL_HASHES,
)
from forensics.evaluation.report_generator import (
    TraceableReportGenerator,
    generate_traceable_evaluation_report,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


# ------------------------------------------------------------------------------
# 1. Anvil Ephemeral Lifecycle & Concurrency Probes
# ------------------------------------------------------------------------------

def test_anvil_port_collision_handling():
    """Verify that AnvilTestNode handles port collisions fail-closed without leaking."""
    # Bind a socket to hold an active port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    occupied_port = sock.getsockname()[1]

    try:
        # Attempt to start Anvil on the occupied port
        with pytest.raises(RuntimeError, match="ANVIL_START_TIMEOUT"):
            with AnvilTestNode(port=occupied_port) as node:
                pass
    finally:
        sock.close()


def test_anvil_concurrent_dynamic_nodes():
    """Verify two concurrent AnvilTestNode instances assign distinct ports and operate simultaneously."""
    with AnvilTestNode(port=None) as node1:
        with AnvilTestNode(port=None) as node2:
            assert node1.port != node2.port
            assert node1.rpc_url != node2.rpc_url
            # Both should respond to RPC eth_chainId
            from forensics.onchain import rpc_read
            res1 = rpc_read(node1.rpc_url, "eth_chainId", [])
            res2 = rpc_read(node2.rpc_url, "eth_chainId", [])
            assert int(res1, 16) == 31337
            assert int(res2, 16) == 31337


def test_anvil_node_crash_recovery_in_context():
    """Verify AnvilTestNode handles unexpected child process termination mid-context without crashing __exit__."""
    with AnvilTestNode() as node:
        proc = node.proc
        assert proc is not None
        assert proc.poll() is None  # Running
        # Simulate abrupt process crash / kill
        proc.kill()
        proc.wait(timeout=3)
        assert proc.poll() is not None

    # Exiting context manager must not raise ProcessLookupError or unhandled exception


# ------------------------------------------------------------------------------
# 2. Demo D3 Repeated Runs & State Isolation
# ------------------------------------------------------------------------------

def test_demo_d3_repeated_runs_isolation():
    """Verify DemoD3Runner executes repeatedly in the same process with zero state leakage and 35/35 rejections."""
    temp_dir1 = Path(tempfile.mkdtemp(prefix="test_d3_rep1_"))
    temp_dir2 = Path(tempfile.mkdtemp(prefix="test_d3_rep2_"))

    try:
        # Run 1
        runner1 = DemoD3Runner(
            workspace_dir=REPO_ROOT,
            report_json_path=temp_dir1 / "rep1.json",
            report_md_path=temp_dir1 / "rep1.md",
            temp_dir=temp_dir1 / "scratch",
        )
        t1 = runner1.run()
        assert t1["summary"]["overall_status"] == "PASS"
        assert t1["summary"]["total_rejected_fail_closed"] == 35
        assert t1["summary"]["total_bypasses_allowed"] == 0

        # Run 2 immediately in the same process
        runner2 = DemoD3Runner(
            workspace_dir=REPO_ROOT,
            report_json_path=temp_dir2 / "rep2.json",
            report_md_path=temp_dir2 / "rep2.md",
            temp_dir=temp_dir2 / "scratch",
        )
        t2 = runner2.run()
        assert t2["summary"]["overall_status"] == "PASS"
        assert t2["summary"]["total_rejected_fail_closed"] == 35
        assert t2["summary"]["total_bypasses_allowed"] == 0

        # Compare vector counts across all gateways
        for gw in t1["gateways"]:
            assert t1["gateways"][gw]["rejected_fail_closed"] == t2["gateways"][gw]["rejected_fail_closed"]

    finally:
        shutil.rmtree(temp_dir1, ignore_errors=True)
        shutil.rmtree(temp_dir2, ignore_errors=True)


# ------------------------------------------------------------------------------
# 3. Gateway 5 (ZKML) On-Chain Fuzzing & Boundary Probes on Live Anvil
# ------------------------------------------------------------------------------

def test_zkml_onchain_verifier_fuzz_and_boundary():
    """Adversarial boundary testing of InferenceVerifier.sol on live Anvil."""
    forge_bin = resolve_foundry_binary("forge")

    with AnvilTestNode() as node:
        # Deploy MockCircuitVerifier
        dummy_proof = b"\xaa" * 128
        proof_keccak = "0x" + hashlib.sha256(dummy_proof).hexdigest()  # Arbitrary hash

        res_circ = subprocess.run([
            forge_bin, "create", "src/InferenceVerifier.sol:MockCircuitVerifier",
            "--root", "contracts",
            "--rpc-url", node.rpc_url,
            "--unlocked",
            "--from", ANVIL_DEFAULT_DEPLOYER,
            "--broadcast",
            "--constructor-args", proof_keccak,
        ], capture_output=True, text=True, check=True, cwd=str(REPO_ROOT))

        import re
        circ_addr = re.search(r"Deployed to:\s*(0x[0-9a-fA-F]{40})", res_circ.stdout).group(1)

        expected_model_hash = "0x" + "11" * 32
        expected_in_comm = "0x" + "22" * 32
        expected_out_comm = "0x" + "33" * 32

        res_iv = subprocess.run([
            forge_bin, "create", "src/InferenceVerifier.sol:InferenceVerifier",
            "--root", "contracts",
            "--rpc-url", node.rpc_url,
            "--unlocked",
            "--from", ANVIL_DEFAULT_DEPLOYER,
            "--broadcast",
            "--constructor-args", circ_addr, expected_model_hash, "true",
        ], capture_output=True, text=True, check=True, cwd=str(REPO_ROOT))

        iv_addr = re.search(r"Deployed to:\s*(0x[0-9a-fA-F]{40})", res_iv.stdout).group(1)

        valid_proof_hex = "0x" + dummy_proof.hex()

        # Probe 1: Zero Model Commitment must revert with InvalidCommitment("modelCommitment")
        p1_reverted = False
        try:
            _run_cast([
                "send", iv_addr,
                "verifyInferenceProof(bytes,bytes32,bytes32,bytes32,string)(bool)",
                valid_proof_hex, "0x" + "00" * 32, expected_in_comm, expected_out_comm, "REC_FUZZ_01",
                "--rpc-url", node.rpc_url,
                "--from", ANVIL_DEFAULT_DEPLOYER,
                "--unlocked",
            ])
        except RuntimeError:
            p1_reverted = True
        assert p1_reverted is True, "Probe 1 failed: Zero model commitment did not revert"

        # Probe 2: Zero Input Commitment must revert with InvalidCommitment("inputCommitment")
        p2_reverted = False
        try:
            _run_cast([
                "send", iv_addr,
                "verifyInferenceProof(bytes,bytes32,bytes32,bytes32,string)(bool)",
                valid_proof_hex, expected_model_hash, "0x" + "00" * 32, expected_out_comm, "REC_FUZZ_02",
                "--rpc-url", node.rpc_url,
                "--from", ANVIL_DEFAULT_DEPLOYER,
                "--unlocked",
            ])
        except RuntimeError:
            p2_reverted = True
        assert p2_reverted is True, "Probe 2 failed: Zero input commitment did not revert"

        # Probe 3: Zero Output Commitment must revert with InvalidCommitment("outputCommitment")
        p3_reverted = False
        try:
            _run_cast([
                "send", iv_addr,
                "verifyInferenceProof(bytes,bytes32,bytes32,bytes32,string)(bool)",
                valid_proof_hex, expected_model_hash, expected_in_comm, "0x" + "00" * 32, "REC_FUZZ_03",
                "--rpc-url", node.rpc_url,
                "--from", ANVIL_DEFAULT_DEPLOYER,
                "--unlocked",
            ])
        except RuntimeError:
            p3_reverted = True
        assert p3_reverted is True, "Probe 3 failed: Zero output commitment did not revert"

        # Probe 4: Empty string inferenceRecordId must revert with EmptyInferenceRecordId()
        p4_reverted = False
        try:
            _run_cast([
                "send", iv_addr,
                "verifyInferenceProof(bytes,bytes32,bytes32,bytes32,string)(bool)",
                valid_proof_hex, expected_model_hash, expected_in_comm, expected_out_comm, "",
                "--rpc-url", node.rpc_url,
                "--from", ANVIL_DEFAULT_DEPLOYER,
                "--unlocked",
            ])
        except RuntimeError:
            p4_reverted = True
        assert p4_reverted is True, "Probe 4 failed: Empty inferenceRecordId did not revert"

        # Probe 5: Sub-64 byte proof (63 bytes) must revert with InvalidProofLength()
        p5_reverted = False
        sub_64_proof = "0x" + ("bb" * 63)
        try:
            _run_cast([
                "send", iv_addr,
                "verifyInferenceProof(bytes,bytes32,bytes32,bytes32,string)(bool)",
                sub_64_proof, expected_model_hash, expected_in_comm, expected_out_comm, "REC_FUZZ_05",
                "--rpc-url", node.rpc_url,
                "--from", ANVIL_DEFAULT_DEPLOYER,
                "--unlocked",
            ])
        except RuntimeError:
            p5_reverted = True
        assert p5_reverted is True, "Probe 5 failed: 63-byte proof did not revert"


# ------------------------------------------------------------------------------
# 4. Master Report Generator Robustness & Input Fuzzing
# ------------------------------------------------------------------------------

def test_report_generator_missing_inputs():
    """Verify TraceableReportGenerator executes gracefully when telemetry inputs are completely missing."""
    temp_dir = Path(tempfile.mkdtemp(prefix="test_rep_miss_"))
    try:
        out_md = temp_dir / "report.md"
        gen = TraceableReportGenerator(
            workspace_dir=REPO_ROOT,
            d1_report_path=temp_dir / "non_existent_d1.json",
            d2_report_path=temp_dir / "non_existent_d2.json",
            d3_report_path=temp_dir / "non_existent_d3.json",
            output_md_path=out_md,
        )
        content = gen.generate()
        assert out_md.exists()
        assert len(content) > 1000
        assert "MASTER TRACEABLE FORENSIC EVALUATION REPORT" in content
        assert "Section 1: Functional Verification Metrics" in content
        assert "7.1 Canonical Database Invariance Sign-Off" in content
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_report_generator_corrupted_json():
    """Verify TraceableReportGenerator handles syntactically broken or truncated JSON gracefully."""
    temp_dir = Path(tempfile.mkdtemp(prefix="test_rep_corrupt_"))
    try:
        d1_corrupt = temp_dir / "d1_corrupt.json"
        d2_corrupt = temp_dir / "d2_corrupt.json"
        d3_corrupt = temp_dir / "d3_corrupt.json"

        d1_corrupt.write_text('{"summary": { "broken": ', encoding="utf-8")
        d2_corrupt.write_text('', encoding="utf-8")  # 0 bytes
        d3_corrupt.write_text('\x00\x01\x02\x03\xff\xfe', encoding="latin-1")  # Non-JSON binary

        out_md = temp_dir / "report.md"
        gen = TraceableReportGenerator(
            workspace_dir=REPO_ROOT,
            d1_report_path=d1_corrupt,
            d2_report_path=d2_corrupt,
            d3_report_path=d3_corrupt,
            output_md_path=out_md,
        )
        content = gen.generate()
        assert out_md.exists()
        assert "MASTER TRACEABLE FORENSIC EVALUATION REPORT" in content
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_report_generator_degraded_schema_resilience():
    """Verify TraceableReportGenerator handles degraded JSON schemas (empty objects or missing subsections)."""
    temp_dir = Path(tempfile.mkdtemp(prefix="test_rep_schema_"))
    try:
        d1_min = temp_dir / "d1_min.json"
        d2_min = temp_dir / "d2_min.json"
        d3_min = temp_dir / "d3_min.json"

        d1_min.write_text(json.dumps({"pipeline_stages": {}}), encoding="utf-8")
        d2_min.write_text(json.dumps({"acquisition": {}}), encoding="utf-8")
        d3_min.write_text(json.dumps({"summary": {}}), encoding="utf-8")

        out_md = temp_dir / "report.md"
        gen = TraceableReportGenerator(
            workspace_dir=REPO_ROOT,
            d1_report_path=d1_min,
            d2_report_path=d2_min,
            d3_report_path=d3_min,
            output_md_path=out_md,
        )
        content = gen.generate()
        assert out_md.exists()
        assert "MASTER TRACEABLE FORENSIC EVALUATION REPORT" in content
        assert "Fail-Closed Rejection Rate:" in content
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_report_generator_partial_degraded_schema_resilience():
    """Verify TraceableReportGenerator handles valid JSON with empty/partial dictionary stages."""
    temp_dir = Path(tempfile.mkdtemp(prefix="test_rep_partial_"))
    try:
        d1_partial = temp_dir / "d1_partial.json"
        d2_partial = temp_dir / "d2_partial.json"
        d3_partial = temp_dir / "d3_partial.json"

        # Valid dictionaries but partial fields omitted
        d1_payload = {
            "pipeline_stages": {
                "stage_1_ingestion": {},
                "stage_2_rule_detection": {},
                "stage_3_ml_inference": {},
                "stage_4_xai_mitre": {},
                "stage_5_ai_investigator": {},
                "stage_6_zkml_proving": {},
                "stage_7_custody_did": {},
                "stage_8_reread_provenance": {},
            }
        }
        d2_payload = {
            "acquisition": {},
            "first_responder_triage": {},
            "analysis_and_ref_checker": {},
            "onchain_custody": {},
            "evidence_package": {},
        }
        d3_payload = {
            "summary": {
                "total_attack_vectors": 35,
                "total_rejected_fail_closed": 35,
                "fail_closed_rate": 1.0,
            }
        }

        d1_partial.write_text(json.dumps(d1_payload), encoding="utf-8")
        d2_partial.write_text(json.dumps(d2_payload), encoding="utf-8")
        d3_partial.write_text(json.dumps(d3_payload), encoding="utf-8")

        out_md = temp_dir / "report.md"
        gen = TraceableReportGenerator(
            workspace_dir=REPO_ROOT,
            d1_report_path=d1_partial,
            d2_report_path=d2_partial,
            d3_report_path=d3_partial,
            output_md_path=out_md,
        )
        content = gen.generate()
        assert out_md.exists()
        assert "MASTER TRACEABLE FORENSIC EVALUATION REPORT" in content
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_report_generator_null_nested_stage_empirical_challenge():
    """Verify TraceableReportGenerator degrades gracefully without raising AttributeError
    when telemetry JSON contains explicit nulls (None) for nested stage dictionaries."""
    temp_dir = Path(tempfile.mkdtemp(prefix="test_rep_null_"))
    try:
        d1_null = temp_dir / "d1_null.json"
        d2_empty = temp_dir / "d2_empty.json"
        d3_empty = temp_dir / "d3_empty.json"

        d1_null.write_text(json.dumps({"pipeline_stages": None}), encoding="utf-8")
        d2_empty.write_text(json.dumps({"phases": None}), encoding="utf-8")
        d3_empty.write_text(json.dumps({"summary": None, "gateways": None}), encoding="utf-8")

        out_md = temp_dir / "report.md"
        gen = TraceableReportGenerator(
            workspace_dir=REPO_ROOT,
            d1_report_path=d1_null,
            d2_report_path=d2_empty,
            d3_report_path=d3_empty,
            output_md_path=out_md,
        )

        content = gen.generate()
        assert out_md.exists()
        assert "MASTER TRACEABLE FORENSIC EVALUATION REPORT" in content
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)



# ------------------------------------------------------------------------------
# 5. Canonical Database Bitwise Invariance Sign-Off
# ------------------------------------------------------------------------------

def test_canonical_invariance_after_stress():
    """Verify 100% bitwise invariance of the 4 canonical databases after all stress operations."""
    results = verify_canonical_invariance(REPO_ROOT)
    assert len(results) == 4
    for name, data in results.items():
        assert data["match"] is True, f"Canonical database {name} violated! {data}"

