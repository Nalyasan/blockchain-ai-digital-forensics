"""Test suite for Demo D1 EVM Incident Replay (tests/test_demo_d1_evm.py)."""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
import pytest

from scripts.demo_d1_evm import DemoD1Runner, verify_canonical_invariance, CANONICAL_HASHES


@pytest.fixture
def temp_demo_dir():
    d = Path(tempfile.mkdtemp(prefix="test_d1_"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


def test_canonical_invariance_baseline():
    """Verify pre-execution canonical hashes match 100% bitwise."""
    repo_root = Path(__file__).resolve().parents[1]
    results = verify_canonical_invariance(repo_root)
    assert len(results) == 4
    for k, v in results.items():
        assert v["match"] is True, f"Mismatch in {k}: {v}"


def test_demo_d1_evm_execution(temp_demo_dir):
    """Execute Demo D1 runner and verify full 8-stage telemetry."""
    repo_root = Path(__file__).resolve().parents[1]
    report_json = temp_demo_dir / "report.json"
    report_md = temp_demo_dir / "report.md"

    runner = DemoD1Runner(
        incident="euler",
        workspace_dir=repo_root,
        report_json_path=report_json,
        report_md_path=report_md,
        temp_dir=temp_demo_dir / "runner_temp",
    )
    telemetry = runner.run()

    assert telemetry["status"] == "PASS"
    stages = telemetry["pipeline_stages"]
    assert len(stages) == 8

    # Stage 1: Ingestion
    assert stages["stage_1_ingestion"]["bitstream_verified"] is True
    assert stages["stage_1_ingestion"]["package_verification_status"] == "VALID"

    # Stage 2: Rule detection
    assert stages["stage_2_rule_detection"]["alerts_count"] >= 1
    assert len(stages["stage_2_rule_detection"]["detected_rules"]) >= 1

    # Stage 3: ML inference
    assert stages["stage_3_ml_inference"]["model_id"] == "anomaly_detector_v1"
    assert stages["stage_3_ml_inference"]["classification"] == "anomalous"

    # Stage 4: XAI & MITRE
    assert stages["stage_4_xai_mitre"]["xai_status"] == "EXPLAINABLE"
    assert stages["stage_4_xai_mitre"]["fidelity_r2"] >= 0.80
    assert stages["stage_4_xai_mitre"]["stability_score"] >= 0.85
    assert len(stages["stage_4_xai_mitre"]["mitre_mappings"]) >= 1

    # Stage 5: AI Investigator
    assert stages["stage_5_ai_investigator"]["ref_checker"]["is_valid"] is True
    assert stages["stage_5_ai_investigator"]["ref_checker"]["existence_ref_ratio"] == 1.0

    # Stage 6: ZKML
    assert stages["stage_6_zkml_proving"]["proof_bytes_length"] == 5504
    assert stages["stage_6_zkml_proving"]["is_valid"] is True
    assert stages["stage_6_zkml_proving"]["tamper_rejection_verified"] is True

    # Stage 7: Custody DID
    assert stages["stage_7_custody_did"]["hash_concordance"]["concordance_verified"] is True

    # Stage 8: Re-read branch
    assert stages["stage_8_reread_provenance"]["provenance_loop_verified"] is True
    assert stages["stage_8_reread_provenance"]["manifest_match"] is True

    # Check files exist
    assert report_json.exists()
    assert report_md.exists()
