"""Test suite for Demo D3 Multi-Gateway Adversarial Replay (tests/test_demo_d3_adversarial.py)."""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
import pytest

from scripts.demo_d3_adversarial import DemoD3Runner, verify_canonical_invariance, CANONICAL_HASHES


@pytest.fixture
def temp_demo_dir():
    d = Path(tempfile.mkdtemp(prefix="test_d3_"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


def test_canonical_invariance_baseline():
    """Verify pre-execution canonical hashes match 100% bitwise."""
    repo_root = Path(__file__).resolve().parents[1]
    results = verify_canonical_invariance(repo_root)
    assert len(results) == 4
    for k, v in results.items():
        assert v["match"] is True, f"Mismatch in {k}: {v}"


def test_demo_d3_adversarial_execution(temp_demo_dir):
    """Execute Demo D3 runner and verify all 35 attack vectors are rejected fail-closed."""
    repo_root = Path(__file__).resolve().parents[1]
    report_json = temp_demo_dir / "report.json"
    report_md = temp_demo_dir / "report.md"

    runner = DemoD3Runner(
        workspace_dir=repo_root,
        report_json_path=report_json,
        report_md_path=report_md,
        temp_dir=temp_demo_dir / "runner_temp",
    )
    telemetry = runner.run()

    summary = telemetry["summary"]
    assert summary["overall_status"] == "PASS"
    assert summary["total_attack_vectors"] == 35
    assert summary["total_rejected_fail_closed"] == 35
    assert summary["total_bypasses_allowed"] == 0
    assert summary["fail_closed_rate"] == 1.0

    gateways = telemetry["gateways"]
    assert len(gateways) == 6

    expected_gateway_counts = {
        "gateway_1_endpoint_first_responder": 8,
        "gateway_2_ml_xai": 6,
        "gateway_3_mitre_threat_intel": 4,
        "gateway_4_ai_investigator": 6,
        "gateway_5_zkml_verifier": 5,
        "gateway_6_did_custody": 6,
    }

    for gw_key, expected_count in expected_gateway_counts.items():
        assert gw_key in gateways, f"Gateway {gw_key} missing from telemetry"
        gw_data = gateways[gw_key]
        assert gw_data["total_vectors"] == expected_count, f"Gateway {gw_key} expected {expected_count} vectors, got {gw_data['total_vectors']}"
        assert gw_data["rejected_fail_closed"] == expected_count, f"Gateway {gw_key} allowed bypasses"

    assert report_json.exists() and report_json.stat().st_size > 0
    assert report_md.exists() and report_md.stat().st_size > 0
