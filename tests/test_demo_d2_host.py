"""Test suite for Demo D2 Host Log Incident Replay (tests/test_demo_d2_host.py)."""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
import pytest

from scripts.demo_d2_host import DemoD2Runner, verify_canonical_invariance, CANONICAL_HASHES


@pytest.fixture
def temp_demo_dir():
    d = Path(tempfile.mkdtemp(prefix="test_d2_"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


def test_canonical_invariance_baseline():
    """Verify pre-execution canonical hashes match 100% bitwise."""
    repo_root = Path(__file__).resolve().parents[1]
    results = verify_canonical_invariance(repo_root)
    assert len(results) == 4
    for k, v in results.items():
        assert v["match"] is True, f"Mismatch in {k}: {v}"


def test_demo_d2_host_execution(temp_demo_dir):
    """Execute Demo D2 runner and verify full 6-phase telemetry."""
    repo_root = Path(__file__).resolve().parents[1]
    fixture_path = repo_root / "tests" / "fixtures" / "host_incident_d2.jsonl"
    assert fixture_path.exists(), f"Fixture missing: {fixture_path}"

    report_json = temp_demo_dir / "report.json"
    report_md = temp_demo_dir / "report.md"

    runner = DemoD2Runner(
        fixture_path=fixture_path,
        case_id="CASE-2026-D2-HOST-TEST",
        workspace_dir=repo_root,
        report_json_path=report_json,
        report_md_path=report_md,
        temp_dir=temp_demo_dir / "runner_temp",
    )
    telemetry = runner.run()

    assert telemetry["status"] == "PASS"
    phases = telemetry["phases"]
    assert len(phases) == 6

    # Phase 1: Acquisition
    p1 = phases["phase_1_acquisition"]
    assert p1["bitwise_match"] is True
    assert p1["records_ingested"] >= 10
    assert p1["consent_scope"] == "security_events_only"

    # Phase 2: Database Isolation
    p2 = phases["phase_2_database_isolation"]
    assert p2["zero_canonical_writes"] is True

    # Phase 3: First Responder Triage
    p3 = phases["phase_3_first_responder_triage"]
    assert len(p3["playbooks_executed"]) == 5
    for guard, blocked in p3["guardrails_verified"].items():
        assert blocked is True, f"Guardrail {guard} not verified"

    # Phase 4: Analysis & RefChecker
    p4 = phases["phase_4_analysis_and_ref_checker"]
    assert set(p4["heuristics_triggered"]) == {
        "rule_h1_encoded_powershell",
        "rule_h2_c2_socket",
        "rule_h3_service_persistence",
    }
    assert p4["ref_checker_status"] == "PASS"
    assert p4["existence_ref_ratio"] == 1.0
    assert p4["field_match_ratio"] == 1.0
    assert p4["mismatches_count"] == 0

    # Phase 5: Evidence Package & On-Chain Custody
    p5_pkg = phases["phase_5_evidence_package"]
    assert p5_pkg["leaf_count"] == 5
    assert len(p5_pkg["canonical_storage_uri"]) == 161
    assert p5_pkg["canonical_storage_uri"].startswith("evidence://sha256/")

    p5_oc = phases["phase_5_onchain_custody"]
    assert p5_oc["evidence_id"] >= 1
    assert p5_oc["concordance"]["package_merkle_root"] == "MATCH_100%"
    assert p5_oc["concordance"]["custodian_address"] == "MATCH_100%"
    assert "ARCHITECTURAL_LIMITATION" in p5_oc["zkml_proof_status"]

    # Verify reports were created
    assert report_json.exists() and report_json.stat().st_size > 0
    assert report_md.exists() and report_md.stat().st_size > 0
