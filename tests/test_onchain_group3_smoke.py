"""Pytest integration module for P3 Group 3 local Anvil end-to-end smoke suite.
Verifies all Group 3 capabilities:
- Canonical SHA-256 case_id and storage URI
- SHA-256 note_hash custody recording
- Multi-manifest anchor_links creation
- Read-only verify and reconcile via Python and CLI
- Fail-closed idempotency refusal on duplicate submission
- Zero leakage of raw case_id or secret note text in on-chain tables or audit events
"""
import os
import sys
import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def group3_smoke_result():
    """Run scripts/run_p3_group3_smoke.py once for this module and return parsed report."""
    smoke_script = ROOT / "scripts" / "run_p3_group3_smoke.py"
    res = subprocess.run(
        [sys.executable, str(smoke_script)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
    )
    assert res.returncode == 0, f"Smoke script failed (exit {res.returncode}):\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}"
    data = json.loads(res.stdout)
    assert data.get("status") == "PASS", f"Smoke status is not PASS: {data.get('failure')}"
    return data


def _get_check(data: dict, name: str) -> dict:
    for check in data.get("checks", []):
        if check.get("name") == name:
            return check
    raise KeyError(f"Check '{name}' not found in smoke report")


def test_smoke_overall_pass(group3_smoke_result):
    assert group3_smoke_result["status"] == "PASS"
    assert group3_smoke_result["chain_id"] == 31337
    assert len(group3_smoke_result["operations"]) >= 3


def test_smoke_canonical_identity(group3_smoke_result):
    check = _get_check(group3_smoke_result, "anchor_evidence_1_canonical_identity")
    assert check["status"] == "PASS"
    assert check["evidence_id"] == 1
    assert check["uri"].startswith("evidence://sha256/")
    assert check["uri"].endswith("/manifest.json")


def test_smoke_multi_manifest_links(group3_smoke_result):
    check = _get_check(group3_smoke_result, "multi_manifest_anchor_links_created")
    assert check["status"] == "PASS"
    assert check["row_count"] >= 2


def test_smoke_custody_sha256_note(group3_smoke_result):
    check = _get_check(group3_smoke_result, "record_custody_sha256_note_hash")
    assert check["status"] == "PASS"
    assert check["verified"] == 1


def test_smoke_verify_and_reconcile(group3_smoke_result):
    v_check = _get_check(group3_smoke_result, "verify_onchain_python_and_cli")
    assert v_check["status"] == "MATCH"
    assert v_check["code"] == "OK"

    r_check = _get_check(group3_smoke_result, "read_only_reconciliation")
    assert r_check["status"] == "PASS"
    assert r_check["state"] == "CONFIRMED"


def test_smoke_idempotency_refusal(group3_smoke_result):
    check = _get_check(group3_smoke_result, "fail_closed_idempotency_no_broadcast")
    assert check["status"] == "PASS"
    assert check["nonce_unchanged"] is True


def test_smoke_zero_raw_leakage(group3_smoke_result):
    check = _get_check(group3_smoke_result, "zero_raw_data_leakage_asserted")
    assert check["status"] == "PASS"
    assert group3_smoke_result["leaks_found"] == []
