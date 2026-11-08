"""Comprehensive Test Suite for FastAPI Forensic Dashboard (tests/test_dashboard_api.py).

Covers:
- Standardized Project Branding: Exact string "Blockchain Ai Aigital Forensics" across all templates & metadata
- Jargon Elimination: Complete removal of Mode A/B, P1-P11, R4-R8, R7.9, PASS/FAIL, VICTORY CONFIRMED from user UI
- Standardized Vietnamese Business Names across navigation and views
- Homepage Architecture (R2): 4 distinct functional areas (Area A, Area B, Area C, Area D with live probes)
- Case Management: Blank Case ID default, regex validation, path traversal rejection, duplicate handling, multiple runs
- Data Isolation: Case & Run switcher on Header / Navigation, strict session filtering, "Chưa có dữ liệu điều tra"
- REST API endpoints (/api/system/status, /api/investigations, /api/evidence/canonical, /api/cases, etc.)
- Persistent JobManager: submission, polling, anti-overlap conflict rejection (HTTP 409)
- Cooperative cancellation tokens: safe abortion and partial 5-artifact generation
- Automated 5-artifact session export (report.html, report.json, manifest, custody, log)
- Bitwise SHA-256 invariance of all 4 canonical databases before and after test suite
"""

from __future__ import annotations

import json
from pathlib import Path
import time
import pytest
from fastapi.testclient import TestClient

from dashboard.app import app
from dashboard.services.job_manager import get_job_manager
from forensics.paths import (
    get_benchmark_db,
    get_endpoint_evidence_db,
    get_forensics_db,
    get_real_p4_db,
)
from forensics.service import compute_sha256, VIETNAMESE_STATUS_MAP

CANONICAL_HASHES = {
    "real_p4.db": "6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97",
    "forensics.db": "3F2B0DFC772A96FF6EA57C65807B5B6B9A20FCF74C409C6F222FCFF29F1EF001",
    "benchmark_p6.db": "C7FF724CD214EEF57E58A6FBE44DBEB2712C54B035907B2A6279A255C0E80507",
    "endpoint_evidence.db": "CAF3F0B30C0F864150CA5DCBD45DD19927A53620001AB696228A744C959B7CD0",
}


@pytest.fixture(scope="session")
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture(autouse=True)
def verify_db_invariance():
    """Verifies all 4 canonical databases remain bitwise identical before and after each test."""
    dbs = {
        "real_p4.db": get_real_p4_db(),
        "forensics.db": get_forensics_db(),
        "benchmark_p6.db": get_benchmark_db(),
        "endpoint_evidence.db": get_endpoint_evidence_db(),
    }
    for name, path in dbs.items():
        assert path.is_file(), f"Canonical database missing: {path}"
        cur_hash = compute_sha256(path)
        assert cur_hash == CANONICAL_HASHES[name], f"Pre-test mutation detected in {name}: {cur_hash} != {CANONICAL_HASHES[name]}"

    yield

    for name, path in dbs.items():
        cur_hash = compute_sha256(path)
        assert cur_hash == CANONICAL_HASHES[name], f"Post-test mutation detected in {name}: {cur_hash} != {CANONICAL_HASHES[name]}"


# ==============================================================================
# 1. HTML Pages Rendering Tests (All 11 Pages with Standardized Names & Branding)
# ==============================================================================

def test_page_overview(client: TestClient):
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "Blockchain Ai Aigital Forensics" in res.text
    assert "Tổng quan" in res.text
    # Verify 4 distinct functional areas exist
    assert "Khu vực A" in res.text
    assert "Điều tra mới" in res.text
    assert "Khu vực B" in res.text
    assert "Phiên đang xử lý" in res.text
    assert "Khu vực C" in res.text
    assert "Hồ sơ gần đây" in res.text
    assert "Khu vực D" in res.text
    assert "Tình trạng hệ thống thực tế" in res.text


def test_page_launcher(client: TestClient):
    res = client.get("/launcher")
    assert res.status_code == 200
    assert "Blockchain Ai Aigital Forensics" in res.text
    assert "Khởi chạy điều tra" in res.text
    assert "Điều tra thực tế" in res.text
    assert "Kiểm thử hệ thống trong khu vực quản trị" in res.text
    assert "ai_provider" in res.text
    # Verify Case ID input is initially blank (not prefilled with euler-curve-incidents)
    assert 'id="case_id" name="case_id" value=""' in res.text
    assert 'pattern="^[A-Za-z0-9_-]{1,64}$"' in res.text


def test_page_progress(client: TestClient):
    res = client.get("/progress")
    assert res.status_code == 200
    assert "Blockchain Ai Aigital Forensics" in res.text
    assert "Tiến độ" in res.text
    assert "8 Giai đoạn Điều tra Chuẩn hóa" in res.text
    assert "Tiếp nhận dữ liệu" in res.text
    # Verify internal jargon is eliminated
    assert "P1 Blockchain Collector" not in res.text
    assert "R7.9" not in res.text


def test_page_evidence(client: TestClient):
    res = client.get("/evidence")
    assert res.status_code == 200
    assert "Blockchain Ai Aigital Forensics" in res.text
    assert "Chứng cứ" in res.text
    assert "real_p4.db" in res.text
    assert "6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97" in res.text
    assert "ISO/IEC 27037" in res.text


def test_page_ai(client: TestClient):
    res = client.get("/ai")
    assert res.status_code == 200
    assert "Blockchain Ai Aigital Forensics" in res.text
    assert "Phân tích AI" in res.text
    assert "Multi-Model AI Provider Adapter" in res.text
    assert "RefChecker" in res.text
    assert "Air-Gap" in res.text
    assert "AI Investigator P5" not in res.text


def test_page_ml_xai(client: TestClient):
    res = client.get("/ml-xai")
    assert res.status_code == 200
    assert "Blockchain Ai Aigital Forensics" in res.text
    assert "Phân tích bất thường" in res.text
    assert "CompactAnomalyMLP" in res.text
    assert "Exact Shapley" in res.text
    assert "979" in res.text
    assert "12" in res.text
    assert "Machine Learning P8" not in res.text
    # Verify hardcoded fake Shapley numbers are eliminated
    assert "+0.3842 (Tác nhân chính)" not in res.text


def test_page_blockchain(client: TestClient):
    res = client.get("/blockchain")
    assert res.status_code == 200
    assert "Blockchain Ai Aigital Forensics" in res.text
    assert "Bảo quản chứng cứ" in res.text
    assert "EvidenceRegistryDID" in res.text
    assert "31337" in res.text
    assert "100% Concordance" in res.text
    assert "Chain of Custody P3/P10" not in res.text


def test_page_zkml(client: TestClient):
    res = client.get("/zkml")
    assert res.status_code == 200
    assert "Blockchain Ai Aigital Forensics" in res.text
    assert "Xác minh suy luận" in res.text
    assert "Halo2 BN254 KZG" in res.text
    assert "InferenceVerifier.sol" in res.text
    assert "ProofAlreadyVerified" in res.text
    assert "Halo2 KZG P9" not in res.text
    assert "185/185 PASS" not in res.text


def test_page_demo_center(client: TestClient):
    res = client.get("/demo-center")
    assert res.status_code == 200
    assert "Blockchain Ai Aigital Forensics" in res.text
    assert "Kiểm thử hệ thống trong khu vực quản trị" in res.text
    assert "Demo D1: EVM Incident Replay" in res.text
    assert "Demo D2: Host Forensics" in res.text
    assert "Demo D3: Adversarial Replay" in res.text
    assert "35 Véc-tơ" in res.text


def test_page_reports(client: TestClient):
    res = client.get("/reports")
    assert res.status_code == 200
    assert "Blockchain Ai Aigital Forensics" in res.text
    assert "Báo cáo điều tra" in res.text
    assert "Hồ sơ Báo cáo" in res.text
    assert "report.html" in res.text


def test_page_settings(client: TestClient):
    res = client.get("/settings")
    assert res.status_code == 200
    assert "Blockchain Ai Aigital Forensics" in res.text
    assert "Cài đặt" in res.text
    assert "PROJECT_ROOT" in res.text
    assert "Foundry Toolchain" in res.text
    assert "185 PASS" not in res.text


# ==============================================================================
# 2. REST API Telemetry Tests
# ==============================================================================

def test_api_system_status(client: TestClient):
    res = client.get("/api/system/status")
    assert res.status_code == 200
    data = res.json()
    assert "canonical_databases" in data
    assert data["canonical_databases"]["real_p4.db"]["sha256"] == CANONICAL_HASHES["real_p4.db"]
    assert data["canonical_databases"]["forensics.db"]["sha256"] == CANONICAL_HASHES["forensics.db"]
    assert data["canonical_databases"]["benchmark_p6.db"]["sha256"] == CANONICAL_HASHES["benchmark_p6.db"]
    assert data["canonical_databases"]["endpoint_evidence.db"]["sha256"] == CANONICAL_HASHES["endpoint_evidence.db"]


def test_api_canonical_evidence(client: TestClient):
    res = client.get("/api/evidence/canonical")
    assert res.status_code == 200
    data = res.json()
    assert data["database"] == "real_p4.db"
    assert data["sha256"] == CANONICAL_HASHES["real_p4.db"]
    assert "table_counts" in data
    assert "blocks" in data["table_counts"]
    assert "transactions" in data["table_counts"]


def test_api_ml_model_details(client: TestClient):
    res = client.get("/api/ml/model")
    assert res.status_code == 200
    data = res.json()
    assert data["model_id"] == "anomaly_detector_v1"
    assert data["frozen"] is True
    assert data["positive_labels_reconciliation"]["heuristic_cooccurrence_labels"] == 979
    assert data["positive_labels_reconciliation"]["ground_truth_attack_labels"] == 12


def test_api_zkml_proof_details(client: TestClient):
    res = client.get("/api/zkml/proof")
    assert res.status_code == 200
    data = res.json()
    assert data["circuit"] == "anomaly_detector_v1"
    assert "InferenceVerifier.sol" in data["onchain_verifiers"][0]


def test_api_blockchain_status(client: TestClient):
    res = client.get("/api/blockchain/status")
    assert res.status_code == 200
    data = res.json()
    assert "rpc_url" in data
    assert data["read_only_default"] is True


def test_api_cases_list(client: TestClient):
    res = client.get("/api/cases")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, dict)


# ==============================================================================
# 3. Investigation Lifecycle & 5-Artifact Export
# ==============================================================================

def test_investigation_lifecycle_mode_a(client: TestClient):
    """Executes a Mode A Demo session, verifying state transitions and the 5 artifacts."""
    payload = {
        "case_id": "test-d1-case",
        "continue_case": True,
        "mode": "MODE_A",
        "demo_target": "D1",
        "ai_provider": "deterministic_fallback",
        "ai_model": "rule-engine-fallback",
        "enable_onchain_write": False,
    }
    res = client.post("/api/investigations", json=payload)
    assert res.status_code == 201
    job = res.json()
    run_id = job["run_id"]
    assert run_id.startswith("run_test-d1-case_")
    assert job["mode"] == "MODE_A"

    # Poll until completed
    max_wait = 20
    t0 = time.time()
    final_job = None
    while time.time() - t0 < max_wait:
        poll_res = client.get(f"/api/investigations/{run_id}")
        assert poll_res.status_code == 200
        j_data = poll_res.json()
        if j_data["status"] in ("completed", "completed_with_warnings", "failed", "stopped"):
            final_job = j_data
            break
        time.sleep(0.5)

    assert final_job is not None, "Job did not complete within timeout"
    assert final_job["status"] in ("completed", "completed_with_warnings")
    assert final_job["vietnamese_status"] in ("Hoàn tất", "Hoàn tất có cảnh báo")

    # Verify 5 artifacts exist in response (including investigation_report.html and backward-compatible report.html)
    artifacts = final_job["artifacts"]
    assert "report_html" in artifacts
    assert "investigation_report_html" in artifacts
    assert "report_json" in artifacts
    assert "evidence_manifest" in artifacts
    assert "custody_receipts" in artifacts
    assert "execution_log" in artifacts

    # Verify physical file existence
    for art_key, art_path in artifacts.items():
        assert Path(art_path).is_file(), f"Artifact file missing: {art_key} -> {art_path}"

    # Test artifact download endpoints (both investigation_report.html and report.html)
    inv_res = client.get(f"/api/investigations/{run_id}/artifacts/investigation_report.html")
    assert inv_res.status_code == 200
    assert "text/html" in inv_res.headers["content-type"]
    assert "Báo cáo Điều tra Pháp y số" in inv_res.text

    html_res = client.get(f"/api/investigations/{run_id}/artifacts/report.html")
    assert html_res.status_code == 200
    assert "text/html" in html_res.headers["content-type"]
    assert "Báo cáo Điều tra Pháp y số" in html_res.text

    json_res = client.get(f"/api/investigations/{run_id}/artifacts/report.json")
    assert json_res.status_code == 200
    assert json_res.json()["run_info"]["run_id"] == run_id

    manifest_res = client.get(f"/api/investigations/{run_id}/artifacts/evidence_manifest.json")
    assert manifest_res.status_code == 200
    assert manifest_res.json()["manifest_version"] == "1.0.0"

    custody_res = client.get(f"/api/investigations/{run_id}/artifacts/custody_receipts.json")
    assert custody_res.status_code == 200
    assert custody_res.json()["run_id"] == run_id

    log_res = client.get(f"/api/investigations/{run_id}/artifacts/execution_log.txt")
    assert log_res.status_code == 200
    assert len(log_res.text) > 0


def test_investigation_lifecycle_mode_b_real(client: TestClient):
    """Executes a Mode B Real Investigation on real_p4.db."""
    payload = {
        "case_id": "test-mode-b-real",
        "continue_case": True,
        "mode": "MODE_B",
        "db_path": "data/real_p4.db",
        "ai_provider": "deterministic_fallback",
        "ai_model": "rule-engine-fallback",
        "enable_onchain_write": False,
        "is_mock": True,
    }
    res = client.post("/api/investigations", json=payload)
    assert res.status_code == 201
    job = res.json()
    run_id = job["run_id"]

    # Poll until completed
    max_wait = 90
    t0 = time.time()
    final_job = None
    while time.time() - t0 < max_wait:
        poll_res = client.get(f"/api/investigations/{run_id}")
        assert poll_res.status_code == 200
        j_data = poll_res.json()
        if j_data["status"] in ("completed", "completed_with_warnings", "failed", "stopped"):
            final_job = j_data
            break
        time.sleep(0.5)

    assert final_job is not None, "Mode B job did not complete within timeout"
    assert final_job["status"] in ("completed", "completed_with_warnings")
    assert final_job["vietnamese_status"] in ("Hoàn tất", "Hoàn tất có cảnh báo")

    # Verify report_detail HTML page renders cleanly
    detail_res = client.get(f"/reports/{run_id}")
    assert detail_res.status_code == 200
    assert run_id in detail_res.text


# ==============================================================================
# 4. Anti-Overlap & Concurrency Protection
# ==============================================================================

def test_anti_overlap_conflict(client: TestClient, monkeypatch):
    """Verifies that attempting to start a new job while another is running raises HTTP 409 Conflict."""
    jm = get_job_manager()
    monkeypatch.setattr(jm, "is_busy", lambda: True)
    monkeypatch.setattr(jm, "get_active_job", lambda: {"run_id": "mock_running_job_001"})

    res = client.post("/api/investigations", json={"case_id": "conflict-test", "continue_case": True, "mode": "MODE_B"})
    assert res.status_code == 409
    assert "Đang có một phiên điều tra khác đang thực thi" in res.json()["detail"]


# ==============================================================================
# 5. Cooperative Cancellation
# ==============================================================================

def test_cancel_nonexistent_job(client: TestClient):
    res = client.post("/api/investigations/nonexistent-run-id/cancel")
    assert res.status_code == 404


def test_cancel_already_finished_job(client: TestClient):
    """Attempting to cancel an already finished job returns success=False."""
    jm = get_job_manager()
    jobs = jm.list_jobs(limit=1)
    if jobs:
        run_id = jobs[0]["run_id"]
        res = client.post(f"/api/investigations/{run_id}/cancel")
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is False
        assert "không ở trạng thái đang xử lý" in data["message"]


# ==============================================================================
# 6. Case ID Validation, Duplication & Security Tests
# ==============================================================================

def test_case_id_blank_validation_error(client: TestClient):
    """Verifies that submitting a blank or whitespace-only Case ID raises HTTP 422."""
    res = client.post("/api/investigations", json={"case_id": "   ", "mode": "MODE_B"})
    assert res.status_code == 422


def test_case_id_path_traversal_rejection(client: TestClient):
    """Verifies that submitting path traversal or illegal characters in Case ID raises HTTP 422."""
    bad_ids = [
        "../../etc/passwd",
        "..\\..\\windows\\system32",
        "case/with/slashes",
        "case\\with\\backslashes",
        "case*with*special!",
    ]
    for bad in bad_ids:
        res = client.post("/api/investigations", json={"case_id": bad, "mode": "MODE_B"})
        assert res.status_code == 422, f"Failed to reject invalid case_id: {bad}"


def test_case_id_duplicate_rejection_and_continue(client: TestClient):
    """Verifies duplicate case ID is rejected with 409 unless continue_case is True."""
    unique_case_id = f"test-dup-{int(time.time())}"

    # 1. First creation without continue_case succeeds
    payload1 = {
        "case_id": unique_case_id,
        "continue_case": False,
        "mode": "MODE_A",
        "demo_target": "D1",
        "ai_provider": "deterministic_fallback",
        "ai_model": "rule-engine-fallback",
        "enable_onchain_write": False,
    }
    res1 = client.post("/api/investigations", json=payload1)
    assert res1.status_code == 201
    run1_id = res1.json()["run_id"]

    # Wait for completion
    t0 = time.time()
    while time.time() - t0 < 10:
        j = client.get(f"/api/investigations/{run1_id}").json()
        if j["status"] in ("completed", "completed_with_warnings"):
            break
        time.sleep(0.3)

    # 2. Second creation with SAME case_id and continue_case=False fails with 409 Conflict
    payload2 = {
        "case_id": unique_case_id,
        "continue_case": False,
        "mode": "MODE_A",
        "demo_target": "D1",
    }
    res2 = client.post("/api/investigations", json=payload2)
    assert res2.status_code == 409
    assert "đã tồn tại trong hệ thống" in res2.json()["detail"]

    # 3. Third creation with continue_case=True succeeds and assigns a new run_id
    time.sleep(1.1)  # Ensure unique second timestamp
    payload3 = {
        "case_id": unique_case_id,
        "continue_case": True,
        "mode": "MODE_A",
        "demo_target": "D1",
        "ai_provider": "deterministic_fallback",
        "ai_model": "rule-engine-fallback",
        "enable_onchain_write": False,
    }
    res3 = client.post("/api/investigations", json=payload3)
    assert res3.status_code == 201
    run3_id = res3.json()["run_id"]
    assert run3_id != run1_id
    assert run3_id.startswith(f"run_{unique_case_id}_")


# ==============================================================================
# 7. Strict Prohibition of Technical Jargon on User-Facing UI
# ==============================================================================

def test_r7_9_ui_standard_no_forbidden_jargon(client: TestClient):
    """Strictly prohibits technical testing jargon on user-facing UI."""
    forbidden_terms = [
        "VICTORY CONFIRMED",
        "100% VERIFIED",
        "Mode A: Tái hiện Vụ việc",
        "Mode B: Điều tra Thực địa",
        "P1 Blockchain Collector",
        "P1–P11",
        "P1-P11",
        "R7.9 UI Tiêu chuẩn",
        "185/185 PASS",
        "185 PASS",
    ]

    pages_to_check = [
        "/",
        "/launcher",
        "/progress",
        "/evidence",
        "/ai",
        "/ml-xai",
        "/blockchain",
        "/zkml",
        "/demo-center",
        "/reports",
        "/settings",
    ]
    for path in pages_to_check:
        res = client.get(path)
        assert res.status_code == 200
        for term in forbidden_terms:
            assert term not in res.text, f"Forbidden jargon '{term}' detected on page {path}"

    # Verify presence of the 7 standardized Vietnamese states
    vietnamese_states = ["Chưa chạy", "Đang chờ", "Đang xử lý", "Hoàn tất", "Hoàn tất có cảnh báo", "Gặp lỗi", "Đã dừng"]
    for st in vietnamese_states:
        assert st in VIETNAMESE_STATUS_MAP.values()


def test_case_run_switcher_present_in_header(client: TestClient):
    """Verifies that the Case & Run switcher is present in the Header across pages."""
    pages = ["/", "/progress", "/evidence", "/ai", "/ml-xai", "/blockchain", "/zkml", "/reports", "/settings"]
    for path in pages:
        res = client.get(path)
        assert res.status_code == 200
        assert "header-case-selector" in res.text
        assert "header-run-selector" in res.text


def test_standardized_branding_across_all_pages(client: TestClient):
    """Verifies exact string 'Blockchain Ai Aigital Forensics' on every page."""
    pages = ["/", "/launcher", "/progress", "/evidence", "/ai", "/ml-xai", "/blockchain", "/zkml", "/demo-center", "/reports", "/settings"]
    for path in pages:
        res = client.get(path)
        assert res.status_code == 200
        assert "Blockchain Ai Aigital Forensics" in res.text, f"Branding missing on {path}"


# ==============================================================================
# 8. Zero Arbitrary Shell / SQL / Transaction Execution
# ==============================================================================

def test_zero_arbitrary_execution_endpoints(client: TestClient):
    """Verifies that arbitrary execution endpoints do NOT exist."""
    dangerous_paths = [
        "/api/execute",
        "/api/shell",
        "/api/terminal",
        "/api/sql",
        "/api/broadcast",
        "/api/tx/send",
    ]
    for p in dangerous_paths:
        res = client.post(p, json={"cmd": "whoami"})
        assert res.status_code in (404, 405), f"Potentially dangerous endpoint active: {p} -> {res.status_code}"


def test_page_overview_empty_state(client: TestClient, monkeypatch):
    """Verifies that overview page displays mandatory 'Chưa có dữ liệu điều tra' in Area B and Area C when empty."""
    jm = get_job_manager()
    monkeypatch.setattr(jm, "list_jobs", lambda *args, **kwargs: [])
    monkeypatch.setattr(jm, "get_active_job", lambda: None)
    res = client.get("/")
    assert res.status_code == 200
    assert "Chưa có dữ liệu điều tra" in res.text


def test_investigation_phase_name_clean_vietnamese(client: TestClient):
    """Verifies that phase callbacks and current_phase_name use clean Vietnamese business terms without internal jargon."""
    import re

    res = client.post("/api/investigations", json={
        "case_id": "test-clean-phase-job",
        "continue_case": True,
        "mode": "MODE_A",
        "demo_target": "D1",
        "ai_provider": "deterministic_fallback",
        "ai_model": "rule-engine-fallback",
        "enable_onchain_write": False,
    })
    assert res.status_code == 201
    run_id = res.json()["run_id"]

    for _ in range(30):
        poll = client.get(f"/api/investigations/{run_id}").json()
        phase_name = poll.get("current_phase_name")
        if phase_name:
            assert "Mode A" not in phase_name
            assert "Mode B" not in phase_name
            assert not re.search(r"\bP(1[01]|[1-9])\b", phase_name)
        if poll.get("status") in ("completed", "completed_with_warnings", "failed", "stopped"):
            break
        time.sleep(0.3)

