"""Empirical Adversarial Challenge Suite: Case Management, Validation & Path Traversal.

Author: Empirical Challenger (critic, specialist)
Milestone: M1 Branding, Jargon Elimination, Case Management & UI Architecture
Targets:
- Path Traversal & Injection Vectors in Case ID
- Duplicate Case ID Prevention (HTTP 409) & Multi-Run Execution (continue_case=True)
- Cross-Case Data Isolation & Non-Leakage across Storage, API, and UI Context
- Canonical Database Bitwise Invariance
"""

from __future__ import annotations

import json
from pathlib import Path
import time
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from dashboard.app import app
from dashboard.schemas import LaunchInvestigationRequest
from dashboard.services.job_manager import get_job_manager
from forensics.paths import (
    get_benchmark_db,
    get_endpoint_evidence_db,
    get_forensics_db,
    get_output_dir,
    get_real_p4_db,
)
from forensics.service import compute_sha256

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
def canonical_db_guard():
    """Verify bitwise integrity of all 4 canonical databases before and after every test."""
    dbs = {
        "real_p4.db": get_real_p4_db(),
        "forensics.db": get_forensics_db(),
        "benchmark_p6.db": get_benchmark_db(),
        "endpoint_evidence.db": get_endpoint_evidence_db(),
    }
    for name, p in dbs.items():
        assert p.is_file(), f"Canonical database missing: {name} at {p}"
        digest = compute_sha256(p)
        assert digest == CANONICAL_HASHES[name], f"Canonical DB pre-test mutation: {name}"

    yield

    for name, p in dbs.items():
        digest = compute_sha256(p)
        assert digest == CANONICAL_HASHES[name], f"Canonical DB post-test mutation: {name}"


# ==============================================================================
# Suite 1: Path Traversal, Injection & Validation Rejections
# ==============================================================================

class TestAdversarialCaseIdValidation:
    """Stress-tests input validation on Case ID against malicious payloads."""

    PATH_TRAVERSAL_PAYLOADS = [
        "../../etc/passwd",
        "..\\windows\\system32",
        "..\\..\\windows\\system32",
        "../../../../../../../../etc/shadow",
        "..",
        ".",
        "...",
        "....",
        "../",
        "..\\",
        "/etc/passwd",
        "\\windows\\system32",
        "C:\\Windows\\System32",
        "D:/Projest/Blockchain/reports",
        "file:///etc/passwd",
        "case/id",
        "case\\id",
        "case/with/slashes",
        "case\\with\\backslashes",
        "case..id",
        "case...id",
        ".case",
        "case.",
        "case.id",
        "/",
        "\\",
        "//",
        "\\\\",
    ]

    NULL_AND_CONTROL_PAYLOADS = [
        "case\x00id",
        "\x00",
        "case\x00",
        "\x00case",
        "case%00id",
        "case\nid",
        "case\rid",
        "case\tid",
        "case\x08id",
        "case\x1bid",
        "case\x7fid",
        "case\x01\x02",
    ]

    SPACE_PAYLOADS = [
        "case id",
        "case  id",
        "   ",
        "",
        "\t",
        "\n",
        "\r\n",
        "case\xa0id",  # Non-breaking space
        "\u200b",      # Zero-width space
        "\u3000",      # Ideographic space
    ]

    UNICODE_AND_SPECIAL_PAYLOADS = [
        "vụ-án-01",
        "case_⚡",
        "../\u2215../etc",  # Unicode division slash
        "\u202e",          # Right-to-left override
        "ｃａｓｅ",          # Fullwidth characters
        "саѕе",            # Cyrillic homoglyphs
        "案例_01",         # CJK characters
        "مرحبا",           # Arabic
        "case_🔥_2026",    # Emoji
        "case#1",
        "case?id=1",
        "case&id=2",
        "case<script>",
        "case' OR '1'='1",
        "case;rm -rf",
        "case$ENV",
        "case`whoami`",
        "case|cat",
    ]

    @pytest.mark.parametrize("payload", PATH_TRAVERSAL_PAYLOADS)
    def test_path_traversal_payloads_rejected(self, client: TestClient, payload: str):
        """Verify path traversal payloads in Case ID are rejected with HTTP 422."""
        # 1. Direct schema validation
        with pytest.raises(ValidationError):
            LaunchInvestigationRequest(case_id=payload, mode="MODE_A")

        # 2. API endpoint validation
        res = client.post("/api/investigations", json={"case_id": payload, "mode": "MODE_A"})
        assert res.status_code == 422, f"Failed to reject path traversal payload: {repr(payload)} (Status: {res.status_code})"

    @pytest.mark.parametrize("payload", NULL_AND_CONTROL_PAYLOADS)
    def test_null_bytes_and_control_chars_rejected(self, client: TestClient, payload: str):
        """Verify null bytes and control chars in Case ID are rejected with HTTP 422."""
        with pytest.raises(ValidationError):
            LaunchInvestigationRequest(case_id=payload, mode="MODE_A")

        res = client.post("/api/investigations", json={"case_id": payload, "mode": "MODE_A"})
        assert res.status_code == 422, f"Failed to reject null/control payload: {repr(payload)}"

    @pytest.mark.parametrize("payload", SPACE_PAYLOADS)
    def test_spaces_and_whitespace_rejected(self, client: TestClient, payload: str):
        """Verify spaces and blank strings in Case ID are rejected with HTTP 422."""
        with pytest.raises(ValidationError):
            LaunchInvestigationRequest(case_id=payload, mode="MODE_A")

        res = client.post("/api/investigations", json={"case_id": payload, "mode": "MODE_A"})
        assert res.status_code == 422, f"Failed to reject space payload: {repr(payload)}"

    @pytest.mark.parametrize("payload", UNICODE_AND_SPECIAL_PAYLOADS)
    def test_unicode_and_special_chars_rejected(self, client: TestClient, payload: str):
        """Verify Unicode, emojis, and special chars in Case ID are rejected with HTTP 422."""
        with pytest.raises(ValidationError):
            LaunchInvestigationRequest(case_id=payload, mode="MODE_A")

        res = client.post("/api/investigations", json={"case_id": payload, "mode": "MODE_A"})
        assert res.status_code == 422, f"Failed to reject special/unicode payload: {repr(payload)}"

    def test_length_boundary_conditions(self, client: TestClient):
        """Verify string length boundary limits: 1 to 64 chars allowed, >= 65 rejected."""
        # Lower bound: 1 char valid
        req1 = LaunchInvestigationRequest(case_id="a", mode="MODE_A")
        assert req1.case_id == "a"

        # Upper bound: exactly 64 chars valid
        case_64 = "A" * 64
        req64 = LaunchInvestigationRequest(case_id=case_64, mode="MODE_A")
        assert req64.case_id == case_64

        # Boundary violation: 65 chars rejected
        case_65 = "A" * 65
        with pytest.raises(ValidationError):
            LaunchInvestigationRequest(case_id=case_65, mode="MODE_A")
        res_65 = client.post("/api/investigations", json={"case_id": case_65, "mode": "MODE_A"})
        assert res_65.status_code == 422

        # Extreme overlength: 100, 1000 chars rejected
        for length in (100, 1000):
            payload = "B" * length
            with pytest.raises(ValidationError):
                LaunchInvestigationRequest(case_id=payload, mode="MODE_A")
            res_ov = client.post("/api/investigations", json={"case_id": payload, "mode": "MODE_A"})
            assert res_ov.status_code == 422

    def test_type_fuzzing_rejected(self, client: TestClient):
        """Verify non-string types and missing case_id are rejected with HTTP 422."""
        # Missing case_id
        res_missing = client.post("/api/investigations", json={"mode": "MODE_A"})
        assert res_missing.status_code == 422

        # Null case_id
        res_null = client.post("/api/investigations", json={"case_id": None, "mode": "MODE_A"})
        assert res_null.status_code == 422

        # Array case_id
        res_arr = client.post("/api/investigations", json={"case_id": ["case1"], "mode": "MODE_A"})
        assert res_arr.status_code == 422

        # Object case_id
        res_obj = client.post("/api/investigations", json={"case_id": {"id": "test"}, "mode": "MODE_A"})
        assert res_obj.status_code == 422

        # Boolean case_id
        res_bool = client.post("/api/investigations", json={"case_id": True, "mode": "MODE_A"})
        assert res_bool.status_code == 422


# ==============================================================================
# Suite 2: Duplicate Case ID Handling & Multi-Run Execution
# ==============================================================================

class TestDuplicateCaseManagement:
    """Stress-tests duplicate Case ID handling, conflict detection, and continue_case multi-run support."""

    def test_duplicate_case_rejection_and_multi_run_success(self, client: TestClient):
        """Verifies duplicate case ID returns 409 Conflict without continue_case, and allows multi-runs with continue_case."""
        unique_id = f"adv-dup-{int(time.time())}"

        # Step 1: First creation of unique_id without continue_case succeeds
        payload1 = {
            "case_id": unique_id,
            "continue_case": False,
            "mode": "MODE_A",
            "demo_target": "D1",
            "ai_provider": "deterministic_fallback",
            "ai_model": "rule-engine-fallback",
            "enable_onchain_write": False,
        }
        res1 = client.post("/api/investigations", json=payload1)
        assert res1.status_code == 201, f"Initial creation failed: {res1.text}"
        run1 = res1.json()["run_id"]
        assert run1.startswith(f"run_{unique_id}_")

        # Wait for run1 to complete
        t0 = time.time()
        while time.time() - t0 < 15:
            st = client.get(f"/api/investigations/{run1}").json().get("status")
            if st in ("completed", "completed_with_warnings", "failed", "stopped"):
                break
            time.sleep(0.3)

        # Step 2: Attempting to create duplicate case with continue_case=False MUST return HTTP 409 Conflict
        payload2 = {
            "case_id": unique_id,
            "continue_case": False,
            "mode": "MODE_A",
            "demo_target": "D1",
        }
        res2 = client.post("/api/investigations", json=payload2)
        assert res2.status_code == 409, f"Duplicate was not rejected with 409: {res2.status_code}"
        assert "đã tồn tại trong hệ thống" in res2.json()["detail"]
        assert "Tiếp tục điều tra" in res2.json()["detail"]

        # Step 3: Attempting creation with SAME case_id and continue_case=True MUST succeed with HTTP 201
        time.sleep(1.1)  # Ensure distinct second-level timestamp
        payload3 = {
            "case_id": unique_id,
            "continue_case": True,
            "mode": "MODE_A",
            "demo_target": "D1",
            "ai_provider": "deterministic_fallback",
            "ai_model": "rule-engine-fallback",
            "enable_onchain_write": False,
        }
        res3 = client.post("/api/investigations", json=payload3)
        assert res3.status_code == 201, f"Multi-run submission failed: {res3.text}"
        run2 = res3.json()["run_id"]
        assert run2.startswith(f"run_{unique_id}_")
        assert run2 != run1, "Multi-run failed to generate unique run_id"

        # Wait for run2 to complete
        t0 = time.time()
        while time.time() - t0 < 15:
            st = client.get(f"/api/investigations/{run2}").json().get("status")
            if st in ("completed", "completed_with_warnings", "failed", "stopped"):
                break
            time.sleep(0.3)

        # Step 4: Verify GET /api/cases returns both runs under this single Case ID
        cases_res = client.get("/api/cases")
        assert cases_res.status_code == 200
        cases_data = cases_res.json()
        assert unique_id in cases_data, f"Case {unique_id} missing from /api/cases"
        runs_in_case = [r["run_id"] for r in cases_data[unique_id]]
        assert run1 in runs_in_case, f"Run 1 {run1} missing from case {unique_id}"
        assert run2 in runs_in_case, f"Run 2 {run2} missing from case {unique_id}"
        assert len(runs_in_case) >= 2


# ==============================================================================
# Suite 3: Cross-Case Data Isolation & Non-Leakage
# ==============================================================================

class TestCrossCaseDataIsolation:
    """Empirically verifies that independent cases do NOT leak data to each other."""

    @pytest.fixture(scope="class")
    def independent_runs(self, client: TestClient):
        """Creates two independent completed runs under different cases."""
        ts = int(time.time())
        case_a = f"adv-iso-alpha-{ts}"
        case_b = f"adv-iso-beta-{ts}"

        # Launch Case A
        res_a = client.post("/api/investigations", json={
            "case_id": case_a,
            "continue_case": False,
            "mode": "MODE_A",
            "demo_target": "D1",
            "ai_provider": "deterministic_fallback",
            "ai_model": "rule-engine-fallback",
            "enable_onchain_write": False,
        })
        assert res_a.status_code == 201
        run_a = res_a.json()["run_id"]

        # Wait for Case A completion
        t0 = time.time()
        while time.time() - t0 < 15:
            st = client.get(f"/api/investigations/{run_a}").json().get("status")
            if st in ("completed", "completed_with_warnings"):
                break
            time.sleep(0.3)

        # Launch Case B
        time.sleep(1.1)
        res_b = client.post("/api/investigations", json={
            "case_id": case_b,
            "continue_case": False,
            "mode": "MODE_A",
            "demo_target": "D1",
            "ai_provider": "deterministic_fallback",
            "ai_model": "rule-engine-fallback",
            "enable_onchain_write": False,
        })
        assert res_b.status_code == 201
        run_b = res_b.json()["run_id"]

        # Wait for Case B completion
        t0 = time.time()
        while time.time() - t0 < 15:
            st = client.get(f"/api/investigations/{run_b}").json().get("status")
            if st in ("completed", "completed_with_warnings"):
                break
            time.sleep(0.3)

        return {
            "case_a": case_a,
            "run_a": run_a,
            "case_b": case_b,
            "run_b": run_b,
        }

    def test_file_and_directory_storage_isolation(self, independent_runs):
        """Verifies session artifacts are written to isolated directories without cross-contamination."""
        run_a = independent_runs["run_a"]
        run_b = independent_runs["run_b"]
        case_a = independent_runs["case_a"]
        case_b = independent_runs["case_b"]

        reports_dir = get_output_dir()
        dir_a = reports_dir / run_a
        dir_b = reports_dir / run_b

        assert dir_a.is_dir(), f"Case A output dir does not exist: {dir_a}"
        assert dir_b.is_dir(), f"Case B output dir does not exist: {dir_b}"
        assert dir_a != dir_b, "Output directories collided"

        # Check all 5 artifacts in Dir A
        required_artifacts = [
            "investigation_report.html",
            "report.json",
            "evidence_manifest.json",
            "custody_receipts.json",
            "execution_log.txt",
        ]
        for art in required_artifacts:
            file_a = dir_a / art
            assert file_a.is_file(), f"Artifact {art} missing in Dir A"
            content_a = file_a.read_text(encoding="utf-8", errors="ignore")
            # Must contain Case A references
            assert run_a in content_a or case_a in content_a
            # Must NOT leak Case B references
            assert run_b not in content_a, f"Data leak: {run_b} found in Case A artifact {art}"
            assert case_b not in content_a, f"Data leak: {case_b} found in Case A artifact {art}"

        # Check all 5 artifacts in Dir B
        for art in required_artifacts:
            file_b = dir_b / art
            assert file_b.is_file(), f"Artifact {art} missing in Dir B"
            content_b = file_b.read_text(encoding="utf-8", errors="ignore")
            # Must contain Case B references
            assert run_b in content_b or case_b in content_b
            # Must NOT leak Case A references
            assert run_a not in content_b, f"Data leak: {run_a} found in Case B artifact {art}"
            assert case_a not in content_b, f"Data leak: {case_a} found in Case B artifact {art}"

    def test_api_artifact_isolation_and_traversal_protection(self, client: TestClient, independent_runs):
        """Verifies API endpoints return strictly isolated data and reject path traversal between runs."""
        run_a = independent_runs["run_a"]
        run_b = independent_runs["run_b"]
        case_a = independent_runs["case_a"]
        case_b = independent_runs["case_b"]

        # Run A artifact
        res_a = client.get(f"/api/investigations/{run_a}/artifacts/report.json")
        assert res_a.status_code == 200
        data_a = res_a.json()
        assert data_a["run_info"]["run_id"] == run_a
        assert data_a["run_info"]["case_id"] == case_a

        # Run B artifact
        res_b = client.get(f"/api/investigations/{run_b}/artifacts/report.json")
        assert res_b.status_code == 200
        data_b = res_b.json()
        assert data_b["run_info"]["run_id"] == run_b
        assert data_b["run_info"]["case_id"] == case_b

        # Path traversal attack via artifact endpoint
        traversal_attempts = [
            f"/api/investigations/{run_a}/artifacts/../{run_b}/report.json",
            f"/api/investigations/{run_a}/artifacts/..\\{run_b}\\report.json",
            f"/api/investigations/{run_a}/artifacts/../../etc/passwd",
            f"/api/investigations/{run_a}/artifacts/..\\..\\windows\\win.ini",
            f"/api/investigations/{run_a}/artifacts/%2e%2e%2f{run_b}%2freport.json",
            f"/api/investigations/{run_a}/artifacts/nonexistent_file.xyz",
        ]
        for url in traversal_attempts:
            res_trav = client.get(url)
            assert res_trav.status_code == 404, f"Traversal attack was not rejected with 404: {url} (Got: {res_trav.status_code})"

    def test_ui_case_filtering_isolation(self, client: TestClient, independent_runs):
        """Verifies HTML pages filter reports strictly by case_id without cross-case bleeding."""
        run_a = independent_runs["run_a"]
        run_b = independent_runs["run_b"]
        case_a = independent_runs["case_a"]
        case_b = independent_runs["case_b"]

        # 1. Reports hub filtered by Case A
        res_page_a = client.get(f"/reports?case_id={case_a}")
        assert res_page_a.status_code == 200
        # Should contain Case A and Run A
        assert case_a in res_page_a.text
        assert run_a in res_page_a.text
        # Should NOT contain Case B or Run B in report rows
        assert f"/reports/{run_b}" not in res_page_a.text, f"Run B leaked into Case A reports page"

        # 2. Reports hub filtered by Case B
        res_page_b = client.get(f"/reports?case_id={case_b}")
        assert res_page_b.status_code == 200
        # Should contain Case B and Run B
        assert case_b in res_page_b.text
        assert run_b in res_page_b.text
        # Should NOT contain Case A or Run A in report rows
        assert f"/reports/{run_a}" not in res_page_b.text, f"Run A leaked into Case B reports page"

        # 3. Report detail pages
        detail_a = client.get(f"/reports/{run_a}")
        assert detail_a.status_code == 200
        assert run_a in detail_a.text
        assert case_a in detail_a.text
        assert run_b not in detail_a.text

        detail_b = client.get(f"/reports/{run_b}")
        assert detail_b.status_code == 200
        assert run_b in detail_b.text
        assert case_b in detail_b.text
        assert run_a not in detail_b.text

        # 4. Querying non-existent case displays clean empty state without leakage
        res_ghost = client.get("/reports?case_id=nonexistent-ghost-case")
        assert res_ghost.status_code == 200
        assert "Chưa có dữ liệu điều tra" in res_ghost.text
        assert run_a not in res_ghost.text
        assert run_b not in res_ghost.text

    def test_business_pages_active_selection_isolation(self, client: TestClient, independent_runs):
        """Verifies business pages render with selected_job bound strictly to the active run_id."""
        run_a = independent_runs["run_a"]
        case_a = independent_runs["case_a"]
        run_b = independent_runs["run_b"]
        case_b = independent_runs["case_b"]

        pages_to_test = [
            "/progress",
            "/evidence",
            "/ai",
            "/ml-xai",
            "/blockchain",
            "/zkml",
        ]
        for page in pages_to_test:
            # Query with Case A and Run A
            res_a = client.get(f"{page}?case_id={case_a}&run_id={run_a}")
            assert res_a.status_code == 200
            assert run_a in res_a.text
            assert run_b not in res_a.text

            # Query with Case B and Run B
            res_b = client.get(f"{page}?case_id={case_b}&run_id={run_b}")
            assert res_b.status_code == 200
            assert run_b in res_b.text
            assert run_a not in res_b.text
