"""Milestone 5 Adversarial Challenger Test Suite:
End-to-End Scenarios A & B, Boundary Conditions, Anti-SSRF Defense & Crash Recovery.

Adversarial Verification Categories:
1. Scenario A Stress: Blank Case ID, special characters, multi-file ingestion isolation,
   0-byte file, corrupt JSON/CSV/SQLite uploads, SchemaCompatibilityError (HTTP 422).
2. Scenario B Stress: Safe live RPC boundaries, max_blocks > 500, negative blocks,
   invalid URLs, state-modifying RPC methods (ReadOnlyViolationError).
3. Anti-SSRF Security Guardrails: Private IPs (10/8, 172.16/12, 192.168/16), loopback without
   allow_local, cloud metadata (169.254.169.254, fd00:ec2::254), IPv6 link-local (fe80::1),
   and HTTP Redirect evasion denial (301, 302, 307, 308).
4. Server Reboot Recovery: Simulated crash during 8-stage execution, frozen progress (< 100%),
   job failed state, and append-only audit trail in execution_log.txt.
5. Canonical Database Bitwise Invariance: Bitwise SHA-256 preservation before and after test execution.
"""

from __future__ import annotations

import http.server
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
from typing import Any, Dict, List
import pytest
from fastapi.testclient import TestClient

from dashboard.app import app
from dashboard.services.job_manager import JobManager
from forensics.paths import (
    get_benchmark_db,
    get_endpoint_evidence_db,
    get_forensics_db,
    get_real_p4_db,
)
from forensics.rpc_guard import (
    ReadOnlyViolationError,
    RpcAllowlistError,
    SSRFSecurityError,
    check_ssrf_safety,
    is_read_only_method,
    safe_rpc_call,
    validate_rpc_url,
)
from forensics.service import compute_sha256

CANONICAL_HASHES = {
    "real_p4.db": "6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97",
    "forensics.db": "3F2B0DFC772A96FF6EA57C65807B5B6B9A20FCF74C409C6F222FCFF29F1EF001",
    "benchmark_p6.db": "C7FF724CD214EEF57E58A6FBE44DBEB2712C54B035907B2A6279A255C0E80507",
    "endpoint_evidence.db": "CAF3F0B30C0F864150CA5DCBD45DD19927A53620001AB696228A744C959B7CD0",
}


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture(autouse=True)
def verify_db_invariance():
    """Asserts that all 4 canonical databases maintain bitwise SHA-256 invariance before and after each test."""
    dbs = {
        "real_p4.db": get_real_p4_db(),
        "forensics.db": get_forensics_db(),
        "benchmark_p6.db": get_benchmark_db(),
        "endpoint_evidence.db": get_endpoint_evidence_db(),
    }
    for name, path in dbs.items():
        assert path.is_file(), f"Missing db: {name}"
        h = compute_sha256(path)
        assert h == CANONICAL_HASHES[name], f"Pre-test mutation in {name}: {h}"

    yield

    for name, path in dbs.items():
        h = compute_sha256(path)
        assert h == CANONICAL_HASHES[name], f"Post-test mutation in {name}: {h}"


# ==============================================================================
# 1. E2E SCENARIO A STRESS TESTING
# ==============================================================================

def test_scenario_a_blank_case_id_rejected(client: TestClient):
    """Stress test: Blank, whitespace, or empty Case IDs must be rejected without crashing."""
    dummy_file = {"file": ("test.json", io.BytesIO(b'[{"hash":"0x1","from":"0x2","value":1}]'), "application/json")}

    # Whitespace Case ID
    res1 = client.post("/api/cases/%20%20/ingest", files=dummy_file)
    assert res1.status_code == 422
    assert "không hợp lệ" in res1.json()["detail"] or "không được để trống" in res1.json()["detail"]

    # In investigation launch request
    res2 = client.post(
        "/api/investigations",
        json={"case_id": "   ", "continue_case": True, "mode": "MODE_B", "is_mock": True},
    )
    assert res2.status_code == 422


def test_scenario_a_special_characters_case_id(client: TestClient):
    """Stress test: Special chars, shell meta-characters, XSS, and SQL injection in Case ID."""
    malicious_case_ids = [
        "case$@!#%^&*()",
        "case;DROP TABLE users;",
        "case<script>alert(1)</script>",
        "case|whoami",
        "case`id`",
        "case' OR '1'='1",
    ]
    dummy_file = {"file": ("test.json", io.BytesIO(b'[{"hash":"0x1","from":"0x2","value":1}]'), "application/json")}

    for cid in malicious_case_ids:
        # 1. URL Path param test: Either FastAPI path router rejects (404) or validator rejects (422)
        res = client.post(f"/api/cases/{cid}/ingest", files=dummy_file)
        assert res.status_code in (404, 422), f"Expected 404/422 for Case ID '{cid}', got {res.status_code}"

        # 2. JSON Body test: Valid JSON string reaching _validate_case_id must return 422
        res_json = client.post(
            "/api/investigations",
            json={"case_id": cid, "continue_case": True, "mode": "MODE_B", "is_mock": True},
        )
        assert res_json.status_code == 422, f"Expected 422 for JSON Case ID '{cid}', got {res_json.status_code}"
        detail_msg = str(res_json.json()["detail"])
        assert any(k in detail_msg for k in ("không hợp lệ", "Chỉ chấp nhận", "chỉ được chứa ký tự"))


def test_scenario_a_multi_file_upload_isolation(client: TestClient):
    """Stress test: Multi-file uploads into single case maintain isolation, distinct hashes, and no overwrites."""
    case_id = f"case-multi-{int(time.time())}"

    # File 1: JSON
    tx_json = [{"hash": "0xaaa1", "from": "0x1111111111111111111111111111111111111111", "value": "100"}]
    res1 = client.post(
        f"/api/cases/{case_id}/ingest",
        files={"file": ("batch1.json", io.BytesIO(json.dumps(tx_json).encode("utf-8")), "application/json")},
    )
    assert res1.status_code == 201
    d1 = res1.json()

    # File 2: CSV
    csv_bytes = b"tx_hash,from_address,to_address,value,token_symbol,block_number\n0xbbb2,0x2222222222222222222222222222222222222222,,500,USDC,16800000\n"
    res2 = client.post(
        f"/api/cases/{case_id}/ingest",
        files={"file": ("batch2.csv", io.BytesIO(csv_bytes), "text/csv")},
    )
    assert res2.status_code == 201
    d2 = res2.json()

    # File 3: Same filename as File 1 but different content (collision stress test)
    tx_json3 = [{"hash": "0xccc3", "from": "0x3333333333333333333333333333333333333333", "value": "900"}]
    res3 = client.post(
        f"/api/cases/{case_id}/ingest",
        files={"file": ("batch1.json", io.BytesIO(json.dumps(tx_json3).encode("utf-8")), "application/json")},
    )
    assert res3.status_code == 201
    d3 = res3.json()

    # Verify distinct evidence IDs and distinct SHA-256 hashes
    assert d1["evidence_id"] != d2["evidence_id"] != d3["evidence_id"]
    assert d1["sha256"] != d2["sha256"] != d3["sha256"]

    # Verify all 3 files tracked in GET /api/cases/{case_id}/evidence
    list_res = client.get(f"/api/cases/{case_id}/evidence")
    assert list_res.status_code == 200
    ev_list = list_res.json()
    assert len(ev_list) == 3
    ev_ids = [item["evidence_id"] for item in ev_list]
    assert d1["evidence_id"] in ev_ids
    assert d2["evidence_id"] in ev_ids
    assert d3["evidence_id"] in ev_ids


def test_scenario_a_empty_evidence_file_rejected(client: TestClient):
    """Stress test: 0-byte evidence file must be rejected with HTTP 400 Bad Request."""
    case_id = f"case-empty-{int(time.time())}"
    res = client.post(
        f"/api/cases/{case_id}/ingest",
        files={"file": ("empty.dat", io.BytesIO(b""), "application/octet-stream")},
    )
    assert res.status_code == 400
    assert "rỗng" in res.json()["detail"].lower()


def test_scenario_a_corrupted_and_incompatible_uploads(client: TestClient, tmp_path):
    """Stress test: Corrupted syntax returns 400, incompatible schema returns 422 SchemaCompatibilityError,
    and neither crashes the pipeline (500).
    """
    case_id = f"case-corrupt-{int(time.time())}"

    # 1. Truncated malformed JSON -> CorruptedFileError (HTTP 400)
    broken_json = b"[{'hash': '0x123', broken_syntax"
    res1 = client.post(
        f"/api/cases/{case_id}/ingest",
        files={"file": ("broken.json", io.BytesIO(broken_json), "application/json")},
    )
    assert res1.status_code == 400
    assert "cú pháp" in res1.json()["detail"].lower() or "json" in res1.json()["detail"].lower()

    # 2. Valid JSON but incompatible non-transaction schema -> SchemaCompatibilityError (HTTP 422)
    unrelated_json = json.dumps({"app": "weather", "forecast": [{"temp": 28, "city": "Hanoi"}]}).encode("utf-8")
    res2 = client.post(
        f"/api/cases/{case_id}/ingest",
        files={"file": ("weather.json", io.BytesIO(unrelated_json), "application/json")},
    )
    assert res2.status_code == 422
    assert "cấu trúc json không chứa mảng giao dịch" in res2.json()["detail"].lower() or "không thể nhận diện" in res2.json()["detail"].lower()

    # 3. CSV with unrelated columns -> SchemaCompatibilityError (HTTP 422)
    unrelated_csv = b"employee_id,department,salary\n101,IT,5000\n102,HR,4000\n"
    res3 = client.post(
        f"/api/cases/{case_id}/ingest",
        files={"file": ("staff.csv", io.BytesIO(unrelated_csv), "text/csv")},
    )
    assert res3.status_code == 422
    assert "thiếu các cột giao dịch bắt buộc" in res3.json()["detail"].lower()

    # 4. SQLite with unrelated table schema -> SchemaCompatibilityError (HTTP 422)
    bad_db = tmp_path / "inventory.sqlite"
    conn = sqlite3.connect(bad_db)
    conn.execute("CREATE TABLE products (sku TEXT PRIMARY KEY, price REAL)")
    conn.execute("INSERT INTO products VALUES ('SKU-1', 19.99)")
    conn.commit()
    conn.close()

    res4 = client.post(
        f"/api/cases/{case_id}/ingest",
        files={"file": ("inventory.sqlite", io.BytesIO(bad_db.read_bytes()), "application/x-sqlite3")},
    )
    assert res4.status_code == 422
    assert "không chứa cấu trúc bảng chứng cứ tương thích" in res4.json()["detail"].lower()

    # 5. Corrupted binary file masquerading as SQLite -> CorruptedFileError (HTTP 400)
    fake_db = b"NOT A VALID SQLITE HEADER RANDOM NOISE 1234567890ABCDEF"
    res5 = client.post(
        f"/api/cases/{case_id}/ingest",
        files={"file": ("corrupt.db", io.BytesIO(fake_db), "application/x-sqlite3")},
    )
    assert res5.status_code == 400
    assert "bị hỏng" in res5.json()["detail"].lower() or "không thể mở" in res5.json()["detail"].lower()


# ==============================================================================
# 2. E2E SCENARIO B STRESS TESTING & SAFE LIVE RPC BOUNDARIES
# ==============================================================================

def test_scenario_b_max_blocks_boundary_exceeded(client: TestClient):
    """Stress test: Exceeding max_blocks (e.g. 501 blocks requested, limit is 500) triggers validation rejection."""
    payload = {
        "case_id": f"case-rpc-bound-{int(time.time())}",
        "rpc_url": "https://rpc.sepolia.org",
        "max_blocks": 501,  # Exceeds maximum 500
    }
    res = client.post("/api/rpc/investigate", json=payload)
    assert res.status_code == 422
    detail_str = str(res.json())
    assert "less_than_equal" in detail_str or "500" in detail_str


def test_scenario_b_request_limit_boundary_exceeded(client: TestClient):
    """Stress test: Exceeding limit_requests (e.g. 501 requests requested, limit is 500) triggers validation rejection."""
    payload = {
        "case_id": f"case-rpc-limit-{int(time.time())}",
        "rpc_url": "https://rpc.sepolia.org",
        "limit_requests": 501,  # Exceeds limit 500
    }
    res = client.post("/api/rpc/investigate", json=payload)
    assert res.status_code == 422
    detail_str = str(res.json())
    assert "less_than_equal" in detail_str or "500" in detail_str


def test_scenario_b_negative_blocks_and_invalid_urls(client: TestClient):
    """Stress test: Negative block bounds and non-HTTP protocols must be strictly rejected."""
    # Negative max_blocks
    payload1 = {
        "case_id": f"case-rpc-neg-{int(time.time())}",
        "rpc_url": "https://rpc.sepolia.org",
        "max_blocks": -5,
    }
    res1 = client.post("/api/rpc/investigate", json=payload1)
    assert res1.status_code == 422

    # Prohibited non-HTTP protocols
    invalid_schemes = [
        "ftp://rpc.sepolia.org",
        "javascript:alert(1)",
        "file:///etc/passwd",
        "gopher://127.0.0.1:8545",
    ]
    for bad_url in invalid_schemes:
        payload = {"rpc_url": bad_url}
        res = client.post("/api/rpc/preflight", json=payload)
        assert res.status_code in (400, 422)


def test_scenario_b_state_modifying_rpc_methods_strictly_forbidden():
    """Stress test: State-modifying methods (eth_sendTransaction, personal_sign, etc.) are strictly blocked."""
    forbidden_methods = [
        "eth_sendTransaction",
        "eth_sendRawTransaction",
        "personal_sign",
        "personal_sendTransaction",
        "eth_sign",
        "eth_signTransaction",
        "eth_signTypedData",
        "wallet_sendCalls",
        "personal_unlockAccount",
    ]
    for method in forbidden_methods:
        assert is_read_only_method(method) is False
        with pytest.raises(ReadOnlyViolationError) as exc_info:
            safe_rpc_call(
                rpc_url="https://rpc.sepolia.org",
                method=method,
                params=[],
            )
        assert "bị nghiêm cấm" in str(exc_info.value) or "chỉ đọc" in str(exc_info.value)


# ==============================================================================
# 3. ANTI-SSRF SECURITY GUARDRAILS STRESS TESTING
# ==============================================================================

def test_anti_ssrf_private_ip_blocking(client: TestClient):
    """Stress test: Private IPv4 and IPv6 networks (RFC 1918 / RFC 4193) are completely blocked."""
    private_endpoints = [
        "http://10.0.0.1:8545",
        "http://10.254.254.254:8545",
        "http://172.16.0.1:8545",
        "http://172.31.255.254:8545",
        "http://192.168.1.1:8545",
        "http://192.168.100.50:8545",
        "http://[fc00::1]:8545",
        "http://[fd12:3456:789a::1]:8545",
    ]
    for bad_ip in private_endpoints:
        # Direct check_ssrf_safety
        clean_ip = bad_ip.replace("http://", "").replace("https://", "").split(":")[0].strip("[]")
        assert check_ssrf_safety(clean_ip, allow_local=True) is False, f"Private IP {clean_ip} must be unsafe even with allow_local"

        # Preflight API check
        res = client.post("/api/rpc/preflight", json={"rpc_url": bad_ip, "allow_local": False})
        assert res.status_code in (403, 422), f"Expected rejection for {bad_ip}, got {res.status_code}"


def test_anti_ssrf_loopback_isolation_guardrail(client: TestClient):
    """Stress test: Loopback (127.0.0.1, localhost, ::1) is rejected when allow_local=False,
    and only permitted when allow_local=True for authorized Anvil testing.
    """
    loopback_endpoints = [
        "http://127.0.0.1:8545",
        "http://127.0.0.2:8545",
        "http://localhost:8545",
        "http://[::1]:8545",
    ]
    for loopback in loopback_endpoints:
        # Blocked without allow_local
        res_blocked = client.post("/api/rpc/preflight", json={"rpc_url": loopback, "allow_local": False})
        assert res_blocked.status_code in (403, 422), f"Expected loopback rejection without allow_local: {loopback}"

        # URL validation raises SSRFSecurityError
        with pytest.raises(SSRFSecurityError):
            validate_rpc_url(loopback, allow_local=False, raise_on_error=True)


def test_anti_ssrf_cloud_metadata_always_blocked(client: TestClient):
    """Stress test: Cloud metadata endpoints (AWS, GCP, Azure, Oracle, fe80::) are ALWAYS blocked,
    even if allow_local=True is mistakenly enabled.
    """
    metadata_endpoints = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254:8545",
        "http://[fd00:ec2::254]:8545",
        "http://[fe80::1]:8545",
        "http://[fe80::dead:beef]:8545",
    ]
    for meta_url in metadata_endpoints:
        # Check ssrf safety returns False even with allow_local=True
        clean_ip = meta_url.replace("http://", "").split("/")[0].split(":")[0].strip("[]")
        assert check_ssrf_safety(clean_ip, allow_local=True) is False, f"Cloud metadata {clean_ip} must be blocked"

        # Preflight check must reject
        res = client.post("/api/rpc/preflight", json={"rpc_url": meta_url, "allow_local": True})
        assert res.status_code in (403, 422), f"Expected rejection for cloud metadata {meta_url}"


class RedirectingHttpHandler(http.server.BaseHTTPRequestHandler):
    """Mock HTTP server that returns redirect responses (301, 302, 307, 308)."""
    target_redirect = "http://169.254.169.254/latest/meta-data/"
    status_code = 302

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            self.rfile.read(content_length)
        self.send_response(self.status_code)
        self.send_header("Location", self.target_redirect)
        self.send_header("Content-Length", "0")
        self.end_headers()


@pytest.fixture(scope="module")
def redirect_server():
    """Starts a local server that responds with HTTP redirects."""
    server = http.server.HTTPServer(("127.0.0.1", 0), RedirectingHttpHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, f"http://127.0.0.1:{port}"
    server.shutdown()


def test_anti_ssrf_http_redirect_denial(redirect_server):
    """Stress test: Safe RPC caller must reject HTTP redirects (301, 302, 307, 308) to defeat SSRF evasion."""
    server, base_url = redirect_server

    for status_code in (301, 302, 307, 308):
        RedirectingHttpHandler.status_code = status_code
        with pytest.raises(SSRFSecurityError) as exc_info:
            safe_rpc_call(
                rpc_url=base_url,
                method="eth_blockNumber",
                allow_local=True,
                allowlist=[base_url],
            )
        assert f"chuyển hướng http {status_code}" in str(exc_info.value).lower() or "ngăn tấn công ssrf" in str(exc_info.value).lower()


# ==============================================================================
# 4. SERVER REBOOT RECOVERY STRESS TESTING
# ==============================================================================

def test_server_reboot_recovery_stress(tmp_path):
    """Stress test: Simulate interrupted job during 8-stage execution.
    Verify recovery marks job as 'failed', freezes progress percent, and writes audit entry to execution_log.txt.
    """
    session_dir = tmp_path / "run-crash-test"
    session_dir.mkdir(parents=True, exist_ok=True)
    exec_log_file = session_dir / "execution_log.txt"
    exec_log_file.write_text("2026-11-08T00:00:00Z [INFO] Giai đoạn S1 hoàn tất.\n", encoding="utf-8")

    jobs_file = tmp_path / "jobs_crash.json"
    lock_file = tmp_path / "jobs_crash.lock"

    interrupted_job = {
        "run_id": "run-crash-test",
        "case_id": "case-crash-audit",
        "mode": "MODE_B",
        "status": "running",
        "vietnamese_status": "Đang xử lý",
        "progress_percent": 62,
        "current_stage": "S5",
        "current_stage_name": "Phân tích AI và giải thích kết quả",
        "stage_status": {
            "S1": "completed",
            "S2": "completed",
            "S3": "completed",
            "S4": "completed",
            "S5": "running",
            "S6": "not_started",
            "S7": "not_started",
            "S8": "not_started",
        },
        "phase_status": {
            "P1": "completed",
            "P2": "completed",
            "P3": "completed",
            "P4": "completed",
            "P5": "running",
            "P6": "not_started",
            "P7": "not_started",
            "P8": "not_started",
            "P9": "not_started",
            "P10": "not_started",
            "P11": "not_started",
        },
        "artifacts": {
            "execution_log": str(exec_log_file),
        },
        "start_time": "2026-11-08T00:00:00Z",
    }
    jobs_file.write_text(json.dumps({"run-crash-test": interrupted_job}), encoding="utf-8")

    # Instantiate new JobManager (simulating server reboot)
    jm = JobManager(jobs_file=jobs_file, lock_file=lock_file)
    recovered = jm.get_job("run-crash-test")

    assert recovered is not None
    # 1. State must be failed
    assert recovered["status"] == "failed"
    assert recovered["vietnamese_status"] == "Gặp lỗi"

    # 2. Progress must be frozen (must NOT jump to 100%)
    assert recovered["progress_percent"] == 62

    # 3. Running stage S5 and phase P5 must transition to failed
    assert recovered["stage_status"]["S5"] == "failed"
    assert recovered["phase_status"]["P5"] == "failed"

    # 4. Error message must state server restart
    assert "khởi động lại" in recovered.get("error_message", "").lower()

    # 5. execution_log.txt must have audit log appended
    log_content = exec_log_file.read_text(encoding="utf-8")
    assert "Phiên bị gián đoạn do máy chủ khởi động lại" in log_content
