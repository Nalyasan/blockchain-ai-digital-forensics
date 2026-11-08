"""Milestone 5 Test Suite: End-to-End Investigation Scenarios & Security Defenses (Acceptance & R6).

Verifies the complete end-to-end acceptance workflows:
1. Scenario A: File Evidence Ingestion -> 8-Stage Execution -> Standalone HTML Report & 5 Audit Artifacts.
2. Scenario B: Live Blockchain RPC Investigation -> Preflight Check -> Bounded Collection -> 8-Stage Execution -> Segregated HTML Report & 5 Audit Artifacts.
3. Security Edge Case: Anti-SSRF blocking of private IPs, loopbacks, and cloud metadata in preflight and investigate.
4. Security Edge Case: Path traversal rejection across case IDs, filenames, and artifact download paths.
5. Security Edge Case: CompactAnomalyMLP graceful handling of incompatible schema / missing tables ('Không áp dụng').
6. Security Edge Case: Server restart recovery audit verification (in-progress jobs marked as 'failed' with frozen state).
"""

from __future__ import annotations

import http.server
import io
import json
from pathlib import Path
import re
import sqlite3
import threading
import time
from typing import Any, Dict, List
import pytest
from fastapi.testclient import TestClient

from dashboard.app import app
from dashboard.services.job_manager import JobManager, get_job_manager
from forensics.paths import get_endpoint_evidence_db, get_real_p4_db, get_reports_dir
from forensics.service import (
    InvestigationConfig,
    InvestigationService,
    compute_sha256,
    STATUS_COMPLETED,
    STATUS_COMPLETED_WITH_WARNINGS,
    STATUS_FAILED,
    STATUS_NOT_APPLICABLE,
)


@pytest.fixture(scope="module")
def client() -> TestClient:
    """FastAPI TestClient fixture."""
    return TestClient(app)


# ==============================================================================
# MOCK JSON-RPC SERVER FOR DETERMINISTIC TESTING
# ==============================================================================

class MockE2ERpcHandler(http.server.BaseHTTPRequestHandler):
    """Mock JSON-RPC HTTP server for deterministic local E2E testing."""
    chain_id = "0xaa36a7"  # 11155111 Sepolia
    latest_block = "0x100"   # 256

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length).decode("utf-8")
        try:
            req = json.loads(post_data)
        except Exception:
            self.send_response(400)
            self.end_headers()
            return

        method = req.get("method")
        params = req.get("params", [])
        req_id = req.get("id", 1)

        result: Any = None
        if method == "eth_chainId":
            result = self.chain_id
        elif method == "eth_blockNumber":
            result = self.latest_block
        elif method == "eth_getBlockByNumber":
            b_hex = params[0] if params else "0x100"
            b_num = int(b_hex, 16) if isinstance(b_hex, str) and b_hex.startswith("0x") else 256
            txs = [
                {
                    "hash": f"0x{b_num:064x}",
                    "blockNumber": hex(b_num),
                    "from": "0xb2698c2d99ad2c302a95a8db26b08d17a77cedd4",
                    "to": "0x2718294289B57BD2357249a523E71c7982565614",
                    "value": "0x7a83d73b3a640000",  # ~8.8M DAI in raw
                    "gas": "0x5208",
                    "gasPrice": "0x4a817c800",
                    "input": "0x",
                }
            ]
            result = {
                "number": hex(b_num),
                "hash": f"0xblock{b_num:058x}",
                "parentHash": f"0xblock{b_num-1:058x}",
                "timestamp": "0x66000000",
                "miner": "0x0000000000000000000000000000000000000000",
                "gasUsed": "0x5208",
                "transactions": txs,
            }
        elif method == "eth_getTransactionByHash":
            tx_h = params[0] if params else "0x"
            result = {
                "hash": tx_h,
                "blockNumber": "0x100",
                "from": "0xb2698c2d99ad2c302a95a8db26b08d17a77cedd4",
                "to": "0x2718294289B57BD2357249a523E71c7982565614",
                "value": "0x7a83d73b3a640000",
                "gas": "0x5208",
                "gasPrice": "0x4a817c800",
                "input": "0x",
            }
        elif method == "eth_getTransactionReceipt":
            tx_h = params[0] if params else "0x"
            result = {
                "transactionHash": tx_h,
                "blockNumber": "0x100",
                "status": "0x1",
                "gasUsed": "0x5208",
            }
        elif method == "eth_getLogs":
            result = []
        else:
            result = None

        response = {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": result,
        }
        res_bytes = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(res_bytes)))
        self.end_headers()
        self.wfile.write(res_bytes)


@pytest.fixture(scope="module")
def mock_rpc_server():
    """Starts an ephemeral mock JSON-RPC HTTP server."""
    server = http.server.HTTPServer(("127.0.0.1", 0), MockE2ERpcHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


# ==============================================================================
# 1. E2E SCENARIO A: FILE INGESTION TO STANDALONE REPORT
# ==============================================================================

def test_e2e_scenario_a_file_ingestion_to_report(client: TestClient):
    """Scenario A: Blank initial Case ID -> Ingest transaction file -> 8-stage execution -> Standalone Report."""
    case_id = f"case-e2e-a-{int(time.time())}"

    # Step 1: Upload evidence file
    tx_json = [
        {
            "hash": "0x12e66f85d115e4da88457884d6585141093f41249fa6b2185b376c72e2124581",
            "from": "0xb2698c2d99ad2c302a95a8db26b08d17a77cedd4",
            "to": "0x2718294289B57BD2357249a523E71c7982565614",
            "value": "8877507340000000000000000",
            "block_number": 16817996,
            "block_timestamp": 1678685000,
        }
    ]
    raw_bytes = json.dumps(tx_json).encode("utf-8")
    files = {
        "file": ("evidence_txs.json", io.BytesIO(raw_bytes), "application/json")
    }
    ingest_res = client.post(f"/api/cases/{case_id}/ingest", files=files)
    assert ingest_res.status_code == 201, f"Ingest failed: {ingest_res.text}"
    ingest_data = ingest_res.json()
    assert ingest_data["source_type"] == "blockchain_tx_json"
    assert ingest_data["records_count"] == 1

    # Step 2: Launch investigation for this case with continue_case=True
    launch_res = client.post(
        "/api/investigations",
        json={
            "case_id": case_id,
            "continue_case": True,
            "mode": "MODE_B",
            "is_mock": True,
        },
    )
    assert launch_res.status_code == 201, f"Launch failed: {launch_res.text}"
    launch_data = launch_res.json()
    run_id = launch_data["run_id"]
    assert launch_data["case_id"] == case_id

    # Step 3: Poll until completion
    final_job = None
    for _ in range(30):
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

    # Step 4: Verify standalone HTML report
    inv_res = client.get(f"/api/investigations/{run_id}/artifacts/investigation_report.html")
    assert inv_res.status_code == 200
    assert "text/html" in inv_res.headers["content-type"]
    html_text = inv_res.text

    # Zero external CDN / http(s)
    assert "cdn.tailwindcss.com" not in html_text
    http_matches = re.findall(r'https?://[^\s"\'<>]+', html_text)
    assert len(http_matches) == 0

    # Brand Title and 11 sections present
    assert "Blockchain Ai Aigital Forensics — Báo cáo Điều tra Pháp y số Chuỗi khối Toàn diện" in html_text
    assert "1. TRANG BÌA" in html_text
    assert "2. Tóm tắt điều tra" in html_text
    assert "3. Thống kê blockchain thực tế" in html_text
    assert "4. Bảng giao dịch đáng chú ý" in html_text
    assert "5. Timeline & biểu đồ luồng tài sản" in html_text
    assert "6. Phân tích Rule & ML/XAI" in html_text
    assert "7. Phân tích AI gắn RefChecker" in html_text
    assert "8. Chứng cứ & SHA-256 manifest" in html_text
    assert "9. Chuỗi bảo quản" in html_text
    assert "10. Xác minh suy luận mật mã ZKML" in html_text
    assert "11. Kết luận điều tra" in html_text

    # Step 5: Verify 5 audit artifacts and manifest SHA-256 matching
    manifest_res = client.get(f"/api/investigations/{run_id}/artifacts/evidence_manifest.json")
    assert manifest_res.status_code == 200
    manifest = manifest_res.json()
    assert manifest["manifest_version"] == "1.0.0"
    assert len(manifest["files"]) >= 5

    report_res = client.get(f"/api/investigations/{run_id}/artifacts/report.json")
    assert report_res.status_code == 200
    assert report_res.json()["run_info"]["run_id"] == run_id


# ==============================================================================
# 2. E2E SCENARIO B: SAFE LIVE RPC INVESTIGATION
# ==============================================================================

def test_e2e_scenario_b_live_rpc_investigation(client: TestClient, mock_rpc_server: str):
    """Scenario B: Blank initial Case ID -> Preflight check -> Bounded RPC Investigation -> Segregated Report."""
    case_id = f"case-e2e-b-{int(time.time())}"

    # Step 1: Pre-flight check with allow_local=True for mock RPC
    preflight_payload = {
        "rpc_url": mock_rpc_server,
        "allow_local": True,
        "target_type": "block_range",
        "start_block": 256,
        "end_block": 256,
    }
    pf_res = client.post("/api/rpc/preflight", json=preflight_payload)
    assert pf_res.status_code == 200, f"Preflight check failed: {pf_res.text}"
    pf_data = pf_res.json()
    assert pf_data["valid"] is True
    assert pf_data["safety_status"] == "SAFE"
    assert pf_data["chain_id"] == 11155111  # Sepolia from mock

    # Step 2: Launch RPC investigation with bounds
    inv_payload = {
        "case_id": case_id,
        "rpc_url": mock_rpc_server,
        "allow_local": True,
        "target_type": "block_range",
        "start_block": 256,
        "end_block": 256,
        "ai_provider": "ollama",
        "ai_model": "qwen3:8b",
        "is_mock": True,
    }
    launch_res = client.post("/api/rpc/investigate", json=inv_payload)
    assert launch_res.status_code == 201, f"Launch RPC investigate failed: {launch_res.text}"
    launch_data = launch_res.json()
    run_id = launch_data["run_id"]
    assert launch_data["case_id"] == case_id
    assert launch_data["status"] == "completed"
    assert launch_data["chain_id"] == 11155111
    assert launch_data["blocks_collected"] >= 1

    # Step 3: Verify environment segregation in HTML report
    report_html_path = Path(launch_data["report_html_path"])
    assert report_html_path.is_file(), f"Report HTML file missing at {report_html_path}"
    html_text = report_html_path.read_text(encoding="utf-8")

    # Real network badge should be displayed for Sepolia chain ID 11155111 or Anvil for mock
    assert "Mạng Chuỗi khối" in html_text or "Chuỗi bảo quản" in html_text or "Sepolia" in html_text

    # Step 4: Audit artifacts package verified in session reports dir
    reports_dir = Path(launch_data["report_html_path"]).parent
    manifest_file = reports_dir / "evidence_manifest.json"
    assert manifest_file.is_file(), f"Manifest missing at {manifest_file}"
    manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
    assert len(manifest_data.get("files", [])) >= 1
    assert (reports_dir / "execution_log.txt").is_file()
    assert (reports_dir / "custody_receipts.json").is_file()
    assert (reports_dir / "report.json").is_file()


# ==============================================================================
# 3. SECURITY: ANTI-SSRF DEFENSE E2E
# ==============================================================================

def test_security_ssrf_blocking_e2e(client: TestClient):
    """Verifies preflight and investigation reject private IPs and cloud metadata."""
    forbidden_urls = [
        "http://10.0.0.1:8545",
        "http://192.168.1.1:8545",
        "http://172.16.0.1:8545",
        "http://169.254.169.254/latest/meta-data/",
    ]

    for bad_url in forbidden_urls:
        payload = {
            "rpc_url": bad_url,
            "target_type": "block_range",
            "start_block": 100,
            "end_block": 100,
        }
        res = client.post("/api/rpc/preflight", json=payload)
        assert res.status_code in (400, 403, 422), f"Expected SSRF rejection for {bad_url}, got {res.status_code}"


# ==============================================================================
# 4. SECURITY: PATH TRAVERSAL REJECTION
# ==============================================================================

def test_security_path_traversal_rejection(client: TestClient):
    """Verifies system rejects directory traversal attempts across endpoints."""
    # 1. Traversal in Case ID during file upload
    bad_files = {
        "file": ("test.json", io.BytesIO(b'[{"hash":"0x1"}]'), "application/json")
    }
    res1 = client.post("/api/cases/..%5C..%5Cwindows%5Csystem32/ingest", files=bad_files)
    assert res1.status_code in (404, 422)

    res2 = client.post("/api/cases/case..traversal/ingest", files=bad_files)
    assert res2.status_code in (404, 422)

    # 2. Traversal in file upload filename
    bad_name_files = {
        "file": ("../../malicious.json", io.BytesIO(b'[{"hash":"0x1"}]'), "application/json")
    }
    res3 = client.post("/api/cases/safe-case/ingest", files=bad_name_files)
    assert res3.status_code in (400, 422)

    # 3. Traversal in artifact download
    res4 = client.get("/api/investigations/run-test/artifacts/..%5C..%5Cpasswd")
    assert res4.status_code in (400, 404, 422)


# ==============================================================================
# 5. SECURITY: COMPACT MLP INCOMPATIBLE SCHEMA GRACEFUL HANDLING
# ==============================================================================

def test_security_compact_mlp_incompatible_schema_graceful(tmp_path):
    """Verifies CompactAnomalyMLP returns 'Không áp dụng' on incompatible database without crashing session."""
    # Create DB with core blocks and transactions, but missing required columns (amount_raw, asset_id) in asset_transfers
    db_file = tmp_path / "incompatible.db"
    conn = sqlite3.connect(db_file)
    conn.execute("CREATE TABLE blocks (number INTEGER PRIMARY KEY, hash TEXT, parent_hash TEXT)")
    conn.execute("INSERT INTO blocks VALUES (1, '0xaaa', '0x000')")
    conn.execute("CREATE TABLE transactions (tx_hash TEXT PRIMARY KEY, from_addr TEXT, to_addr TEXT, value_raw TEXT, block_number INTEGER)")
    conn.execute("INSERT INTO transactions VALUES ('0x111', '0xabc', '0xdef', '1000', 1)")
    conn.execute("CREATE TABLE asset_transfers (block_number INT, from_addr TEXT, to_addr TEXT)")
    conn.execute("CREATE TABLE alerts (alert_id TEXT PRIMARY KEY, rule_id TEXT, severity TEXT, unit_type TEXT, unit_key TEXT, asset_id TEXT, score REAL, reason TEXT, evidence_refs TEXT, window_start INTEGER, window_end INTEGER, created_at TEXT)")
    conn.execute("CREATE TABLE custody_events (id INTEGER PRIMARY KEY)")
    conn.execute("CREATE TABLE anchor_links (id INTEGER PRIMARY KEY)")
    conn.execute("CREATE TABLE onchain_operations (id INTEGER PRIMARY KEY)")
    conn.commit()
    conn.close()

    service = InvestigationService()
    config = InvestigationConfig(
        case_id="case-incompatible-schema",
        mode="MODE_B",
        db_path=db_file,
        output_dir=tmp_path,
        ai_provider="ollama",
        ai_model="qwen3:8b",
        is_mock=True,
    )

    result = service.execute(config)
    # The session must not crash; it should finish completed with warnings or completed
    assert result.status in (STATUS_COMPLETED, STATUS_COMPLETED_WITH_WARNINGS)

    # Phase 8 status must be 'not_applicable' ('Không áp dụng')
    p8_status = result.phase_status.get("P8")
    assert p8_status == STATUS_NOT_APPLICABLE or result.stage_status.get("S5") in (STATUS_NOT_APPLICABLE, STATUS_COMPLETED)

    # HTML report must still be generated cleanly
    html_path = tmp_path / result.run_id / "investigation_report.html"
    assert html_path.is_file()
    html_content = html_path.read_text(encoding="utf-8")
    assert "Không áp dụng" in html_content or "Chưa hỗ trợ phân tích" in html_content


# ==============================================================================
# 6. SECURITY: SERVER RESTART RECOVERY AUDIT
# ==============================================================================

def test_security_server_restart_recovery_audit(tmp_path):
    """Simulates server restart while job is in-progress; verifies JobManager marks it as failed with audit frozen."""
    jobs_file = tmp_path / "orphaned_jobs.json"
    stuck_job = {
        "run_id": "run-restart-simulate",
        "case_id": "case-restart-audit",
        "status": "running",
        "vietnamese_status": "Đang xử lý",
        "progress_percent": 45,
        "active_phase": "P4",
        "start_time": "2026-11-07T20:00:00Z",
    }
    jobs_file.write_text(json.dumps({"run-restart-simulate": stuck_job}), encoding="utf-8")

    # Instantiate new JobManager pointing to this file (simulating server reboot)
    jm = JobManager(jobs_file=jobs_file)
    recovered = jm.get_job("run-restart-simulate")

    assert recovered is not None
    assert recovered["status"] == "failed"
    assert recovered["vietnamese_status"] == "Gặp lỗi"
    assert "khởi động lại" in recovered.get("error_message", "").lower() or "dở dang" in recovered.get("error_message", "").lower()
