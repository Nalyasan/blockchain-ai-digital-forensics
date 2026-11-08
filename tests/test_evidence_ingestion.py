"""Comprehensive Test Suite for Evidence File Ingestion Pipeline & Adapters (tests/test_evidence_ingestion.py).

Covers:
- Canonical Database Bitwise SHA-256 Invariance (100% untouched)
- Blockchain Transactions JSON / JSONL Adapter
- Transaction CSV Adapter & Header Validation
- SQLite Database Adapter (strictly mode=ro&immutable=1)
- SQLite Incompatible Schema Rejection (never faking success)
- Authorized Host Logs / Sysmon Adapter & Anomaly Detection
- Corrupted and Malformed File Rejection
- 8-Step Pipeline End-to-End Execution
- Multi-File Ingestion Independence (no file overwrites, unique hashes)
- Security: Path Traversal Rejection on Case ID and Filename
- REST API: POST /api/cases/{case_id}/ingest (Multipart Form Data)
- REST API: GET /api/cases/{case_id}/evidence & GET /api/cases/{case_id}/evidence/{evidence_id}
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import time
from typing import Any, Dict, List
import pytest
from fastapi.testclient import TestClient

from dashboard.app import app
from forensics.ingestion import (
    AuthorizedHostLogsAdapter,
    BlockchainTxJsonAdapter,
    CorruptedFileError,
    EvidenceIngestionPipeline,
    FormatError,
    IngestionError,
    SchemaCompatibilityError,
    SecurityError,
    SqliteEvidenceAdapter,
    TransactionCsvAdapter,
    get_adapter_for_format,
)
from forensics.paths import (
    get_benchmark_db,
    get_data_dir,
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
def verify_db_invariance():
    """Verifies all 4 canonical databases remain 100% bitwise invariant before and after each test."""
    dbs = {
        "real_p4.db": get_real_p4_db(),
        "forensics.db": get_forensics_db(),
        "benchmark_p6.db": get_benchmark_db(),
        "endpoint_evidence.db": get_endpoint_evidence_db(),
    }
    for name, path in dbs.items():
        assert path.is_file(), f"Canonical database missing: {path}"
        cur_hash = compute_sha256(path)
        assert cur_hash == CANONICAL_HASHES[name], f"Pre-test mutation in {name}: {cur_hash} != {CANONICAL_HASHES[name]}"

    yield

    for name, path in dbs.items():
        cur_hash = compute_sha256(path)
        assert cur_hash == CANONICAL_HASHES[name], f"Post-test mutation in {name}: {cur_hash} != {CANONICAL_HASHES[name]}"


# ==============================================================================
# 1. Blockchain Transactions JSON / JSONL Adapter Tests
# ==============================================================================

def test_json_adapter_valid_array():
    """Verifies JSON adapter successfully parses an array of transactions."""
    adapter = BlockchainTxJsonAdapter()
    sample_txs = [
        {
            "hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "from": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "to": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "value": "1000000000000000000",
            "blockNumber": 16817990,
            "timestamp": 1678700000,
            "token": "ETH",
        },
        {
            "tx_hash": "0x2222222222222222222222222222222222222222222222222222222222222222",
            "from_address": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "to_address": None,  # Contract creation
            "value": 0,
            "block_number": 16817995,
            "timestamp": 1678700050,
            "token_symbol": "ETH",
        },
    ]
    raw_bytes = json.dumps(sample_txs).encode("utf-8")
    assert adapter.can_handle("transactions.json", raw_bytes) is True

    records = adapter.parse_and_normalize(raw_bytes)
    assert len(records) == 2

    r0 = records[0]
    assert r0["tx_hash"] == "0x1111111111111111111111111111111111111111111111111111111111111111"
    assert r0["from_address"] == "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    assert r0["to_address"] == "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    assert r0["value"] == "1000000000000000000"
    assert r0["token_symbol"] == "ETH"
    assert r0["block_number"] == 16817990

    r1 = records[1]
    assert r1["to_address"] is None


def test_json_adapter_wrapper_and_jsonl():
    """Verifies JSON adapter handles wrapper object and JSONL line-delimited files."""
    adapter = BlockchainTxJsonAdapter()

    # Wrapper object
    wrapper = {
        "transactions": [
            {
                "hash": "0x3333333333333333333333333333333333333333333333333333333333333333",
                "from": "0xcccccccccccccccccccccccccccccccccccccccc",
                "to": "0xdddddddddddddddddddddddddddddddddddddddd",
                "value": "500000",
            }
        ]
    }
    records = adapter.parse_and_normalize(json.dumps(wrapper).encode("utf-8"))
    assert len(records) == 1
    assert records[0]["tx_hash"] == "0x3333333333333333333333333333333333333333333333333333333333333333"

    # JSONL
    line1 = json.dumps({"hash": "0x4444444444444444444444444444444444444444444444444444444444444444", "from": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "to": "0xffffffffffffffffffffffffffffffffffffffff", "value": "100"})
    line2 = json.dumps({"hash": "0x5555555555555555555555555555555555555555555555555555555555555555", "from": "0xffffffffffffffffffffffffffffffffffffffff", "to": "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "value": "200"})
    jsonl_bytes = f"{line1}\n{line2}\n".encode("utf-8")
    records_jsonl = adapter.parse_and_normalize(jsonl_bytes)
    assert len(records_jsonl) == 2


def test_json_adapter_corrupted_and_empty():
    """Verifies JSON adapter raises CorruptedFileError on bad syntax and SchemaCompatibilityError on empty."""
    adapter = BlockchainTxJsonAdapter()

    # Malformed JSON
    with pytest.raises(CorruptedFileError):
        adapter.parse_and_normalize(b"[{malformed json, not closed")

    # Empty content
    with pytest.raises(SchemaCompatibilityError):
        adapter.parse_and_normalize(b"")

    # Object without transaction schema
    with pytest.raises(SchemaCompatibilityError):
        adapter.parse_and_normalize(b'{"user": "alice", "settings": {"dark_mode": true}}')


# ==============================================================================
# 2. Transaction CSV Adapter Tests
# ==============================================================================

def test_csv_adapter_valid_headers():
    """Verifies CSV adapter correctly parses standard CSV files."""
    adapter = TransactionCsvAdapter()
    csv_text = (
        "tx_hash,from_address,to_address,value,token_symbol,block_number,timestamp\n"
        "0xaaaa1111222233334444555566667777888899990000aaaabbbbccccddddeeee01,0x1111111111111111111111111111111111111111,0x2222222222222222222222222222222222222222,1500000,USDC,17800001,1680000000\n"
        "0xaaaa1111222233334444555566667777888899990000aaaabbbbccccddddeeee02,0x2222222222222222222222222222222222222222,0x3333333333333333333333333333333333333333,3000000,DAI,17800002,1680000012\n"
    )
    raw_bytes = csv_text.encode("utf-8")
    assert adapter.can_handle("transfers.csv", raw_bytes) is True

    records = adapter.parse_and_normalize(raw_bytes)
    assert len(records) == 2
    assert records[0]["token_symbol"] == "USDC"
    assert records[0]["block_number"] == 17800001
    assert records[1]["token_symbol"] == "DAI"


def test_csv_adapter_alternative_headers():
    """Verifies CSV adapter detects alternative headers (hash, from, to, amount)."""
    adapter = TransactionCsvAdapter()
    csv_text = (
        "hash,from,to,amount\n"
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef,0xabcabcabcabcabcabcabcabcabcabcabcabcabca,0xdefdefdefdefdefdefdefdefdefdefdefdefdefd,1000\n"
    )
    records = adapter.parse_and_normalize(csv_text.encode("utf-8"))
    assert len(records) == 1
    assert records[0]["tx_hash"] == "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    assert records[0]["value"] == "1000"


def test_csv_adapter_missing_required_headers():
    """Verifies CSV adapter rejects CSV without transaction headers."""
    adapter = TransactionCsvAdapter()
    csv_text = "id,name,role,department\n1,Alice,Investigator,Cyber\n2,Bob,Analyst,Forensics\n"
    with pytest.raises(SchemaCompatibilityError) as exc_info:
        adapter.parse_and_normalize(csv_text.encode("utf-8"))
    assert "thiếu các cột giao dịch bắt buộc" in str(exc_info.value)


# ==============================================================================
# 3. SQLite Database Adapter Tests (Read-Only & Invariance)
# ==============================================================================

def test_sqlite_adapter_valid_transactions_table(tmp_path):
    """Verifies SQLite adapter parses a database containing a transactions table."""
    adapter = SqliteEvidenceAdapter()
    db_file = tmp_path / "valid_tx.db"
    conn = sqlite3.connect(db_file)
    conn.execute("""
        CREATE TABLE transactions (
            tx_hash TEXT PRIMARY KEY,
            from_addr TEXT,
            to_addr TEXT,
            value_raw TEXT,
            block_number INTEGER,
            block_timestamp INTEGER
        )
    """)
    conn.execute(
        "INSERT INTO transactions VALUES (?, ?, ?, ?, ?, ?)",
        ("0xabc1", "0x1111111111111111111111111111111111111111", "0x2222222222222222222222222222222222222222", "5000000000000000000", 17000000, 1680000000)
    )
    conn.commit()
    conn.close()

    assert adapter.can_handle("evidence.db", db_file.read_bytes()[:100]) is True
    records = adapter.parse_and_normalize(db_file)
    assert len(records) == 1
    assert records[0]["tx_hash"] == "0xabc1"
    assert records[0]["block_number"] == 17000000


def test_sqlite_adapter_incompatible_schema_rejection(tmp_path):
    """Verifies SQLite adapter reports clear error when database schema is incompatible (no faking)."""
    adapter = SqliteEvidenceAdapter()
    db_file = tmp_path / "incompatible.db"
    conn = sqlite3.connect(db_file)
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'alice', 'alice@example.com')")
    conn.commit()
    conn.close()

    with pytest.raises(SchemaCompatibilityError) as exc_info:
        adapter.parse_and_normalize(db_file)

    assert "không chứa cấu trúc bảng chứng cứ tương thích" in str(exc_info.value)


def test_sqlite_adapter_canonical_real_db_reading():
    """Verifies reading real_p4.db via adapter leaves database 100% untouched."""
    real_db = get_real_p4_db()
    assert real_db.is_file()
    pre_hash = compute_sha256(real_db)

    adapter = SqliteEvidenceAdapter()
    records = adapter.parse_and_normalize(real_db)
    assert len(records) > 0

    post_hash = compute_sha256(real_db)
    assert pre_hash == post_hash, "Canonical real_p4.db mutated during adapter read!"


# ==============================================================================
# 4. Authorized Host Logs Adapter Tests
# ==============================================================================

def test_host_logs_adapter_json_and_anomaly_detection():
    """Verifies host logs adapter parses events and identifies suspicious commands."""
    adapter = AuthorizedHostLogsAdapter()
    events = [
        {
            "timestamp_utc": "2026-11-08T01:00:00Z",
            "event_id": 1,
            "process_name": "cmd.exe",
            "command_line": "powershell -enc JABhID0A...",
            "user": "DOMAIN\\Administrator",
            "host_id": "WS-FINANCE-01",
        },
        {
            "timestamp_utc": "2026-11-08T01:05:00Z",
            "event_id": 1,
            "process_name": "notepad.exe",
            "command_line": "notepad.exe C:\\notes.txt",
            "user": "DOMAIN\\User01",
            "host_id": "WS-FINANCE-01",
        },
    ]
    raw_bytes = json.dumps(events).encode("utf-8")
    assert adapter.can_handle("sysmon_audit.json", raw_bytes) is True

    records = adapter.parse_and_normalize(raw_bytes)
    assert len(records) == 2
    assert records[0]["event_id"] == 1

    # Run analysis
    from forensics.ingestion.adapters import analyze_records
    analysis = analyze_records(records, "authorized_host_logs")
    assert analysis["statistics"]["total_records"] == 2
    assert len(analysis["anomalies"]) > 0
    assert analysis["anomalies"][0]["type"] == "SUSPICIOUS_ENDPOINT_COMMAND"
    assert analysis["risk_score"] > 0


# ==============================================================================
# 5. 8-Step Pipeline End-to-End Execution Tests
# ==============================================================================

def test_pipeline_8_steps_complete_flow(tmp_path):
    """Verifies that EvidenceIngestionPipeline completes all 8 stages seamlessly."""
    pipe = EvidenceIngestionPipeline(data_dir=tmp_path / "data", output_dir=tmp_path / "reports")

    case_id = "test-case-pipeline-01"
    txs = [
        {
            "hash": "0x99991111222233334444555566667777888899990000aaaabbbbccccddddeeee01",
            "from": "0x1111111111111111111111111111111111111111",
            "to": "0x2222222222222222222222222222222222222222",
            "value": "10000000000000000000000",  # High value
            "blockNumber": 16818000,
        }
    ]
    raw_bytes = json.dumps(txs).encode("utf-8")
    expected_sha = hashlib.sha256(raw_bytes).hexdigest().upper()

    res = pipe.ingest_bytes(
        case_id=case_id,
        file_bytes=raw_bytes,
        original_filename="euler_incident_txs.json",
        source_type="blockchain_tx_json",
        description="Euler Finance attack transaction sample",
    )

    assert res.status == "completed"
    assert res.sha256 == expected_sha
    assert res.records_count == 1
    assert res.evidence_id.startswith(f"ev_{case_id}_")
    assert res.run_id.startswith(f"run_{case_id}_")
    assert len(res.step_logs) == 8

    # Verify 8 stages mentioned in step_logs
    assert any("Giai đoạn 1" in l for l in res.step_logs)
    assert any("Giai đoạn 2" in l for l in res.step_logs)
    assert any("Giai đoạn 3" in l for l in res.step_logs)
    assert any("Giai đoạn 4" in l for l in res.step_logs)
    assert any("Giai đoạn 5" in l for l in res.step_logs)
    assert any("Giai đoạn 6" in l for l in res.step_logs)
    assert any("Giai đoạn 7" in l for l in res.step_logs)
    assert any("Giai đoạn 8" in l for l in res.step_logs)

    # Verify physical file existence in case vault
    assert Path(res.vault_path).is_file()
    assert Path(res.report_path).is_file()
    assert "investigation_report.html" in res.report_path

    # Verify session report artifacts
    run_dir = Path(res.report_path).parent
    assert (run_dir / "report.json").is_file()
    assert (run_dir / "evidence_manifest.json").is_file()
    assert (run_dir / "custody_receipts.json").is_file()
    assert (run_dir / "execution_log.txt").is_file()


def test_pipeline_multi_file_independence(tmp_path):
    """Verifies ingesting multiple files into the same case creates independent entries without overwriting."""
    pipe = EvidenceIngestionPipeline(data_dir=tmp_path / "data", output_dir=tmp_path / "reports")
    case_id = "test-multi-file-case"

    # File 1: JSON
    f1_bytes = json.dumps([{"hash": "0x1111", "from": "0xaaaa", "to": "0xbbbb", "value": "100"}]).encode()
    r1 = pipe.ingest_bytes(case_id, f1_bytes, "batch1.json")

    # File 2: CSV
    f2_bytes = b"tx_hash,from_address,to_address,value\n0x2222,0xbbbb,0xcccc,200\n"
    r2 = pipe.ingest_bytes(case_id, f2_bytes, "batch2.csv")

    # File 3: Same filename as File 1 but different content
    f3_bytes = json.dumps([{"hash": "0x3333", "from": "0xcccc", "to": "0xdddd", "value": "300"}]).encode()
    r3 = pipe.ingest_bytes(case_id, f3_bytes, "batch1.json")

    assert r1.evidence_id != r2.evidence_id != r3.evidence_id
    assert r1.sha256 != r2.sha256 != r3.sha256

    # Verify evidence_index.json has all 3 records preserved
    index_file = pipe.cases_dir / case_id / "evidence" / "evidence_index.json"
    assert index_file.is_file()
    items = json.loads(index_file.read_text(encoding="utf-8"))
    assert len(items) == 3

    assert items[0]["sha256"] == r1.sha256
    assert items[1]["sha256"] == r2.sha256
    assert items[2]["sha256"] == r3.sha256

    # Verify neither vault file was overwritten
    assert Path(r1.vault_path).is_file()
    assert Path(r2.vault_path).is_file()
    assert Path(r3.vault_path).is_file()
    assert r1.vault_path != r3.vault_path


def test_pipeline_path_traversal_rejection(tmp_path):
    """Verifies that path traversal attacks on case_id are strictly rejected with SecurityError."""
    pipe = EvidenceIngestionPipeline(data_dir=tmp_path / "data", output_dir=tmp_path / "reports")

    bad_case_ids = [
        "../../etc/passwd",
        "..\\..\\windows\\system32",
        "case/traversal",
        "case\\traversal",
        "case*special",
        "case\x00null",
    ]
    sample_bytes = json.dumps([{"hash": "0x1", "from": "0x2", "to": "0x3", "value": "1"}]).encode()

    for bad in bad_case_ids:
        with pytest.raises(SecurityError):
            pipe.ingest_bytes(case_id=bad, file_bytes=sample_bytes, original_filename="tx.json")


# ==============================================================================
# 6. REST API Endpoint Tests (/api/cases/{case_id}/ingest)
# ==============================================================================

def test_api_ingest_json_endpoint(client: TestClient):
    """Verifies multipart/form-data ingestion via POST /api/cases/{case_id}/ingest."""
    txs = [
        {
            "hash": "0x9876543210abcdef9876543210abcdef9876543210abcdef9876543210abcdef",
            "from": "0x111122223333444455556666777788889999aaaa",
            "to": "0xbbbbccccddddeeeeffff00001111222233334444",
            "value": "2500000000000000000",
            "token": "ETH",
            "blockNumber": 16818100,
        }
    ]
    file_content = json.dumps(txs).encode("utf-8")
    case_id = f"api-test-{int(time.time())}"

    files = {
        "file": ("api_transactions.json", io.BytesIO(file_content), "application/json")
    }
    data = {
        "source_type": "blockchain_tx_json",
        "description": "API Test Ingestion JSON",
    }

    res = client.post(f"/api/cases/{case_id}/ingest", files=files, data=data)
    assert res.status_code == 201
    resp_data = res.json()

    assert resp_data["status"] == "completed"
    assert resp_data["original_filename"] == "api_transactions.json"
    assert resp_data["records_count"] == 1
    assert resp_data["sha256"] == hashlib.sha256(file_content).hexdigest().upper()
    assert resp_data["run_id"].startswith(f"run_{case_id}_")

    # Verify listing via GET /api/cases/{case_id}/evidence
    list_res = client.get(f"/api/cases/{case_id}/evidence")
    assert list_res.status_code == 200
    ev_list = list_res.json()
    assert len(ev_list) == 1
    assert ev_list[0]["evidence_id"] == resp_data["evidence_id"]

    # Verify detail via GET /api/cases/{case_id}/evidence/{evidence_id}
    detail_res = client.get(f"/api/cases/{case_id}/evidence/{resp_data['evidence_id']}")
    assert detail_res.status_code == 200
    det = detail_res.json()
    assert det["metadata"]["evidence_id"] == resp_data["evidence_id"]
    assert len(det["sample_records"]) == 1


def test_api_ingest_csv_endpoint(client: TestClient):
    """Verifies multipart/form-data ingestion for CSV files."""
    csv_bytes = (
        b"tx_hash,from_address,to_address,value,token_symbol,block_number\n"
        b"0xfeedbeef01,0x1111111111111111111111111111111111111111,0x2222222222222222222222222222222222222222,100,DAI,16818050\n"
    )
    case_id = f"api-csv-{int(time.time())}"
    files = {
        "file": ("api_transfers.csv", io.BytesIO(csv_bytes), "text/csv")
    }
    res = client.post(f"/api/cases/{case_id}/ingest", files=files)
    assert res.status_code == 201
    data = res.json()
    assert data["source_type"] == "blockchain_tx_csv"
    assert data["records_count"] == 1


def test_api_ingest_incompatible_sqlite_raises_422(client: TestClient, tmp_path):
    """Verifies submitting an incompatible SQLite database returns HTTP 422 with clear explanation."""
    db_file = tmp_path / "unrelated_db.sqlite"
    conn = sqlite3.connect(db_file)
    conn.execute("CREATE TABLE products (sku TEXT PRIMARY KEY, price REAL)")
    conn.execute("INSERT INTO products VALUES ('SKU-101', 99.9)")
    conn.commit()
    conn.close()

    case_id = "test-bad-db"
    files = {
        "file": ("unrelated_db.sqlite", io.BytesIO(db_file.read_bytes()), "application/x-sqlite3")
    }
    res = client.post(f"/api/cases/{case_id}/ingest", files=files)
    assert res.status_code == 422
    assert "không chứa cấu trúc bảng chứng cứ tương thích" in res.json()["detail"]


def test_api_ingest_empty_file_raises_400(client: TestClient):
    """Verifies submitting an empty file returns HTTP 400 Bad Request."""
    case_id = "test-empty"
    files = {
        "file": ("empty.json", io.BytesIO(b""), "application/json")
    }
    res = client.post(f"/api/cases/{case_id}/ingest", files=files)
    assert res.status_code == 400
    assert "Tệp tải lên rỗng" in res.json()["detail"]


def test_api_ingest_path_traversal_rejection(client: TestClient):
    """Verifies submitting path traversal or invalid characters in case_id or filename returns HTTP 422."""
    files = {
        "file": ("good.json", io.BytesIO(b'[{"hash": "0x1", "from": "0x2", "to": "0x3", "value": "1"}]'), "application/json")
    }
    # Path traversal with backslashes
    res1 = client.post("/api/cases/..%5C..%5Cwindows%5Csystem32/ingest", files=files)
    assert res1.status_code == 422

    # Relative path traversal with dots
    res2 = client.post("/api/cases/case..traversal/ingest", files=files)
    assert res2.status_code == 422

    # Forbidden characters in case_id
    res3 = client.post("/api/cases/case*with*special!/ingest", files=files)
    assert res3.status_code == 422

    # Traversal in filename
    bad_filename_files = {
        "file": ("../../malicious.json", io.BytesIO(b'[{"hash": "0x1", "from": "0x2", "to": "0x3", "value": "1"}]'), "application/json")
    }
    res4 = client.post("/api/cases/safe-case-id/ingest", files=bad_filename_files)
    assert res4.status_code == 422
