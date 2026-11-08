"""Adversarial Challenge Test Suite for Milestone 2 (tests/test_adversarial_m2.py).

Adversarially stresses the Evidence File Ingestion Pipeline & Adapters (R3):
1. Fuzzing & Malformed Inputs (corrupted JSON, binary trash, corrupted CSV, empty files, oversized files)
2. Incompatible SQLite Schema Rejection (table cats(name, age) -> strict HTTP 422, zero fake success)
3. Path Traversal & Injection Rejection (traversal in filename, traversal in case_id)
4. Multi-File Ingestion to Same Case (unique SHA-256, timestamps, evidence IDs, no overwriting)
5. Multi-Case Isolation (zero cross-contamination between Case A and Case B)
6. 4 Canonical Databases Bitwise Invariance (zero byte mutation)
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
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
def verify_canonical_dbs_untouched():
    """Verifies that all 4 canonical databases are bitwise untouched before and after every test."""
    dbs = {
        "real_p4.db": get_real_p4_db(),
        "forensics.db": get_forensics_db(),
        "benchmark_p6.db": get_benchmark_db(),
        "endpoint_evidence.db": get_endpoint_evidence_db(),
    }
    for name, path in dbs.items():
        assert path.is_file(), f"Canonical database missing: {path}"
        current = compute_sha256(path)
        assert current == CANONICAL_HASHES[name], f"Pre-test mutation in {name}: {current}"

    yield

    for name, path in dbs.items():
        current = compute_sha256(path)
        assert current == CANONICAL_HASHES[name], f"Post-test mutation in {name}: {current}"


# ==============================================================================
# 1. Adversarial Fuzzing: Malformed JSON, Binary Trash, & Corrupted Payloads
# ==============================================================================

@pytest.mark.parametrize(
    "corrupted_payload,expected_status",
    [
        (b'{"transactions": [{"tx_hash": "0x123", "from": ', 400),       # Truncated JSON
        (b'{{{{[[[[}}}]', 400),                                             # Corrupted syntax
        (os.urandom(2048), 400),                                            # Pure binary garbage
        (b'{"owner": "attacker", "status": "malicious"}', 422),             # Valid JSON, missing tx fields
        (b'[{"random_field": "val1"}, {"random_field": "val2"}]', 422),   # Valid JSON array, missing tx fields
        (b'"just a string root"', 422),                                     # JSON string primitive
        (b'123456789', 422),                                                # JSON number primitive
        (b'true', 422),                                                     # JSON boolean primitive
        (b'[]', 422),                                                       # Empty JSON array
        (b'{"transactions": []}', 422),                                     # JSON container with 0 transactions
    ],
)
def test_fuzz_malformed_json_endpoint(client: TestClient, corrupted_payload: bytes, expected_status: int):
    """Adversarially sends corrupted/incompatible JSON payloads and asserts strict rejection (400/422)."""
    case_id = "CASE-FUZZ-JSON-01"
    files = {"file": ("fuzz_test.json", io.BytesIO(corrupted_payload), "application/json")}
    res = client.post(f"/api/cases/{case_id}/ingest", files=files)
    assert res.status_code == expected_status, f"Expected {expected_status}, got {res.status_code}: {res.text}"
    # Ensure no success was returned
    assert res.status_code not in (200, 201)


@pytest.mark.parametrize(
    "corrupted_csv,expected_status",
    [
        (b'animal,sound,age\ncat,meow,3\ndog,woof,5\n', 422),              # Non-transaction arbitrary columns
        (b'tx_hash,from_address,to_address,value\n', 422),                 # Valid headers but 0 data rows
        (b'   \n\r\t   \n', 422),                                          # Whitespace-only CSV
        (os.urandom(1024), 422),                                           # Binary trash disguised as CSV
    ],
)
def test_fuzz_malformed_csv_endpoint(client: TestClient, corrupted_csv: bytes, expected_status: int):
    """Adversarially sends corrupted or non-forensic CSV files and asserts rejection."""
    case_id = "CASE-FUZZ-CSV-01"
    files = {"file": ("fuzz_test.csv", io.BytesIO(corrupted_csv), "text/csv")}
    res = client.post(f"/api/cases/{case_id}/ingest", files=files)
    assert res.status_code == expected_status, f"Expected {expected_status}, got {res.status_code}: {res.text}"
    assert res.status_code not in (200, 201)


def test_fuzz_empty_files_rejected(client: TestClient):
    """Asserts that completely empty 0-byte files are strictly rejected with 400 Bad Request."""
    case_id = "CASE-FUZZ-EMPTY-01"
    for fname in ("empty.json", "empty.csv", "empty.db"):
        files = {"file": (fname, io.BytesIO(b""), "application/octet-stream")}
        res = client.post(f"/api/cases/{case_id}/ingest", files=files)
        assert res.status_code == 400, f"Expected 400 for empty file {fname}, got {res.status_code}"
        assert "r\u1ed1ng" in res.text.lower() or "empty" in res.text.lower() or "0 bytes" in res.text.lower()


def test_fuzz_oversized_file_rejected():
    """Asserts that files exceeding MAX_FILE_BYTES (128 MB) are rejected with IngestionError."""
    pipeline = EvidenceIngestionPipeline()
    oversized_bytes = b"X" * (128 * 1024 * 1024 + 1024)
    with pytest.raises(IngestionError) as exc_info:
        pipeline.ingest_bytes(
            case_id="CASE-OVERSIZED-01",
            file_bytes=oversized_bytes,
            original_filename="huge_evidence.json",
        )
    assert "v\u01b0\u1ee3t qu\u00e1 gi\u1edbi h\u1ea1n cho ph\u00e9p" in str(exc_info.value)


# ==============================================================================
# 2. SQLite Database Incompatible Schema Rejection & Zero Fake Success
# ==============================================================================

def test_sqlite_arbitrary_schema_cats_rejected(client: TestClient):
    """Verifies that an SQLite DB with an arbitrary schema (e.g. table cats(name, age))

    is strictly rejected with SchemaCompatibilityError (HTTP 422) and NEVER fakes success.
    """
    case_id = "CASE-SQLITE-CATS-01"
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    try:
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE cats (id INTEGER PRIMARY KEY, name TEXT, age INTEGER, favorite_food TEXT)")
        conn.execute("INSERT INTO cats (name, age, favorite_food) VALUES ('Whiskers', 3, 'Tuna')")
        conn.execute("INSERT INTO cats (name, age, favorite_food) VALUES ('Mittens', 5, 'Salmon')")
        conn.commit()
        conn.close()

        with open(db_path, "rb") as f:
            db_bytes = f.read()

        files = {"file": ("cats_evidence.db", io.BytesIO(db_bytes), "application/x-sqlite3")}
        res = client.post(f"/api/cases/{case_id}/ingest", files=files)

        # Must reject with 422 Unprocessable Content
        assert res.status_code == 422, f"Expected 422 for arbitrary SQLite schema, got {res.status_code}: {res.text}"
        data = res.json()
        assert "cats" in data["detail"].lower() or "t\u01b0\u01a1ng th\u00edch" in data["detail"].lower()
        # Verify no evidence was saved to vault
        evidence_list_res = client.get(f"/api/cases/{case_id}/evidence")
        assert evidence_list_res.status_code == 200
        assert evidence_list_res.json() == []

    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_sqlite_zero_tables_database_rejected(client: TestClient):
    """Verifies that a valid SQLite database with zero tables is rejected with 422 SchemaCompatibilityError."""
    case_id = "CASE-SQLITE-EMPTY-01"
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    try:
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE temp_tbl (id INT)")
        conn.execute("DROP TABLE temp_tbl")
        conn.commit()
        conn.close()

        with open(db_path, "rb") as f:
            db_bytes = f.read()

        files = {"file": ("empty_database.sqlite", io.BytesIO(db_bytes), "application/x-sqlite3")}
        res = client.post(f"/api/cases/{case_id}/ingest", files=files)
        assert res.status_code == 422
        assert "r\u1ed7ng" in res.text.lower()
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_sqlite_transactions_table_arbitrary_columns_rejected(client: TestClient):
    """Verifies that SQLite with 'transactions' table but incompatible columns (missing hash/from) is rejected with 422."""
    case_id = "CASE-SQLITE-BADCOLS-01"
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    try:
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE transactions (id INTEGER PRIMARY KEY, note TEXT, score REAL)")
        conn.execute("INSERT INTO transactions (note, score) VALUES ('test', 12.5)")
        conn.commit()
        conn.close()

        with open(db_path, "rb") as f:
            db_bytes = f.read()

        files = {"file": ("bad_cols.db", io.BytesIO(db_bytes), "application/x-sqlite3")}
        res = client.post(f"/api/cases/{case_id}/ingest", files=files)
        assert res.status_code == 422
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_sqlite_corrupted_header_rejected(client: TestClient):
    """Verifies that an SQLite file with valid magic header but corrupted pages raises 400 CorruptedFileError."""
    case_id = "CASE-SQLITE-CORRUPT-01"
    corrupted_db_bytes = b"SQLite format 3\x00" + os.urandom(512)
    files = {"file": ("corrupted.db", io.BytesIO(corrupted_db_bytes), "application/x-sqlite3")}
    res = client.post(f"/api/cases/{case_id}/ingest", files=files)
    assert res.status_code in (400, 422)


# ==============================================================================
# 3. Path Traversal & Injection Vectors
# ==============================================================================

@pytest.mark.parametrize(
    "malicious_filename",
    [
        "../../etc/passwd.json",
        "..\\windows\\system32.json",
        "....//....//boot.json",
        "sub/folder/file.json",
        "sub\\folder\\file.json",
    ],
)
def test_path_traversal_in_filename_rejected(client: TestClient, malicious_filename: str):
    """Verifies that path traversal and dangerous separators in filename are strictly rejected with 422."""
    case_id = "CASE-SECURITY-PATH-01"
    dummy_payload = json.dumps([
        {"tx_hash": "0xabc123", "from": "0x1111", "to": "0x2222", "value": "1000"}
    ]).encode("utf-8")
    files = {"file": (malicious_filename, io.BytesIO(dummy_payload), "application/json")}
    res = client.post(f"/api/cases/{case_id}/ingest", files=files)
    assert res.status_code == 422, f"Expected 422 for malicious filename '{malicious_filename}', got {res.status_code}"
    assert "nguy hi\u1ec3m" in res.text.lower() or "kh\u00f4ng h\u1ee3p l\u1ec7" in res.text.lower()


@pytest.mark.parametrize(
    "malicious_case_id,expected_status",
    [
        ("..%5C..%5Cwindows%5Csystem32", 422),     # Backslash traversal encoded
        ("case..traversal", 422),                 # Relative traversal with dots
        ("case*with*special!", 422),              # Forbidden wildcard and punctuation
        ("case with spaces", 422),                # Space in case ID
        ("a" * 65, 422),                          # Exceeds max length (64 chars)
        ("../../escape_case", 404),               # URL path escape resolved by router
        ("case/subcase", 404),                    # Extra path segment rejected by router
    ],
)
def test_path_traversal_in_case_id_rejected(client: TestClient, malicious_case_id: str, expected_status: int):
    """Verifies that malicious or invalid case_id formats are strictly rejected (422 or 404)."""
    dummy_payload = json.dumps([
        {"tx_hash": "0xabc123", "from": "0x1111", "to": "0x2222", "value": "1000"}
    ]).encode("utf-8")
    files = {"file": ("valid_evidence.json", io.BytesIO(dummy_payload), "application/json")}
    res = client.post(f"/api/cases/{malicious_case_id}/ingest", files=files)
    assert res.status_code == expected_status, f"Expected {expected_status} for case_id '{malicious_case_id}', got {res.status_code}"


def test_pipeline_unit_level_traversal_rejection():
    """Unit-level check verifying that EvidenceIngestionPipeline raises SecurityError on traversal attempts."""
    pipeline = EvidenceIngestionPipeline()
    for bad_id in ("../../escape", "..\\escape", "case/sub", "case\\sub", "", "bad!id", "x" * 65):
        with pytest.raises(SecurityError):
            pipeline.validate_case_id(bad_id)


# ==============================================================================
# 4. Multi-File Ingestion to Same Case
# ==============================================================================

def test_multi_file_independence_same_case(client: TestClient):
    """Verifies that ingesting multiple files into the same case grants each file:

    - Independent SHA-256
    - Independent timestamp
    - Independent Evidence ID
    - Zero overwriting of existing vault files or index entries
    """
    case_id = f"CASE-MULTI-ADV-{int(time.time())}"

    # File 1: JSON transactions
    file1_data = json.dumps([
        {"tx_hash": "0x1111111111111111111111111111111111111111111111111111111111111111", "from": "0xaaaa", "to": "0xbbbb", "value": "100"},
        {"tx_hash": "0x2222222222222222222222222222222222222222222222222222222222222222", "from": "0xcccc", "to": "0xdddd", "value": "200"},
    ]).encode("utf-8")

    # File 2: CSV transactions
    file2_data = (
        "tx_hash,from_address,to_address,value,block_number\n"
        "0x3333333333333333333333333333333333333333333333333333333333333333,0xeeee,0xffff,500,1001\n"
        "0x4444444444444444444444444444444444444444444444444444444444444444,0x1212,0x3434,600,1002\n"
        "0x5555555555555555555555555555555555555555555555555555555555555555,0x5656,0x7878,700,1003\n"
    ).encode("utf-8")

    # File 3: Host log events
    file3_data = json.dumps([
        {"event_id": 1, "process_name": "cmd.exe", "command_line": "whoami", "user": "SYSTEM"},
        {"event_id": 3, "process_name": "curl.exe", "command_line": "curl http://exfil.com", "user": "ADMIN"},
    ]).encode("utf-8")

    # Ingest File 1
    res1 = client.post(f"/api/cases/{case_id}/ingest", files={"file": ("batch_tx.json", io.BytesIO(file1_data), "application/json")})
    assert res1.status_code == 201
    d1 = res1.json()

    # Small delay to ensure timestamp separation
    time.sleep(1.05)

    # Ingest File 2
    res2 = client.post(f"/api/cases/{case_id}/ingest", files={"file": ("batch_tx.csv", io.BytesIO(file2_data), "text/csv")})
    assert res2.status_code == 201
    d2 = res2.json()

    time.sleep(1.05)

    # Ingest File 3
    res3 = client.post(f"/api/cases/{case_id}/ingest", files={"file": ("host_events.json", io.BytesIO(file3_data), "application/json")})
    assert res3.status_code == 201
    d3 = res3.json()

    # Verify uniqueness of evidence IDs and SHA-256
    evidence_ids = {d1["evidence_id"], d2["evidence_id"], d3["evidence_id"]}
    sha_hashes = {d1["sha256"], d2["sha256"], d3["sha256"]}
    assert len(evidence_ids) == 3, f"Evidence IDs collided: {evidence_ids}"
    assert len(sha_hashes) == 3, f"SHA-256 hashes collided: {sha_hashes}"

    # Verify all 3 files are returned in index query
    index_res = client.get(f"/api/cases/{case_id}/evidence")
    assert index_res.status_code == 200
    index_list = index_res.json()
    assert len(index_list) == 3

    indexed_ev_ids = [item["evidence_id"] for item in index_list]
    assert d1["evidence_id"] in indexed_ev_ids
    assert d2["evidence_id"] in indexed_ev_ids
    assert d3["evidence_id"] in indexed_ev_ids

    # Verify detail retrieval for each file without cross-contamination
    for d, expected_count in ((d1, 2), (d2, 3), (d3, 2)):
        ev_detail_res = client.get(f"/api/cases/{case_id}/evidence/{d['evidence_id']}")
        assert ev_detail_res.status_code == 200
        detail_data = ev_detail_res.json()
        assert detail_data["metadata"]["evidence_id"] == d["evidence_id"]
        assert detail_data["metadata"]["sha256"] == d["sha256"]
        assert detail_data["metadata"]["records_count"] == expected_count


# ==============================================================================
# 5. Multi-Case Isolation
# ==============================================================================

def test_case_isolation_zero_leakage(client: TestClient):
    """Verifies that evidence uploaded to Case A NEVER appears in Case B,

    and cross-case detail requests return 404 Not Found.
    """
    case_a = f"CASE-ISOLATION-A-{int(time.time())}"
    case_b = f"CASE-ISOLATION-B-{int(time.time())}"

    payload_a = json.dumps([
        {"tx_hash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "from": "0x1111", "to": "0x2222", "value": "100"}
    ]).encode("utf-8")

    payload_b = json.dumps([
        {"tx_hash": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "from": "0x3333", "to": "0x4444", "value": "200"}
    ]).encode("utf-8")

    # Ingest into Case A
    res_a = client.post(f"/api/cases/{case_a}/ingest", files={"file": ("evidence_a.json", io.BytesIO(payload_a), "application/json")})
    assert res_a.status_code == 201
    ev_a = res_a.json()["evidence_id"]

    # Ingest into Case B
    res_b = client.post(f"/api/cases/{case_b}/ingest", files={"file": ("evidence_b.json", io.BytesIO(payload_b), "application/json")})
    assert res_b.status_code == 201
    ev_b = res_b.json()["evidence_id"]

    # Check Case A list: MUST contain ev_a, MUST NOT contain ev_b
    list_a = client.get(f"/api/cases/{case_a}/evidence").json()
    assert len(list_a) == 1
    assert list_a[0]["evidence_id"] == ev_a
    assert ev_b not in [x["evidence_id"] for x in list_a]

    # Check Case B list: MUST contain ev_b, MUST NOT contain ev_a
    list_b = client.get(f"/api/cases/{case_b}/evidence").json()
    assert len(list_b) == 1
    assert list_b[0]["evidence_id"] == ev_b
    assert ev_a not in [x["evidence_id"] for x in list_b]

    # Cross-lookup: Case A querying ev_b MUST return 404
    cross_res_1 = client.get(f"/api/cases/{case_a}/evidence/{ev_b}")
    assert cross_res_1.status_code == 404, f"Case A leaked Case B evidence: {cross_res_1.text}"

    # Cross-lookup: Case B querying ev_a MUST return 404
    cross_res_2 = client.get(f"/api/cases/{case_b}/evidence/{ev_a}")
    assert cross_res_2.status_code == 404, f"Case B leaked Case A evidence: {cross_res_2.text}"
