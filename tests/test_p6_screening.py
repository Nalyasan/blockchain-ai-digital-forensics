"""Unit test suite for Gate P6-03 Entity Screening Engine & Cross-Referencing.

Verifies:
1. Strict read-only database isolation and SQLite authorizer defenses on real_p4.db.
2. Accurate on-chain counterparty extraction for Euler Finance and Curve alETH.
3. Entity screening match detection, category attribution, and deterministic IDs.
4. Clean zero-match behavior on unlisted addresses (Open World Assumption).
5. High-volume chunked query execution (>1,000 addresses).
6. SQL injection resistance on adversarial address strings.
7. Append-only persistence into screening_matches, replay idempotency, and conflict detection.
8. Single-address lookup API for P5 AI investigator tools.
9. Physical database isolation assertions.
"""
from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import pytest

from forensics.adapters.base import (
    ThreatIntelBatch,
    ThreatIntelRecord,
    current_iso_utc,
    normalize_eth_address,
)
from forensics.adapters.persistence_benchmark import (
    EvidenceConflictError,
    assert_database_isolation,
    init_benchmark_db,
    insert_intel_batch,
)
from forensics.adapters.screening import (
    DEFAULT_REAL_P4_DB_PATH,
    ScreeningMatch,
    extract_incident_counterparties,
    get_readonly_p4_connection,
    persist_screening_matches,
    run_incident_screening,
    screen_addresses,
    screen_single_address,
)


@pytest.fixture
def temp_bench_db(tmp_path: Path) -> Path:
    """Fixture providing an initialized, isolated benchmark SQLite database."""
    db_file = tmp_path / "test_screening_bench.db"
    conn = init_benchmark_db(db_file)
    conn.close()
    return db_file


@pytest.fixture
def populated_bench_db(temp_bench_db: Path) -> Path:
    """Fixture with pre-populated threat intelligence records."""
    conn = sqlite3.connect(temp_bench_db)
    # Add dummy source
    records = [
        ThreatIntelRecord(
            source_file_path="datasets/test/threats.csv",
            source_file_sha256="aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
            source_commit="55003fd7466148ccd8ce806bba83f923399f3074",
            row_identifier=f"row_{idx}",
            raw_payload_sha256=f"hash_{idx}",
            entity_type="address",
            entity_value=addr,
            threat_category=cat,
            threat_sub_tactic=sub,
            confidence_score=1.0,
            data_source="test_feed",
            raw_metadata_json='{"test": true}',
            ingestion_timestamp=current_iso_utc(),
        )
        for idx, (addr, cat, sub) in enumerate([
            ("0x1111111111111111111111111111111111111111", "PHISHING", "credential_harvest"),
            ("0x2222222222222222222222222222222222222222", "ICE_PHISHING", "approval_abuse"),
            ("0x3333333333333333333333333333333333333333", "MALICIOUS_CONTRACT", "drainer"),
            ("0x4444444444444444444444444444444444444444", "ADDRESS_POISONING", "vanity_spoof"),
        ], start=1)
    ]
    batch = ThreatIntelBatch(
        source_id="test_source_v1",
        source_name="test_feed",
        file_path="datasets/test/threats.csv",
        file_sha256="aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        source_commit="55003fd7466148ccd8ce806bba83f923399f3074",
        records=records,
        rejections=[],
        total_raw_records=len(records),
        valid_records=len(records),
        rejected_records=0,
        duplicate_records=0,
    )
    insert_intel_batch(conn, batch)
    conn.close()
    return temp_bench_db


# =============================================================================
# 1. Read-Only P4 Connection Isolation & Security Authorizer Tests
# =============================================================================

def test_readonly_p4_connection_isolation():
    """Verify that get_readonly_p4_connection rejects any write operation via authorizer."""
    if not DEFAULT_REAL_P4_DB_PATH.exists():
        pytest.skip(f"Canonical database {DEFAULT_REAL_P4_DB_PATH} not found.")

    conn = get_readonly_p4_connection(DEFAULT_REAL_P4_DB_PATH)
    try:
        # SELECT is permitted
        row = conn.execute("SELECT count(*) FROM blocks").fetchone()
        assert row is not None and row[0] >= 0

        # Attempting INSERT must be denied by authorizer or query_only
        with pytest.raises((sqlite3.DatabaseError, sqlite3.OperationalError)):
            conn.execute("INSERT INTO audit_events (action) VALUES ('unauthorized_write')")

        # Attempting UPDATE must be denied
        with pytest.raises((sqlite3.DatabaseError, sqlite3.OperationalError)):
            conn.execute("UPDATE blocks SET status = 'compromised'")

        # Attempting DELETE must be denied
        with pytest.raises((sqlite3.DatabaseError, sqlite3.OperationalError)):
            conn.execute("DELETE FROM blocks")

        # Attempting DDL (CREATE / DROP) must be denied
        with pytest.raises((sqlite3.DatabaseError, sqlite3.OperationalError)):
            conn.execute("CREATE TABLE malicious_table (id INT)")
    finally:
        conn.close()


def test_readonly_p4_nonexistent_raises(tmp_path: Path):
    """Verify that targeting a missing database file raises FileNotFoundError."""
    missing = tmp_path / "does_not_exist.db"
    with pytest.raises(FileNotFoundError):
        get_readonly_p4_connection(missing)


# =============================================================================
# 2. Counterparty Extraction Tests
# =============================================================================

def test_extract_incident_counterparties_euler():
    """Verify on-chain counterparty extraction for Euler Finance from real_p4.db."""
    if not DEFAULT_REAL_P4_DB_PATH.exists():
        pytest.skip("Canonical real_p4.db not available.")

    conn = get_readonly_p4_connection(DEFAULT_REAL_P4_DB_PATH)
    try:
        addrs = extract_incident_counterparties(conn, "euler_finance")
        assert len(addrs) > 2000, f"Expected >2000 counterparties for Euler, got {len(addrs)}"
        # Verify normalization invariant (lowercase 0x + 40 hex chars)
        for a in addrs:
            assert a.startswith("0x")
            assert len(a) == 42
            assert a == a.lower()
            assert int(a, 16) >= 0
    finally:
        conn.close()


def test_extract_incident_counterparties_curve():
    """Verify on-chain counterparty extraction for Curve alETH from real_p4.db."""
    if not DEFAULT_REAL_P4_DB_PATH.exists():
        pytest.skip("Canonical real_p4.db not available.")

    conn = get_readonly_p4_connection(DEFAULT_REAL_P4_DB_PATH)
    try:
        addrs = extract_incident_counterparties(conn, "curve_aleth")
        assert len(addrs) >= 100, f"Expected >=100 counterparties for Curve, got {len(addrs)}"
        for a in addrs:
            assert a.startswith("0x")
            assert len(a) == 42
            assert a == a.lower()
    finally:
        conn.close()


def test_extract_incident_counterparties_invalid_name():
    """Verify ValueError is raised for an unknown incident identifier."""
    if not DEFAULT_REAL_P4_DB_PATH.exists():
        pytest.skip("Canonical real_p4.db not available.")

    conn = get_readonly_p4_connection(DEFAULT_REAL_P4_DB_PATH)
    try:
        with pytest.raises(ValueError, match="Unknown incident"):
            extract_incident_counterparties(conn, "fictitious_exploit_2026")
    finally:
        conn.close()


# =============================================================================
# 3. Screening Match Detection Logic Tests
# =============================================================================

def test_screening_match_logic_with_fixture(populated_bench_db: Path):
    """Verify that screen_addresses detects positive threat matches accurately."""
    conn = sqlite3.connect(populated_bench_db)
    try:
        targets = [
            "0x1111111111111111111111111111111111111111",  # Matches PHISHING
            "0x2222222222222222222222222222222222222222",  # Matches ICE_PHISHING
            "0x9999999999999999999999999999999999999999",  # Unlisted (benign/unknown)
        ]
        matches = screen_addresses(conn, targets, incident_name="unit_test_incident")
        assert len(matches) == 2, f"Expected 2 matches, got {len(matches)}"

        match_map = {m.target_address: m for m in matches}
        m1 = match_map["0x1111111111111111111111111111111111111111"]
        assert m1.canonical_category == "PHISHING"
        assert m1.source_incident == "unit_test_incident"
        assert m1.match_type == "EXACT_MATCH"
        assert m1.match_id.startswith("sm_")
        assert m1.threat_sub_tactic == "credential_harvest"

        m2 = match_map["0x2222222222222222222222222222222222222222"]
        assert m2.canonical_category == "ICE_PHISHING"
        assert m2.threat_sub_tactic == "approval_abuse"
    finally:
        conn.close()


def test_screening_no_match_behavior(populated_bench_db: Path):
    """Verify that unlisted addresses produce zero matches and no exceptions."""
    conn = sqlite3.connect(populated_bench_db)
    try:
        targets = [
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ]
        matches = screen_addresses(conn, targets, incident_name="clean_test")
        assert len(matches) == 0
    finally:
        conn.close()


# =============================================================================
# 4. High-Volume Batch Chunking & SQL Injection Defense Tests
# =============================================================================

def test_screening_batch_chunking(populated_bench_db: Path):
    """Verify that screen_addresses correctly chunks lists larger than 500 items."""
    conn = sqlite3.connect(populated_bench_db)
    try:
        # Create a large list of 1,200 addresses with target matches placed at indices 0 and 1,199
        large_list = [f"0x{i:040x}" for i in range(5, 1205)]
        large_list[0] = "0x1111111111111111111111111111111111111111"
        large_list[-1] = "0x4444444444444444444444444444444444444444"

        matches = screen_addresses(conn, large_list, incident_name="chunk_test", chunk_size=500)
        assert len(matches) == 2
        matched_addrs = {m.target_address for m in matches}
        assert "0x1111111111111111111111111111111111111111" in matched_addrs
        assert "0x4444444444444444444444444444444444444444" in matched_addrs
    finally:
        conn.close()


def test_screening_sql_injection_defense(populated_bench_db: Path):
    """Verify that malicious SQL injection strings are safely handled and do not mutate tables."""
    conn = sqlite3.connect(populated_bench_db)
    try:
        adversarial_inputs = [
            "0x1111111111111111111111111111111111111111' OR '1'='1",
            "'; DROP TABLE threat_intel_records;--",
            "0x0000000000000000000000000000000000000000' UNION SELECT * FROM sqlite_master;--",
        ]
        # Should gracefully filter out invalid addresses and execute safely
        matches = screen_addresses(conn, adversarial_inputs, incident_name="injection_test")
        assert len(matches) == 0

        # Confirm threat_intel_records table was not dropped or compromised
        count = conn.execute("SELECT count(*) FROM threat_intel_records").fetchone()[0]
        assert count == 4
    finally:
        conn.close()


# =============================================================================
# 5. Persistence, Replay Idempotency & Conflict Detection Tests
# =============================================================================

def test_persist_screening_matches_append_only(temp_bench_db: Path):
    """Verify append-only persistence of screening matches into screening_matches table."""
    conn = sqlite3.connect(temp_bench_db)
    try:
        m1 = ScreeningMatch(
            match_id="sm_test_001",
            target_address="0x1111111111111111111111111111111111111111",
            source_incident="euler_finance",
            canonical_category="PHISHING",
            match_type="EXACT_MATCH",
            matched_at=current_iso_utc(),
        )
        m2 = ScreeningMatch(
            match_id="sm_test_002",
            target_address="0x2222222222222222222222222222222222222222",
            source_incident="curve_aleth",
            canonical_category="EXPLOIT",
            match_type="EXACT_MATCH",
            matched_at=current_iso_utc(),
        )

        # First insert
        stats1 = persist_screening_matches(conn, [m1, m2])
        assert stats1 == {"total": 2, "inserted": 2, "replay": 0}

        # Verify rows in DB
        rows = conn.execute("SELECT match_id, target_address FROM screening_matches ORDER BY match_id").fetchall()
        assert len(rows) == 2
        assert rows[0][0] == "sm_test_001"

        # Idempotent replay: must acknowledge duplicates without adding rows
        stats2 = persist_screening_matches(conn, [m1, m2])
        assert stats2 == {"total": 2, "inserted": 0, "replay": 2}
        assert conn.execute("SELECT count(*) FROM screening_matches").fetchone()[0] == 2

        # Conflicting modification: different category with same match_id must raise EvidenceConflictError
        conflicting_m1 = ScreeningMatch(
            match_id="sm_test_001",
            target_address="0x1111111111111111111111111111111111111111",
            source_incident="euler_finance",
            canonical_category="TAMPERED_CATEGORY",  # Conflict!
            match_type="EXACT_MATCH",
            matched_at=current_iso_utc(),
        )
        with pytest.raises(EvidenceConflictError):
            persist_screening_matches(conn, [conflicting_m1])

    finally:
        conn.close()


# =============================================================================
# 6. Ad-Hoc Single Address Screening API Tests
# =============================================================================

def test_screen_single_address_lookup(populated_bench_db: Path):
    """Verify single address screening lookup API."""
    conn = sqlite3.connect(populated_bench_db)
    try:
        # Known threat
        results = screen_single_address(conn, "0x1111111111111111111111111111111111111111")
        assert len(results) == 1
        assert results[0]["address"] == "0x1111111111111111111111111111111111111111"
        assert results[0]["threat_category"] == "PHISHING"
        assert results[0]["threat_sub_tactic"] == "credential_harvest"
        assert results[0]["data_source"] == "test_feed"

        # Unknown / benign address
        empty_res = screen_single_address(conn, "0x9999999999999999999999999999999999999999")
        assert len(empty_res) == 0

        # Malformed string
        invalid_res = screen_single_address(conn, "not_an_address")
        assert len(invalid_res) == 0
    finally:
        conn.close()


# =============================================================================
# 7. Physical Database Isolation Guard Tests
# =============================================================================

def test_screening_database_isolation_guard():
    """Verify that assert_database_isolation rejects canonical database paths."""
    forbidden = [
        "D:/Projest/worktrees/p4_real_integration/data/real_p4.db",
        "data/real_p4.db",
        "real_p4.db",
        "data/forensics.db",
        "D:/Projest/Blockchain/data/forensics.db",
    ]
    for path in forbidden:
        with pytest.raises(ValueError, match="Database isolation violation"):
            assert_database_isolation(path)
