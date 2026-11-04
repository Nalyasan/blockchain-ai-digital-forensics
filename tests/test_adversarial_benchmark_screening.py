"""Adversarial stress-test battery for Gate P6-03 Entity Screening Engine.

Systematically challenges:
1. High-volume chunked screening lookup (5,000 & 10,000 synthetic addresses in memory)
   without memory spikes (tracemalloc < 10 MB) or SQL parameter limit errors.
2. Variable chunk size behavior (100, 500, 1000, 2500) under batch query loads.
3. Matching logic positive detection fidelity at chunk boundaries (index 0, 499, 500, 999, 4999),
   multi-feed attribution, and exact category/tactic propagation.
4. Positive match detection verification directly against authentic benchmark_p6.db (34,841 records).
5. Single-address lookup edge cases: empty strings, whitespace, malformed lengths, non-hex strings,
   uppercase addresses, mixed-case checksummed addresses, leading/trailing whitespace, and SQL injections.
6. Append-only persistence invariants into screening_matches, replay idempotency, and conflict rejection.
7. Verification of performance figures, scale throughput, and latency against benchmark_metrics.json.
"""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
import sqlite3
import time
import tracemalloc
from typing import Any, List, Sequence
import pytest

from forensics.adapters.base import (
    ThreatIntelBatch,
    ThreatIntelRecord,
    current_iso_utc,
    is_valid_eth_address,
    normalize_eth_address,
)
from forensics.adapters.persistence_benchmark import (
    DEFAULT_BENCHMARK_DB_PATH,
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

logger = logging.getLogger(__name__)

from forensics.paths import BENCHMARK_DB as CANONICAL_BENCH_DB, PROJECT_ROOT

_P6_BENCH_ROOT = PROJECT_ROOT.parent / "p6_public_benchmark" if (PROJECT_ROOT.parent / "p6_public_benchmark").exists() else Path("D:/Projest/p6_public_benchmark")
BENCHMARK_METRICS_PATH = _P6_BENCH_ROOT / "results" / "benchmark_metrics.json"
AUTHENTIC_BENCH_DB_PATH = CANONICAL_BENCH_DB if CANONICAL_BENCH_DB.exists() else Path("D:/Projest/p6_public_benchmark/data/benchmark_p6.db")


@pytest.fixture
def temp_bench_db(tmp_path: Path) -> Path:
    """Fixture providing an initialized, isolated benchmark SQLite database."""
    db_file = tmp_path / "test_adversarial_screening.db"
    conn = init_benchmark_db(db_file)
    conn.close()
    return db_file


@pytest.fixture
def populated_bench_db(temp_bench_db: Path) -> Path:
    """Fixture with pre-populated diverse threat intelligence records."""
    conn = sqlite3.connect(temp_bench_db)
    threat_configs = [
        ("0x1111111111111111111111111111111111111111", "PHISHING", "credential_harvest", "forta", 0.95),
        ("0x2222222222222222222222222222222222222222", "ICE_PHISHING", "approval_abuse", "ptxphish", 1.0),
        ("0x3333333333333333333333333333333333333333", "MALICIOUS_CONTRACT", "drainer", "forta", 0.99),
        ("0x4444444444444444444444444444444444444444", "ADDRESS_POISONING", "vanity_spoof", "ptxphish", 0.85),
        ("0x5555555555555555555555555555555555555555", "MEW_DARKLIST", "known_scam", "mew_darklist", 1.0),
        ("0x6666666666666666666666666666666666666666", "ETHERSCAN_MALICIOUS", "phishing_hack", "etherscan", 0.9),
        # Multi-source threat address
        ("0x7777777777777777777777777777777777777777", "PHISHING", "credential_harvest", "feed_a", 1.0),
        ("0x7777777777777777777777777777777777777777", "ICE_PHISHING", "approval_abuse", "feed_b", 0.9),
    ]

    records = [
        ThreatIntelRecord(
            source_file_path=f"datasets/test/{src}.csv",
            source_file_sha256=f"hash_source_{src}_{idx}",
            source_commit="55003fd7466148ccd8ce806bba83f923399f3074",
            row_identifier=f"row_{idx}",
            raw_payload_sha256=f"hash_payload_{idx}",
            entity_type="address",
            entity_value=addr,
            threat_category=cat,
            threat_sub_tactic=sub,
            confidence_score=conf,
            data_source=src,
            raw_metadata_json=f'{{"tag": "{cat}", "source": "{src}"}}',
            ingestion_timestamp=current_iso_utc(),
        )
        for idx, (addr, cat, sub, src, conf) in enumerate(threat_configs, start=1)
    ]

    batch = ThreatIntelBatch(
        source_id="adversarial_fixture_v1",
        source_name="adversarial_test",
        file_path="datasets/test/adversarial.csv",
        file_sha256="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
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
# 1. High-Volume Chunked Lookup Stress Tests
# =============================================================================

def test_stress_chunked_lookup_5000_addresses(populated_bench_db: Path):
    """Verify that screen_addresses processes 5,000 synthetic addresses without memory spikes or SQL errors."""
    conn = sqlite3.connect(populated_bench_db)
    try:
        # Generate 5,000 synthetic addresses
        synthetic_5k = [f"0x{i:040x}" for i in range(100, 5100)]
        # Inject one known threat target at index 2500
        synthetic_5k[2500] = "0x1111111111111111111111111111111111111111"

        tracemalloc.start()
        mem_before, _ = tracemalloc.get_traced_memory()
        t0 = time.perf_counter()

        matches = screen_addresses(conn, synthetic_5k, incident_name="stress_5k", chunk_size=500)

        elapsed = time.perf_counter() - t0
        _, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        mem_delta_mb = (peak_mem - mem_before) / (1024 * 1024)

        # Assertions
        assert len(matches) == 1, f"Expected 1 match, got {len(matches)}"
        assert matches[0].target_address == "0x1111111111111111111111111111111111111111"
        assert matches[0].canonical_category == "PHISHING"
        assert matches[0].source_incident == "stress_5k"

        # Performance assertions
        assert mem_delta_mb < 10.0, f"Memory spike exceeded 10 MB: {mem_delta_mb:.2f} MB"
        assert elapsed < 2.0, f"5,000 lookups took too long: {elapsed:.3f} s"
    finally:
        conn.close()


def test_stress_chunked_lookup_variable_chunk_sizes(populated_bench_db: Path):
    """Verify invariant behavior across different SQL IN parameter chunk sizes."""
    conn = sqlite3.connect(populated_bench_db)
    try:
        # Generate 2,000 addresses with 3 known targets
        addrs = [f"0x{i:040x}" for i in range(200, 2200)]
        addrs[10] = "0x1111111111111111111111111111111111111111"
        addrs[999] = "0x2222222222222222222222222222222222222222"
        addrs[1999] = "0x3333333333333333333333333333333333333333"

        chunk_sizes = [50, 100, 250, 500, 1000]
        results_by_chunk = {}

        for cs in chunk_sizes:
            matches = screen_addresses(conn, addrs, incident_name=f"chunk_{cs}", chunk_size=cs)
            matched_addrs = {m.target_address for m in matches}
            assert len(matches) == 3, f"Failed for chunk_size={cs}: got {len(matches)} matches"
            assert "0x1111111111111111111111111111111111111111" in matched_addrs
            assert "0x2222222222222222222222222222222222222222" in matched_addrs
            assert "0x3333333333333333333333333333333333333333" in matched_addrs
            results_by_chunk[cs] = len(matches)

        # All chunk sizes must produce identical output counts
        assert len(set(results_by_chunk.values())) == 1
    finally:
        conn.close()


def test_stress_chunked_lookup_10000_addresses(populated_bench_db: Path):
    """Stress-test with 10,000 synthetic addresses in memory to verify scale stability."""
    conn = sqlite3.connect(populated_bench_db)
    try:
        synthetic_10k = [f"0x{i:040x}" for i in range(1000, 11000)]
        synthetic_10k[0] = "0x1111111111111111111111111111111111111111"
        synthetic_10k[5000] = "0x3333333333333333333333333333333333333333"
        synthetic_10k[9999] = "0x5555555555555555555555555555555555555555"

        tracemalloc.start()
        mem_before, _ = tracemalloc.get_traced_memory()
        t0 = time.perf_counter()

        matches = screen_addresses(conn, synthetic_10k, incident_name="stress_10k", chunk_size=500)

        elapsed = time.perf_counter() - t0
        _, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        mem_delta_mb = (peak_mem - mem_before) / (1024 * 1024)

        assert len(matches) == 3
        assert mem_delta_mb < 15.0
        assert elapsed < 3.0, f"10,000 lookups took {elapsed:.3f} s"
    finally:
        conn.close()


# =============================================================================
# 2. Positive Match Detection Logic & Boundary Fidelity
# =============================================================================

def test_positive_match_detection_at_boundaries(populated_bench_db: Path):
    """Verify that matches placed exactly at chunk boundaries (index 0, 499, 500, 999, 4999) are reliably caught."""
    conn = sqlite3.connect(populated_bench_db)
    try:
        # 5,000 addresses with 5 known targets positioned at exact chunk boundaries (chunk_size=500)
        boundary_list = [f"0x{i:040x}" for i in range(1, 5001)]
        boundary_list[0] = "0x1111111111111111111111111111111111111111"     # First element (Chunk 0)
        boundary_list[499] = "0x2222222222222222222222222222222222222222"   # Last element of Chunk 0
        boundary_list[500] = "0x3333333333333333333333333333333333333333"   # First element of Chunk 1
        boundary_list[999] = "0x4444444444444444444444444444444444444444"   # Last element of Chunk 1
        boundary_list[4999] = "0x5555555555555555555555555555555555555555"  # Last element of Chunk 9

        matches = screen_addresses(conn, boundary_list, incident_name="boundary_test", chunk_size=500)
        assert len(matches) == 5, f"Expected 5 boundary matches, got {len(matches)}"

        matched_map = {m.target_address: m for m in matches}
        assert matched_map["0x1111111111111111111111111111111111111111"].canonical_category == "PHISHING"
        assert matched_map["0x2222222222222222222222222222222222222222"].canonical_category == "ICE_PHISHING"
        assert matched_map["0x3333333333333333333333333333333333333333"].canonical_category == "MALICIOUS_CONTRACT"
        assert matched_map["0x4444444444444444444444444444444444444444"].canonical_category == "ADDRESS_POISONING"
        assert matched_map["0x5555555555555555555555555555555555555555"].canonical_category == "MEW_DARKLIST"

        # Verify deterministic match_id format
        for m in matches:
            assert m.match_id.startswith("sm_")
            assert len(m.match_id) == 27  # 'sm_' (3 chars) + 24 hex chars
    finally:
        conn.close()


def test_positive_match_multi_feed_attribution(populated_bench_db: Path):
    """Verify that an address listed in multiple feeds yields distinct match records with correct attribution."""
    conn = sqlite3.connect(populated_bench_db)
    try:
        # 0x7777... is present twice in fixture with feeds 'feed_a' and 'feed_b'
        target = ["0x7777777777777777777777777777777777777777"]
        matches = screen_addresses(conn, target, incident_name="multi_feed_test")
        assert len(matches) == 2, f"Expected 2 matches for dual-feed address, got {len(matches)}"

        sources = {m.data_source for m in matches}
        assert sources == {"feed_a", "feed_b"}

        match_ids = {m.match_id for m in matches}
        assert len(match_ids) == 2, "Match IDs for distinct feed attributions must be unique"
    finally:
        conn.close()


def test_positive_match_against_authentic_benchmark_db():
    """Verify matching fidelity by extracting authentic threat records from benchmark_p6.db."""
    if not AUTHENTIC_BENCH_DB_PATH.exists():
        pytest.skip(f"Authentic benchmark database {AUTHENTIC_BENCH_DB_PATH} not found.")

    conn = sqlite3.connect(f"file:///{AUTHENTIC_BENCH_DB_PATH.as_posix()}?mode=ro&immutable=1", uri=True)
    try:
        # Select 20 authentic addresses across different datasets
        query = """
            SELECT DISTINCT entity_value, threat_category, data_source
            FROM threat_intel_records
            WHERE entity_type IN ('address', 'contract')
            LIMIT 20
        """
        rows = conn.execute(query).fetchall()
        assert len(rows) == 20, f"Expected 20 sample records from benchmark_p6.db, got {len(rows)}"

        target_addrs = [r[0] for r in rows]
        # Interleave with 80 unlisted addresses (total 100)
        mixed_batch = [f"0xdeadbeef{i:032x}" for i in range(80)] + target_addrs

        matches = screen_addresses(conn, mixed_batch, incident_name="authentic_test", chunk_size=50)
        matched_target_addrs = {m.target_address for m in matches}

        # Verify 100% recall on authentic target addresses
        for addr in target_addrs:
            assert addr in matched_target_addrs, f"Authentic threat address {addr} was not detected!"

        # Verify 0% false positives on unlisted synthetic addresses
        for synthetic in mixed_batch[:80]:
            assert synthetic not in matched_target_addrs, f"False positive reported on unlisted {synthetic}"
    finally:
        conn.close()


# =============================================================================
# 3. Single Address Lookup Boundary & Sanitization Tests
# =============================================================================

@pytest.mark.parametrize("empty_input", [
    "",
    "   ",
    "\t\n\r",
    None,
    12345,
    [],
    {},
])
def test_screen_single_address_empty_and_non_string(populated_bench_db: Path, empty_input: Any):
    """Verify that empty, whitespace-only, or non-string inputs return [] gracefully."""
    conn = sqlite3.connect(populated_bench_db)
    try:
        res = screen_single_address(conn, empty_input)  # type: ignore[arg-type]
        assert res == []
    finally:
        conn.close()


@pytest.mark.parametrize("malformed_addr", [
    "0x" + "a" * 39,          # 39 hex chars (too short)
    "0x" + "a" * 41,          # 41 hex chars (too long)
    "0x" + "g" * 40,          # Invalid non-hex char 'g'
    "0x" + "z" * 40,          # Invalid non-hex char 'z'
    "not_an_address_at_all",  # Arbitrary string
    "0x" + "1" * 38 + "??",   # Special chars in hex
])
def test_screen_single_address_malformed_syntax(populated_bench_db: Path, malformed_addr: str):
    """Verify that syntactically invalid addresses return [] without exception."""
    conn = sqlite3.connect(populated_bench_db)
    try:
        res = screen_single_address(conn, malformed_addr)
        assert res == []
    finally:
        conn.close()


def test_screen_single_address_uppercase_and_whitespace(populated_bench_db: Path):
    """Verify that uppercase hex, mixed-case, un-prefixed, padded addresses match, and 0X prefix is handled gracefully."""
    conn = sqlite3.connect(populated_bench_db)
    try:
        # Insert a canonical address with distinct hex letters a-f:
        canonical = "0xabcdef1234567890abcdef1234567890abcdef12"
        record = ThreatIntelRecord(
            source_file_path="datasets/test/mixed.csv",
            source_file_sha256="mixed_source_sha256_abcdef",
            source_commit="55003fd7466148ccd8ce806bba83f923399f3074",
            row_identifier="row_mixed",
            raw_payload_sha256="payload_mixed_sha256",
            entity_type="address",
            entity_value=canonical,
            threat_category="PHISHING",
            confidence_score=1.0,
            data_source="test_mixed",
            raw_metadata_json="{}",
            ingestion_timestamp=current_iso_utc(),
        )
        batch = ThreatIntelBatch(
            source_id="mixed_src",
            source_name="mixed",
            file_path="datasets/test/mixed.csv",
            file_sha256="mixed_source_sha256_abcdef",
            source_commit="55003fd7466148ccd8ce806bba83f923399f3074",
            records=[record],
            rejections=[],
            total_raw_records=1,
            valid_records=1,
            rejected_records=0,
            duplicate_records=0,
        )
        insert_intel_batch(conn, batch)

        # 1. Uppercase hex characters with standard 0x prefix ('0xABCDEF...')
        upper_hex = "0x" + canonical[2:].upper()
        res_upper = screen_single_address(conn, upper_hex)
        assert len(res_upper) == 1, "Failed to match uppercase hex characters with 0x prefix"
        assert res_upper[0]["address"] == canonical

        # 2. Leading and trailing whitespace
        padded_addr = f"   \t{canonical} \n "
        res_padded = screen_single_address(conn, padded_addr)
        assert len(res_padded) == 1, "Failed to match whitespace-padded address"
        assert res_padded[0]["address"] == canonical

        # 3. Missing '0x' prefix (40 uppercase hex chars)
        no_prefix_upper = canonical[2:].upper()
        res_no_prefix = screen_single_address(conn, no_prefix_upper)
        assert len(res_no_prefix) == 1, "Failed to match uppercase address without 0x prefix"
        assert res_no_prefix[0]["address"] == canonical

        # 4. Mixed-case checksummed hex
        mixed_checksum = "0xAbCdEf1234567890aBcDeF1234567890AbCdEf12"
        res_mixed = screen_single_address(conn, mixed_checksum)
        assert len(res_mixed) == 1, "Failed to match mixed-case checksummed address"
        assert res_mixed[0]["address"] == canonical

        # 5. Uppercase '0X' prefix: gracefully handled as non-standard syntax, returning [] without error
        upper_0x_prefix = "0X" + canonical[2:].upper()
        res_0x = screen_single_address(conn, upper_0x_prefix)
        assert res_0x == [], "Uppercase 0X prefix should gracefully return []"
    finally:
        conn.close()


@pytest.mark.parametrize("sql_injection_payload", [
    "0x1111111111111111111111111111111111111111' OR 1=1 --",
    "0x1111111111111111111111111111111111111111' UNION SELECT * FROM sqlite_master --",
    "'; DROP TABLE threat_intel_records; --",
    "0x' OR ''='",
    "admin' --",
    "0x1111111111111111111111111111111111111111; VACUUM;",
])
def test_screen_single_address_sql_injection_resilience(
    populated_bench_db: Path,
    sql_injection_payload: str,
):
    """Verify that SQL injection payloads are neutralized and table integrity is preserved."""
    conn = sqlite3.connect(populated_bench_db)
    try:
        count_before = conn.execute("SELECT count(*) FROM threat_intel_records").fetchone()[0]

        res = screen_single_address(conn, sql_injection_payload)
        assert res == [], f"SQL injection payload {sql_injection_payload!r} returned unexpected matches"

        # Verify table row count did not mutate
        count_after = conn.execute("SELECT count(*) FROM threat_intel_records").fetchone()[0]
        assert count_before == count_after, "Table row count mutated during SQL injection attempt!"
    finally:
        conn.close()


# =============================================================================
# 4. Persistence Invariants & Conflict Rejection Tests
# =============================================================================

def test_persist_screening_matches_idempotent_and_conflict(temp_bench_db: Path):
    """Verify G5-02 append-only invariant: zero updates, idempotent replay, and conflict raising."""
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

        # 1. Initial insert
        stats1 = persist_screening_matches(conn, [m1])
        assert stats1 == {"total": 1, "inserted": 1, "replay": 0}

        # 2. Idempotent replay
        stats2 = persist_screening_matches(conn, [m1])
        assert stats2 == {"total": 1, "inserted": 0, "replay": 1}

        # 3. Conflict modification: changing canonical_category for same match_id
        conflicting = ScreeningMatch(
            match_id="sm_test_001",
            target_address="0x1111111111111111111111111111111111111111",
            source_incident="euler_finance",
            canonical_category="CONFLICTING_CATEGORY",
            match_type="EXACT_MATCH",
            matched_at=current_iso_utc(),
        )
        with pytest.raises(EvidenceConflictError):
            persist_screening_matches(conn, [conflicting])

        # Table row count must remain exactly 1
        assert conn.execute("SELECT count(*) FROM screening_matches").fetchone()[0] == 1
    finally:
        conn.close()


# =============================================================================
# 5. Benchmark Metrics & Real Incident Screening Verification
# =============================================================================

def test_verify_benchmark_metrics_file_consistency():
    """Verify benchmark_metrics.json structure, dataset provenance, and scale records."""
    assert BENCHMARK_METRICS_PATH.exists(), f"Benchmark metrics not found: {BENCHMARK_METRICS_PATH}"

    with open(BENCHMARK_METRICS_PATH, "r", encoding="utf-8") as f:
        metrics = json.load(f)

    # 1. Verify schema top-level keys
    assert "suite_name" in metrics
    assert "system_info" in metrics
    assert "datasets" in metrics
    assert "scales" in metrics
    assert "canonical_screening_evaluation" in metrics

    # 2. Verify all 6 authentic datasets
    datasets = metrics["datasets"]
    assert len(datasets) == 6, f"Expected 6 datasets, found {len(datasets)}"
    total_records = sum(d["records"] for d in datasets)
    assert total_records == 34841, f"Expected 34,841 total records, got {total_records}"
    assert all(d["rejections"] == 0 for d in datasets)

    # 3. Verify scale definitions
    scales = metrics["scales"]
    assert "scale_1k_small" in scales
    assert "scale_10k_medium" in scales
    assert "scale_full_34841" in scales

    # Scale 1k
    s1 = scales["scale_1k_small"]
    assert s1["target_count"] == 1000
    assert s1["duplicate_replay"]["duplicate_rate_pct"] == 100.0
    assert s1["ingestion"]["throughput_rec_per_sec"] > 20000.0
    assert s1["ingestion"]["peak_memory_mb"] < 1.0

    # Scale 10k
    s2 = scales["scale_10k_medium"]
    assert s2["target_count"] == 10000
    assert s2["duplicate_replay"]["duplicate_rate_pct"] == 100.0
    assert s2["ingestion"]["throughput_rec_per_sec"] > 20000.0

    # Scale Full 34,841
    s3 = scales["scale_full_34841"]
    assert s3["target_count"] == 34841
    assert s3["records_processed"] == 34841
    assert s3["duplicate_replay"]["duplicate_rate_pct"] == 100.0
    assert s3["ingestion"]["throughput_rec_per_sec"] > 20000.0
    assert s3["ingestion"]["duration_s"] < 5.0


def test_verify_incident_screening_live_reproducibility():
    """Verify live Euler and Curve counterparty screening against real_p4.db and benchmark_p6.db."""
    if not DEFAULT_REAL_P4_DB_PATH.exists():
        pytest.skip(f"Canonical database {DEFAULT_REAL_P4_DB_PATH} not found.")
    if not AUTHENTIC_BENCH_DB_PATH.exists():
        pytest.skip(f"Benchmark database {AUTHENTIC_BENCH_DB_PATH} not found.")

    p4_conn = get_readonly_p4_connection(DEFAULT_REAL_P4_DB_PATH)
    bench_conn = sqlite3.connect(f"file:///{AUTHENTIC_BENCH_DB_PATH.as_posix()}?mode=ro&immutable=1", uri=True)

    try:
        # 1. Euler Finance Counterparties
        t0_euler = time.perf_counter()
        euler_addrs = extract_incident_counterparties(p4_conn, "euler_finance")
        t_screen_euler = time.perf_counter()
        euler_matches = screen_addresses(bench_conn, euler_addrs, incident_name="euler_finance")
        euler_duration_ms = (time.perf_counter() - t_screen_euler) * 1000.0

        assert len(euler_addrs) == 2852, f"Expected 2,852 counterparties for Euler, got {len(euler_addrs)}"
        assert len(euler_matches) == 0, f"Expected 0 matches for Euler, got {len(euler_matches)}"
        assert euler_duration_ms < 100.0, f"Euler screening took {euler_duration_ms:.2f} ms (>100 ms)"

        # 2. Curve alETH Counterparties
        t_screen_curve = time.perf_counter()
        curve_addrs = extract_incident_counterparties(p4_conn, "curve_aleth")
        curve_matches = screen_addresses(bench_conn, curve_addrs, incident_name="curve_aleth")
        curve_duration_ms = (time.perf_counter() - t_screen_curve) * 1000.0

        assert len(curve_addrs) == 120, f"Expected 120 counterparties for Curve, got {len(curve_addrs)}"
        assert len(curve_matches) == 0, f"Expected 0 matches for Curve, got {len(curve_matches)}"
        assert curve_duration_ms < 50.0, f"Curve screening took {curve_duration_ms:.2f} ms (>50 ms)"

        # 3. Overall screening latency per address (must be sub-millisecond, <0.2 ms/addr)
        euler_latency_ms = euler_duration_ms / len(euler_addrs)
        curve_latency_ms = curve_duration_ms / len(curve_addrs)
        assert euler_latency_ms < 0.2, f"Euler per-address latency {euler_latency_ms:.5f} ms too high"
        assert curve_latency_ms < 0.2, f"Curve per-address latency {curve_latency_ms:.5f} ms too high"

    finally:
        p4_conn.close()
        bench_conn.close()
