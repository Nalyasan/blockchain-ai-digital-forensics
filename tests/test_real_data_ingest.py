"""Tests for real Ethereum dataset ingestion & normalization engine (Phase 4).

Verifies:
1. Exact 7,032 transfers ingested (6,858 verified ERC-20, 152 incident ERC-20, 6 top-level ETH, 16 internal ETH).
2. 16 internal ETH transfers present with asset_id == 'NATIVE' and log_index < 0.
3. No duplicate canonical events (UNIQUE constraint on chain_id, block_hash, tx_hash, log_index).
4. Strict non-overlapping window bounds between calibration and test partitions.
5. Zero floating-point conversion error (amount_raw matches exact integer strings without precision loss).
6. Canonical blocks properly linked with status = 'canonical' and valid block_time_utc.
"""
from __future__ import annotations

import csv
from pathlib import Path
import sqlite3
import pytest

from forensics.real_data_ingest import (
    DEFAULT_DB_PATH,
    DEFAULT_RESEARCH_DIR,
    EULER_DAI_CALIBRATION_BOUNDS,
    EULER_DAI_TEST_BOUNDS,
    CURVE_ALETH_CALIBRATION_BOUNDS,
    CURVE_ALETH_TEST_BOUNDS,
    find_internal_transfers_file,
    ingest_real_dataset,
)


@pytest.fixture(scope="module")
def real_ingest_fixture(tmp_path_factory):
    """Run ingestion once on a temporary SQLite DB for all module tests."""
    temp_dir = tmp_path_factory.mktemp("real_p4_test")
    temp_db = temp_dir / "test_real_p4.db"
    stats = ingest_real_dataset(research_dir=DEFAULT_RESEARCH_DIR, db_path=temp_db)
    conn = sqlite3.connect(str(temp_db))
    yield {"db_path": temp_db, "conn": conn, "stats": stats}
    conn.close()


def test_exact_7032_transfers_ingested(real_ingest_fixture):
    """Verify exact 7,032 total transfers ingested across all categories."""
    conn: sqlite3.Connection = real_ingest_fixture["conn"]
    stats = real_ingest_fixture["stats"]

    assert stats["total_transfers"] == 7032
    assert stats["verified_erc20"] == 6858
    assert stats["incident_erc20"] == 152
    assert stats["toplevel_eth"] == 6
    assert stats["internal_eth"] == 16

    # Verify directly via SQL
    total_db = conn.execute("SELECT count(*) FROM asset_transfers").fetchone()[0]
    assert total_db == 7032

    # ERC-20 transfers count: 6,858 + 152 = 7,010
    erc20_count = conn.execute("SELECT count(*) FROM asset_transfers WHERE asset_id != 'NATIVE'").fetchone()[0]
    assert erc20_count == 7010

    # NATIVE transfers count: 6 top-level + 16 internal = 22
    native_count = conn.execute("SELECT count(*) FROM asset_transfers WHERE asset_id = 'NATIVE'").fetchone()[0]
    assert native_count == 22


def test_internal_eth_transfers_normalization(real_ingest_fixture):
    """Verify 16 internal ETH transfers normalized to NATIVE with distinct negative log_index."""
    conn: sqlite3.Connection = real_ingest_fixture["conn"]

    internal_rows = conn.execute(
        """
        SELECT chain_id, tx_hash, block_number, block_hash, log_index, asset_id,
               from_addr, to_addr, amount_raw
        FROM asset_transfers
        WHERE asset_id = 'NATIVE' AND log_index < -1
        ORDER BY block_number, tx_hash, log_index
        """
    ).fetchall()

    assert len(internal_rows) == 16, f"Expected 16 internal ETH transfers, got {len(internal_rows)}"

    for row in internal_rows:
        cid, tx_h, b_num, b_h, log_idx, asset_id, from_a, to_a, amt_raw = row
        assert cid == 1
        assert tx_h.startswith("0x") and len(tx_h) == 66
        assert b_h.startswith("0x") and len(b_h) == 66
        assert b_num > 0
        assert asset_id == "NATIVE", f"Expected NATIVE, got {asset_id}"
        assert log_idx < 0, f"Expected negative log_index, got {log_idx}"
        assert log_idx <= -100, f"Expected internal log_index <= -100, got {log_idx}"
        assert from_a == from_a.lower() and from_a.startswith("0x")
        assert to_a == to_a.lower() and to_a.startswith("0x")
        assert amt_raw.isdigit(), f"amount_raw must be pure integer string: {amt_raw}"
        assert "." not in amt_raw and "e" not in amt_raw

    # Verify per-transaction uniqueness of assigned log_index
    tx_log_indices = {}
    for row in internal_rows:
        tx_h = row[1]
        log_idx = row[4]
        tx_log_indices.setdefault(tx_h, []).append(log_idx)

    for tx_h, indices in tx_log_indices.items():
        assert len(indices) == len(set(indices)), f"Duplicate log_index in tx {tx_h}: {indices}"


def test_toplevel_eth_transfers(real_ingest_fixture):
    """Verify 6 top-level ETH transfers normalized with log_index = -1 and asset_id = 'NATIVE'."""
    conn: sqlite3.Connection = real_ingest_fixture["conn"]

    toplevel_rows = conn.execute(
        """
        SELECT chain_id, tx_hash, block_number, block_hash, log_index, asset_id,
               from_addr, to_addr, amount_raw
        FROM asset_transfers
        WHERE asset_id = 'NATIVE' AND log_index = -1
        ORDER BY block_number, tx_hash
        """
    ).fetchall()

    assert len(toplevel_rows) == 6, f"Expected 6 top-level ETH transfers, got {len(toplevel_rows)}"

    for row in toplevel_rows:
        cid, tx_h, b_num, b_h, log_idx, asset_id, from_a, to_a, amt_raw = row
        assert cid == 1
        assert asset_id == "NATIVE"
        assert log_idx == -1
        assert amt_raw.isdigit()


def test_no_duplicate_canonical_events(real_ingest_fixture):
    """Verify zero duplicate canonical events across (chain_id, block_hash, tx_hash, log_index)."""
    conn: sqlite3.Connection = real_ingest_fixture["conn"]

    duplicates = conn.execute(
        """
        SELECT chain_id, block_hash, tx_hash, log_index, count(*) as cnt
        FROM asset_transfers
        GROUP BY chain_id, block_hash, tx_hash, log_index
        HAVING cnt > 1
        """
    ).fetchall()

    assert len(duplicates) == 0, f"Found duplicate transfers: {duplicates}"

    # Verify deduplication between p4_erc20_verified_so_far.csv and asset_transfers.csv
    # The 11 incident transfers already in verified window must not be duplicated
    output_dir = Path(DEFAULT_RESEARCH_DIR) / "output"
    verified_csv = output_dir / "verification" / "p4_erc20_verified_so_far.csv"
    asset_csv = output_dir / "asset_transfers.csv"

    ver_keys = set()
    with open(verified_csv, "r", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            ver_keys.add((int(r["chain_id"]), r["tx_hash"], int(r["log_index"])))

    overlapping_in_asset_transfers = 0
    with open(asset_csv, "r", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if (int(r["chain_id"]), r["tx_hash"], int(r["log_index"])) in ver_keys:
                overlapping_in_asset_transfers += 1

    assert overlapping_in_asset_transfers == 11, f"Expected 11 overlapping transfers, got {overlapping_in_asset_transfers}"


def test_strict_non_overlapping_window_bounds():
    """Verify strict non-overlapping calibration and test window bounds for Euler and Curve."""
    output_dir = Path(DEFAULT_RESEARCH_DIR) / "output"
    verified_csv = output_dir / "verification" / "p4_erc20_verified_so_far.csv"

    euler_cal_blocks = []
    euler_test_blocks = []
    curve_cal_blocks = []
    curve_test_blocks = []

    with open(verified_csv, "r", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            incident = r["incident"]
            dataset = r["dataset"]
            b_num = int(r["block_number"])

            if incident == "Euler":
                if dataset == "calibration":
                    euler_cal_blocks.append(b_num)
                elif dataset == "test":
                    euler_test_blocks.append(b_num)
            elif incident == "Curve":
                if dataset == "calibration":
                    curve_cal_blocks.append(b_num)
                elif dataset == "test":
                    curve_test_blocks.append(b_num)

    # Counts
    assert len(euler_cal_blocks) == 6042
    assert len(euler_test_blocks) == 340
    assert len(curve_cal_blocks) == 246
    assert len(curve_test_blocks) == 230

    # Bounds check
    assert min(euler_cal_blocks) >= EULER_DAI_CALIBRATION_BOUNDS[0]
    assert max(euler_cal_blocks) <= EULER_DAI_CALIBRATION_BOUNDS[1]
    assert min(euler_test_blocks) >= EULER_DAI_TEST_BOUNDS[0]
    assert max(euler_test_blocks) <= EULER_DAI_TEST_BOUNDS[1]
    # Strict separation
    assert max(euler_cal_blocks) < min(euler_test_blocks)
    assert EULER_DAI_CALIBRATION_BOUNDS[1] < EULER_DAI_TEST_BOUNDS[0]

    assert min(curve_cal_blocks) >= CURVE_ALETH_CALIBRATION_BOUNDS[0]
    assert max(curve_cal_blocks) <= CURVE_ALETH_CALIBRATION_BOUNDS[1]
    assert min(curve_test_blocks) >= CURVE_ALETH_TEST_BOUNDS[0]
    assert max(curve_test_blocks) <= CURVE_ALETH_TEST_BOUNDS[1]
    # Strict separation
    assert max(curve_cal_blocks) < min(curve_test_blocks)
    assert CURVE_ALETH_CALIBRATION_BOUNDS[1] < CURVE_ALETH_TEST_BOUNDS[0]


def test_zero_floating_point_conversion_error(real_ingest_fixture):
    """Verify zero floating point conversion error; amount_raw matches exact source Wei strings."""
    conn: sqlite3.Connection = real_ingest_fixture["conn"]
    output_dir = Path(DEFAULT_RESEARCH_DIR) / "output"

    # 1. Verified ERC-20
    verified_csv = output_dir / "verification" / "p4_erc20_verified_so_far.csv"
    with open(verified_csv, "r", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            cid = int(r["chain_id"])
            b_hash = r["block_hash"]
            tx_h = r["tx_hash"]
            log_idx = int(r["log_index"])
            expected_amt = str(r["amount_raw"]).strip()

            row = conn.execute(
                "SELECT amount_raw FROM asset_transfers WHERE chain_id=? AND block_hash=? AND tx_hash=? AND log_index=?",
                (cid, b_hash, tx_h, log_idx),
            ).fetchone()
            assert row is not None, f"Missing transfer for {tx_h}:{log_idx}"
            assert row[0] == expected_amt, f"Precision mismatch: {row[0]} != {expected_amt}"

    # 2. Internal ETH transfers
    internal_csv = find_internal_transfers_file(output_dir)
    with open(internal_csv, "r", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            tx_h = r["tx_hash"]
            expected_wei = str(r["amount_wei"]).strip()
            from_a = r["from_address"].strip().lower()
            to_a = r["to_address"].strip().lower()

            rows = conn.execute(
                """
                SELECT amount_raw FROM asset_transfers
                WHERE tx_hash=? AND from_addr=? AND to_addr=? AND asset_id='NATIVE' AND log_index < -1
                """,
                (tx_h, from_a, to_a),
            ).fetchall()
            amounts = [x[0] for x in rows]
            assert expected_wei in amounts, f"Internal transfer amount {expected_wei} not found in DB for tx {tx_h}"


def test_canonical_blocks_properly_linked(real_ingest_fixture):
    """Verify all 7,032 transfers INNER JOIN with blocks b ON t.block_hash = b.hash WHERE b.status = 'canonical'."""
    conn: sqlite3.Connection = real_ingest_fixture["conn"]

    joined_count = conn.execute(
        """
        SELECT count(*)
        FROM asset_transfers t
        INNER JOIN blocks b ON t.block_hash = b.hash
        WHERE b.status = 'canonical'
        """
    ).fetchone()[0]

    assert joined_count == 7032, f"Expected 7,032 joined transfers, got {joined_count}"

    # Verify no orphaned transfers exist
    orphans = conn.execute(
        """
        SELECT count(*)
        FROM asset_transfers t
        LEFT JOIN blocks b ON t.block_hash = b.hash AND b.status = 'canonical'
        WHERE b.hash IS NULL
        """
    ).fetchone()[0]
    assert orphans == 0, f"Found {orphans} orphaned transfers not linked to canonical blocks"

    # Verify block_time_utc is populated and valid ISO UTC string
    empty_block_times = conn.execute(
        "SELECT count(*) FROM blocks WHERE block_time_utc IS NULL OR block_time_utc = ''"
    ).fetchone()[0]
    assert empty_block_times == 0


def test_default_database_artifact():
    """Verify target real_p4.db is correctly initialized and populated."""
    assert DEFAULT_DB_PATH.exists(), f"Default DB {DEFAULT_DB_PATH} does not exist"
    conn = sqlite3.connect(str(DEFAULT_DB_PATH))
    try:
        count = conn.execute("SELECT count(*) FROM asset_transfers").fetchone()[0]
        assert count == 7032
        canonical_count = conn.execute("SELECT count(*) FROM blocks WHERE status='canonical'").fetchone()[0]
        assert canonical_count == 1789
    finally:
        conn.close()
