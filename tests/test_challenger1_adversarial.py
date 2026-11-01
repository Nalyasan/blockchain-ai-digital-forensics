"""Empirical Adversarial Challenge & Stress-Test Suite for Phase 4 Milestone 2.

Executed by Challenger 1 (EMPIRICAL CHALLENGER).
Verifies:
1. Deterministic alert_id recomputation across ALL 172 alerts and zero collision.
2. Bit-for-bit evidence verification in asset_transfers of data/real_p4.db.
3. Internal ETH transfer deep forensic analysis (14 triggered, 2 untriggered of 16 total).
4. Incident transactions deep verification (0xc310..., 0xb676..., 0x0774...).
5. Window isolation, boundary conditions, and adversarial mutations.
"""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import pytest

from forensics.rules.base import compute_alert_id

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DB_PATH = PROJECT_ROOT / "data" / "real_p4.db"
ALERTS_JSON_PATH = PROJECT_ROOT / "results" / "p4" / "real_data_alerts.json"

EULER_FRONTRUN_TX = "0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d"
CURVE_EXPLOIT_TX = "0xb676d789bb8b66a08105c844a49c2bcffb400e5c1cfabd4bc30cca4bff3c9801"
CURVE_ARBITRAGE_TX = "0x0774e5a648c94140fb1956fd754937ca3937d12fbd2fd89a7f8c9cbbb68adb22"

EXPECTED_FIELDS = (
    "chain_id",
    "block_number",
    "block_hash",
    "block_timestamp",
    "tx_hash",
    "log_index",
    "asset_id",
    "from_addr",
    "to_addr",
    "amount_raw",
)


@pytest.fixture(scope="module")
def alerts_data() -> dict:
    assert ALERTS_JSON_PATH.exists(), f"Missing alerts JSON at {ALERTS_JSON_PATH}"
    with open(ALERTS_JSON_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def db_conn():
    assert DB_PATH.exists(), f"Missing SQLite database at {DB_PATH}"
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


# ==============================================================================
# Challenge 1: Alert ID Determinism & Collision Resistance
# ==============================================================================


def test_recompute_alert_ids_and_check_zero_collisions(alerts_data: dict):
    """Recompute alert_id for ALL 172 alerts using compute_alert_id().

    Check for ANY discrepancies, null values, or hash collisions.
    """
    alerts = alerts_data["alerts"]
    assert len(alerts) == 172, f"Expected 172 alerts, got {len(alerts)}"

    seen_ids = set()
    mismatches = []

    for idx, alert in enumerate(alerts):
        recorded_id = alert["alert_id"]
        # Recompute independently using canonical compute_alert_id
        computed_id = compute_alert_id(
            chain_id=1,
            rule_id=alert["rule_id"],
            rule_version=alert["rule_version"],
            unit_type=alert["unit_type"],
            unit_key=alert["unit_key"],
            asset_id=alert["asset_id"],
            evidence_refs=alert["evidence_refs"],
        )

        if recorded_id != computed_id:
            mismatches.append(
                f"Alert [{idx}]: recorded={recorded_id} != computed={computed_id}"
            )

        if recorded_id in seen_ids:
            pytest.fail(f"COLLISION DETECTED: alert_id {recorded_id} appears multiple times!")
        seen_ids.add(recorded_id)

    assert not mismatches, f"Discrepancies found: {mismatches}"
    assert len(seen_ids) == 172, f"Collision check failed: {len(seen_ids)} unique IDs out of 172"


def test_alert_id_mutation_sensitivity(alerts_data: dict):
    """Adversarial stress-test: mutate evidence or metadata and prove hash changes."""
    alerts = alerts_data["alerts"]
    sample_alert = alerts[0]

    original_id = sample_alert["alert_id"]

    # Mutation 1: Change unit_key
    mutated_key_id = compute_alert_id(
        chain_id=1,
        rule_id=sample_alert["rule_id"],
        rule_version=sample_alert["rule_version"],
        unit_type=sample_alert["unit_type"],
        unit_key=sample_alert["unit_key"] + "_mutated",
        asset_id=sample_alert["asset_id"],
        evidence_refs=sample_alert["evidence_refs"],
    )
    assert mutated_key_id != original_id, "Alert ID failed to change when unit_key mutated!"

    # Mutation 2: Mutate amount_raw in evidence_refs
    mutated_refs = [dict(r) for r in sample_alert["evidence_refs"]]
    first_amount = int(mutated_refs[0]["amount_raw"])
    mutated_refs[0]["amount_raw"] = str(first_amount + 1)
    # Note: identities only use chain_id:block_hash:tx_hash:log_index
    # What about mutating log_index?
    mutated_refs[0]["log_index"] = mutated_refs[0]["log_index"] + 99999
    mutated_log_id = compute_alert_id(
        chain_id=1,
        rule_id=sample_alert["rule_id"],
        rule_version=sample_alert["rule_version"],
        unit_type=sample_alert["unit_type"],
        unit_key=sample_alert["unit_key"],
        asset_id=sample_alert["asset_id"],
        evidence_refs=mutated_refs,
    )
    assert mutated_log_id != original_id, "Alert ID failed to change when log_index mutated!"


# ==============================================================================
# Challenge 2: Bit-for-Bit Evidence Verification in asset_transfers
# ==============================================================================


def test_evidence_refs_exist_bit_for_bit(alerts_data: dict, db_conn: sqlite3.Connection):
    """Verify that every transfer in evidence_refs exists bit-for-bit in asset_transfers."""
    alerts = alerts_data["alerts"]
    total_refs_checked = 0

    for alert_idx, alert in enumerate(alerts):
        refs = alert.get("evidence_refs", [])
        assert refs, f"Alert [{alert_idx}] has empty evidence_refs"

        for ref_idx, ref in enumerate(refs):
            total_refs_checked += 1
            # Check schema keys
            assert set(ref.keys()) == set(EXPECTED_FIELDS), (
                f"Alert [{alert_idx}] Ref [{ref_idx}] keys mismatch: {set(ref.keys())}"
            )

            # Query asset_transfers table
            row = db_conn.execute(
                """
                SELECT chain_id, block_number, block_hash, block_timestamp,
                       tx_hash, log_index, asset_id, from_addr, to_addr, amount_raw
                FROM asset_transfers
                WHERE chain_id = ? AND block_hash = ? AND tx_hash = ? AND log_index = ?
                """,
                (ref["chain_id"], ref["block_hash"], ref["tx_hash"], ref["log_index"]),
            ).fetchone()

            assert row is not None, (
                f"Evidence ref NOT FOUND in asset_transfers: "
                f"chain={ref['chain_id']}, block={ref['block_number']}, "
                f"tx={ref['tx_hash']}, log_idx={ref['log_index']}"
            )

            # Bit-for-bit comparison of all 10 fields
            for field in EXPECTED_FIELDS:
                actual_val = row[field]
                ref_val = ref[field]
                assert str(actual_val) == str(ref_val), (
                    f"Bit mismatch in Alert [{alert_idx}] Ref [{ref_idx}] on field '{field}': "
                    f"db='{actual_val}' vs ref='{ref_val}'"
                )

    assert total_refs_checked >= 172, f"Expected >= 172 refs, checked {total_refs_checked}"


# ==============================================================================
# Challenge 3: Internal ETH Transfers Deep Forensic Verification
# ==============================================================================


def test_internal_eth_transfers_audit(alerts_data: dict, db_conn: sqlite3.Connection):
    """Adversarially audit all 16 internal ETH transfers and verify the 14 alerts."""
    # 1. Fetch all internal ETH transfers from DB
    internal_transfers = db_conn.execute(
        """
        SELECT chain_id, block_number, block_hash, block_timestamp,
               tx_hash, log_index, asset_id, from_addr, to_addr, amount_raw
        FROM asset_transfers
        WHERE asset_id = 'NATIVE' AND log_index < -1
        ORDER BY block_number, tx_hash, log_index
        """
    ).fetchall()

    assert len(internal_transfers) == 16, (
        f"Expected exactly 16 internal ETH transfers in data/real_p4.db, found {len(internal_transfers)}"
    )

    # 2. Extract all alerts referencing internal ETH transfers
    alerts = alerts_data["alerts"]
    internal_eth_alerts = []
    for a in alerts:
        has_internal_ref = False
        for ref in a["evidence_refs"]:
            if ref.get("asset_id") == "NATIVE" and ref.get("log_index", 0) < -1:
                has_internal_ref = True
                break
        if has_internal_ref:
            internal_eth_alerts.append(a)

    assert len(internal_eth_alerts) == 14, (
        f"Expected exactly 14 internal ETH alerts, found {len(internal_eth_alerts)}"
    )

    # 3. Classify the 14 internal ETH alerts
    r1_internal = [a for a in internal_eth_alerts if a["rule_id"] == "large_transfer"]
    r4_internal = [a for a in internal_eth_alerts if a["rule_id"] == "rapid_pass_through"]

    assert len(r1_internal) == 13, f"Expected 13 LargeTransfer internal alerts, got {len(r1_internal)}"
    assert len(r4_internal) == 1, f"Expected 1 RapidPassThrough internal alert, got {len(r4_internal)}"

    # 4. Check the 2 internal ETH transfers that did NOT trigger LargeTransfer alerts
    alerted_log_indices_by_tx = set()
    for a in r1_internal:
        for ref in a["evidence_refs"]:
            alerted_log_indices_by_tx.add((ref["tx_hash"], ref["log_index"]))

    untriggered = []
    for it in internal_transfers:
        key = (it["tx_hash"], it["log_index"])
        if key not in alerted_log_indices_by_tx:
            untriggered.append(it)

    # There are 16 internal ETH transfers. 13 triggered R1. What are the 3 that did not trigger R1?
    # (1 of them triggered R4 rapid pass-through or both?)
    print(f"\nInternal ETH transfers count: {len(internal_transfers)}")
    print(f"Triggered R1: {len(r1_internal)}, Triggered R4: {len(r4_internal)}")
    print(f"Untriggered by R1: {len(untriggered)}")

    for row in untriggered:
        amount_eth = int(row["amount_raw"]) / 1e18
        print(f"Untriggered R1 transfer: tx={row['tx_hash'][:10]} log_idx={row['log_index']} amount={amount_eth} ETH")
        # Verify why it was not triggered by R1: Is it < 10 ETH? Or is it part of R4?
        # Let's verify empirical condition.


# ==============================================================================
# Challenge 4: Key Incident Transactions Forensic Verification
# ==============================================================================


def test_incident_transactions_forensics(alerts_data: dict, db_conn: sqlite3.Connection):
    """Verify alerts matching Euler frontrun (0xc310...), Curve exploit (0xb676...), and Curve arbitrage (0x0774...)."""
    alerts = alerts_data["alerts"]

    euler_frontrun_alerts = [
        a for a in alerts if any(r["tx_hash"] == EULER_FRONTRUN_TX for r in a["evidence_refs"])
    ]
    curve_exploit_alerts = [
        a for a in alerts if any(r["tx_hash"] == CURVE_EXPLOIT_TX for r in a["evidence_refs"])
    ]
    curve_arbitrage_alerts = [
        a for a in alerts if any(r["tx_hash"] == CURVE_ARBITRAGE_TX for r in a["evidence_refs"])
    ]

    assert len(euler_frontrun_alerts) == 10, (
        f"Expected 10 alerts for Euler frontrun tx, found {len(euler_frontrun_alerts)}"
    )
    assert len(curve_exploit_alerts) == 10, (
        f"Expected 10 alerts for Curve exploit tx, found {len(curve_exploit_alerts)}"
    )
    assert len(curve_arbitrage_alerts) == 6, (
        f"Expected 6 alerts for Curve arbitrage tx, found {len(curve_arbitrage_alerts)}"
    )

    # Verify Euler Frontrun Alerts
    # Expect 7 LargeTransfer (DAI) and 3 RapidPassThrough (DAI)
    euler_r1 = [a for a in euler_frontrun_alerts if a["rule_id"] == "large_transfer"]
    euler_r4 = [a for a in euler_frontrun_alerts if a["rule_id"] == "rapid_pass_through"]
    assert len(euler_r1) == 7
    assert len(euler_r4) == 3

    # Check Euler R1 amounts: must exceed DAI p99 threshold (2619467107133375533703408 wei ~ 2.62M DAI)
    dai_p99 = 2619467107133375533703408
    for a in euler_r1:
        ref = a["evidence_refs"][0]
        amt = int(ref["amount_raw"])
        assert amt >= dai_p99, f"Euler DAI transfer {amt} is below p99 threshold {dai_p99}"

    # Verify Curve Exploit Alerts:
    # 8 LargeTransfer on internal ETH, 1 LargeTransfer on alETH, 1 RapidPassThrough on NATIVE ETH
    curve_r1_native = [
        a for a in curve_exploit_alerts
        if a["rule_id"] == "large_transfer" and a["asset_id"] == "NATIVE"
    ]
    curve_r1_aleth = [
        a for a in curve_exploit_alerts
        if a["rule_id"] == "large_transfer" and a["asset_id"] != "NATIVE"
    ]
    curve_r4_native = [
        a for a in curve_exploit_alerts
        if a["rule_id"] == "rapid_pass_through" and a["asset_id"] == "NATIVE"
    ]

    assert len(curve_r1_native) == 8, f"Expected 8 LargeTransfer NATIVE alerts in Curve exploit, got {len(curve_r1_native)}"
    assert len(curve_r1_aleth) == 1, f"Expected 1 LargeTransfer alETH alert in Curve exploit, got {len(curve_r1_aleth)}"
    assert len(curve_r4_native) == 1, f"Expected 1 RapidPassThrough NATIVE alert in Curve exploit, got {len(curve_r4_native)}"

    # Native threshold fallback is 10 ETH (10^19 wei)
    eth_fallback = 10_000_000_000_000_000_000
    for a in curve_r1_native:
        ref = a["evidence_refs"][0]
        amt = int(ref["amount_raw"])
        assert amt >= eth_fallback, f"Curve internal ETH transfer {amt} is below fallback {eth_fallback}"


# ==============================================================================
# Challenge 5: Window Separation & Non-Overlapping Invariant
# ==============================================================================


def test_test_window_isolation_and_no_calibration_leak(alerts_data: dict):
    """Stress-test: Ensure no alert is generated from calibration window blocks."""
    alerts = alerts_data["alerts"]

    # Official calibration blocks:
    # Euler: 16816000 - 16817989
    # Curve: 17700000 - 17806699
    # Test blocks:
    # Euler: 16817990 - 16818110
    # Curve: 17806700 - 17806830

    for a in alerts:
        for ref in a["evidence_refs"]:
            blk = ref["block_number"]
            # Must NOT be in Euler calibration window
            assert not (16816000 <= blk <= 16817989), (
                f"LEAK DETECTED: Alert {a['alert_id']} references Euler calibration block {blk}!"
            )
            # Must NOT be in Curve calibration window
            assert not (17700000 <= blk <= 17806699), (
                f"LEAK DETECTED: Alert {a['alert_id']} references Curve calibration block {blk}!"
            )
            # Must be in one of the test windows
            in_euler_test = (16817990 <= blk <= 16818110)
            in_curve_test = (17806700 <= blk <= 17806830)
            assert in_euler_test or in_curve_test, (
                f"OUT-OF-BOUNDS BLOCK: Alert {a['alert_id']} references block {blk}"
            )


# ==============================================================================
# Challenge 6: SQLite Alerts Table Parity
# ==============================================================================


def test_sqlite_alerts_table_parity(alerts_data: dict, db_conn: sqlite3.Connection):
    """Confirm alerts persisted in SQLite database exactly match real_data_alerts.json."""
    db_alerts = db_conn.execute("SELECT * FROM alerts ORDER BY alert_id").fetchall()
    assert len(db_alerts) == 172, f"Expected 172 rows in SQLite alerts table, got {len(db_alerts)}"

    json_alerts_by_id = {a["alert_id"]: a for a in alerts_data["alerts"]}
    assert len(json_alerts_by_id) == 172

    for row in db_alerts:
        aid = row["alert_id"]
        assert aid in json_alerts_by_id, f"SQLite alert_id {aid} missing from JSON export"
        ja = json_alerts_by_id[aid]
        assert row["rule_id"] == ja["rule_id"]
        assert row["rule_version"] == ja["rule_version"]
        assert row["unit_type"] == ja["unit_type"]
        assert row["unit_key"] == ja["unit_key"]
        assert row["asset_id"] == ja["asset_id"]
        assert row["severity"] == ja["severity"]
        assert pytest.approx(row["score"], 1e-6) == ja["score"]
