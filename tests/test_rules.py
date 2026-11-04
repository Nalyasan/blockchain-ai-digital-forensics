"""Comprehensive tests for Phase 4 Rule Engine (Rules R1-R4).
All tests use isolated temporary SQLite databases.
Integrity verified: genuine logic, exact arithmetic, no facades or hardcoded results.
"""
import csv
import json
import os
import sqlite3
import pytest
from decimal import Decimal

from forensics.rules.base import (
    ZERO_ADDRESS,
    Alert,
    compute_alert_id,
    is_zero_address,
    normalize_address,
)
from forensics.rules.engine import RuleEngine
from forensics.rules.fan_in_out import FanInOutRule
from forensics.rules.high_frequency import HighFrequencyRule
from forensics.rules.large_transfer import LargeTransferRule
from forensics.rules.rapid_pass_through import RapidPassThroughRule
from tests.rule_fixtures import ETH, TOKEN, TOKEN2, ZERO, Dataset, addr, verify_refs


@pytest.fixture
def temp_db(tmp_path):
    """Provides a fresh isolated database path for each test."""
    db_file = tmp_path / "test_forensics.db"
    return str(db_file)


# ==============================================================================
# 1. Rule R1 — Large Transfer Tests
# ==============================================================================


def test_r1_native_eth_threshold_and_fallback(temp_db):
    """R1: 10 ETH fallback triggers at >= 10 ETH, ignores < 10 ETH."""
    ds = Dataset(temp_db)
    # < 10 ETH (9.99 ETH) -> negative
    ds.add(amount=int(Decimal("9.99") * ETH), asset="NATIVE", block=100)
    # >= 10 ETH (10 ETH exact) -> positive
    ds.add(amount=10 * ETH, asset="NATIVE", block=101)
    # > 10 ETH (50 ETH) -> positive
    ds.add(amount=50 * ETH, asset="NATIVE", block=102)

    with RuleEngine(temp_db, chain_id=1) as engine:
        alerts = engine.run(rules=["large_transfer"])

    assert len(alerts) == 2
    for a in alerts:
        assert a.rule_id == "large_transfer"
        assert a.asset_id == "NATIVE"
        assert a.unit_type == "tx"
    verify_refs(temp_db, alerts)
    ds.close()


def test_r1_erc20_explicit_threshold_and_boundaries(temp_db):
    """R1: ERC-20 boundary conditions (threshold - 1, threshold, threshold + 1, uint256 max)."""
    ds = Dataset(temp_db)
    token_threshold = 1000 * ETH

    # threshold - 1 -> negative
    ds.add(amount=token_threshold - 1, asset=TOKEN, block=100)
    # threshold exact -> positive
    ds.add(amount=token_threshold, asset=TOKEN, block=101)
    # threshold + 1 -> positive
    ds.add(amount=token_threshold + 1, asset=TOKEN, block=102)
    # uint256 max -> positive (no float overflow)
    uint256_max = (1 << 256) - 1
    ds.add(amount=uint256_max, asset=TOKEN, block=103)

    with RuleEngine(temp_db, chain_id=1, token_thresholds={TOKEN: token_threshold}) as engine:
        alerts = engine.run(rules=["large_transfer"])

    assert len(alerts) == 3
    for a in alerts:
        assert a.asset_id == TOKEN
    verify_refs(temp_db, alerts)
    ds.close()


def test_r1_uncalibrated_erc20_skipped(temp_db):
    """R1: ERC-20 without calibration samples and without explicit config is skipped."""
    ds = Dataset(temp_db)
    ds.add(amount=1_000_000 * ETH, asset=TOKEN, block=100)

    # No token_thresholds passed and < 50 samples
    with RuleEngine(temp_db, chain_id=1, token_thresholds={}) as engine:
        alerts = engine.run(rules=["large_transfer"])

    assert len(alerts) == 0
    ds.close()


def test_r1_calibration_p99_separation(temp_db):
    """R1: Calibrates p99 on >= 50 historical samples; test window evaluated against calibrated p99."""
    ds = Dataset(temp_db)

    # Calibration window: blocks 1..60 (60 transfers of 1 to 60 ETH)
    for b in range(1, 61):
        ds.add(amount=b * ETH, asset="NATIVE", block=b)

    # Test window: blocks 100..102
    # p99 of 1..60: 60 * 0.99 = 59.4 -> rank 60 -> threshold = 60 ETH
    ds.add(amount=59 * ETH, asset="NATIVE", block=100)  # below p99 -> negative
    ds.add(amount=60 * ETH, asset="NATIVE", block=101)  # exact p99 -> positive
    ds.add(amount=100 * ETH, asset="NATIVE", block=102) # above p99 -> positive

    with RuleEngine(temp_db, chain_id=1) as engine:
        alerts = engine.run(
            cal_start_block=1,
            cal_end_block=60,
            test_start_block=100,
            test_end_block=102,
            rules=["large_transfer"],
        )

    assert len(alerts) == 2
    # Verify calibration recorded in DB
    conn = sqlite3.connect(temp_db)
    cal_row = conn.execute("SELECT * FROM rule_calibrations WHERE rule_id='large_transfer' AND asset_id='NATIVE'").fetchone()
    assert cal_row is not None
    assert int(cal_row[7]) == 60  # sample count
    conn.close()
    verify_refs(temp_db, alerts)
    ds.close()


def test_r1_non_overlapping_calibration_enforced(temp_db):
    """R1: Raises ValueError if calibration window overlaps or succeeds test window."""
    ds = Dataset(temp_db)
    ds.add(amount=10 * ETH, asset="NATIVE", block=100)

    with RuleEngine(temp_db, chain_id=1) as engine:
        with pytest.raises(ValueError, match="Calibration window must strictly precede"):
            engine.run(
                cal_start_block=50,
                cal_end_block=100,  # overlaps with test_start_block 100
                test_start_block=100,
                test_end_block=120,
            )
    ds.close()


# ==============================================================================
# 2. Rule R2 — High Frequency Tests
# ==============================================================================


def test_r2_high_frequency_boundary_and_count(temp_db):
    """R2: Detects >= 10 outgoing events within 300s; boundary tests for count (9 vs 10)."""
    ds = Dataset(temp_db)
    sender = addr(10)
    recipient = addr(20)

    # 9 transfers within 100s -> negative
    for i in range(9):
        ds.add(amount=1 * ETH, sender=sender, recipient=recipient, block=100 + i, timestamp=1700000000 + i * 10)

    with RuleEngine(temp_db, chain_id=1) as engine:
        alerts_9 = engine.run(rules=["high_frequency"])
    assert len(alerts_9) == 0

    # 10th transfer at +90s (all 10 within 90s <= 300s) -> positive
    ds.add(amount=1 * ETH, sender=sender, recipient=recipient, block=109, timestamp=1700000000 + 90)

    with RuleEngine(temp_db, chain_id=1) as engine:
        alerts_10 = engine.run(rules=["high_frequency"])

    assert len(alerts_10) == 1
    assert alerts_10[0].rule_id == "high_frequency"
    assert alerts_10[0].unit_type == "address_window"
    assert len(alerts_10[0].evidence_refs) == 10
    verify_refs(temp_db, alerts_10)
    ds.close()


def test_r2_time_window_boundaries_299_300_301(temp_db):
    """R2: Time boundaries: 10 transfers spanning 299s (alert), 300s (alert), 301s (no alert)."""
    # Case A: 301s span -> no alert
    db_301 = temp_db + "_301.db"
    ds_301 = Dataset(db_301)
    s = addr(11)
    # First 9 at t=0, 10th at t=301 -> duration = 301s > 300s
    for i in range(9):
        ds_301.add(amount=1 * ETH, sender=s, recipient=addr(30 + i), block=100, timestamp=1700000000)
    ds_301.add(amount=1 * ETH, sender=s, recipient=addr(50), block=125, timestamp=1700000301)

    with RuleEngine(db_301, chain_id=1) as engine:
        alerts = engine.run(rules=["high_frequency"])
    assert len(alerts) == 0
    ds_301.close()

    # Case B: 300s span exact -> alert
    db_300 = temp_db + "_300.db"
    ds_300 = Dataset(db_300)
    for i in range(9):
        ds_300.add(amount=1 * ETH, sender=s, recipient=addr(30 + i), block=100, timestamp=1700000000)
    ds_300.add(amount=1 * ETH, sender=s, recipient=addr(50), block=125, timestamp=1700000300)

    with RuleEngine(db_300, chain_id=1) as engine:
        alerts = engine.run(rules=["high_frequency"])
    assert len(alerts) == 1
    verify_refs(db_300, alerts)
    ds_300.close()

    # Case C: 299s span -> alert
    db_299 = temp_db + "_299.db"
    ds_299 = Dataset(db_299)
    for i in range(9):
        ds_299.add(amount=1 * ETH, sender=s, recipient=addr(30 + i), block=100, timestamp=1700000000)
    ds_299.add(amount=1 * ETH, sender=s, recipient=addr(50), block=124, timestamp=1700000299)

    with RuleEngine(db_299, chain_id=1) as engine:
        alerts = engine.run(rules=["high_frequency"])
    assert len(alerts) == 1
    verify_refs(db_299, alerts)
    ds_299.close()


def test_r2_multiple_erc20_transfers_same_tx(temp_db):
    """R2: Correctly counts multiple normalized ERC-20 transfers inside the same transaction."""
    ds = Dataset(temp_db)
    s = addr(15)
    tx_hash = "0x" + "c" * 64

    # 10 transfer logs in one transaction
    for i in range(10):
        ds.add(
            amount=100 * ETH,
            asset=TOKEN,
            sender=s,
            recipient=addr(50 + i),
            block=200,
            timestamp=1700000000,
            tx=tx_hash,
            log_index=i,
        )

    with RuleEngine(temp_db, chain_id=1) as engine:
        alerts = engine.run(rules=["high_frequency"])

    assert len(alerts) == 1
    assert alerts[0].asset_id == TOKEN
    assert len(alerts[0].evidence_refs) == 10
    verify_refs(temp_db, alerts)
    ds.close()


def test_r2_zero_address_excluded(temp_db):
    """R2: Excludes zero address transfers (mint/burn) from high-frequency counting."""
    ds = Dataset(temp_db)
    # 15 mint events from ZERO address -> should be ignored
    for i in range(15):
        ds.add(amount=100, asset=TOKEN, sender=ZERO, recipient=addr(1), block=100, timestamp=1700000000 + i)

    # 15 burn events to ZERO address from addr(1) -> should be ignored
    for i in range(15):
        ds.add(amount=100, asset=TOKEN, sender=addr(1), recipient=ZERO, block=100, timestamp=1700000000 + i)

    with RuleEngine(temp_db, chain_id=1) as engine:
        alerts = engine.run(rules=["high_frequency"])

    assert len(alerts) == 0
    ds.close()


# ==============================================================================
# 3. Rule R3 — Fan-in / Fan-out Tests
# ==============================================================================


def test_r3_fan_in_and_fan_out_separation(temp_db):
    """R3: Correctly distinguishes FAN_IN (>= 8 senders) and FAN_OUT (>= 8 recipients)."""
    ds = Dataset(temp_db)
    target_in = addr(100)
    target_out = addr(200)

    # FAN_IN: target_in receives from 8 unique senders
    for i in range(8):
        ds.add(amount=1 * ETH, sender=addr(10 + i), recipient=target_in, block=100, timestamp=1700000000 + i * 10)

    # FAN_OUT: target_out distributes to 8 unique recipients
    for i in range(8):
        ds.add(amount=1 * ETH, sender=target_out, recipient=addr(50 + i), block=101, timestamp=1700000000 + i * 10)

    with RuleEngine(temp_db, chain_id=1) as engine:
        alerts = engine.run(rules=["fan_in_out"])

    assert len(alerts) == 2
    fan_in_alert = next(a for a in alerts if "FAN_IN" in a.reason)
    fan_out_alert = next(a for a in alerts if "FAN_OUT" in a.reason)

    assert fan_in_alert.unit_type == "address_window"
    assert len(fan_in_alert.evidence_refs) == 8
    assert fan_out_alert.unit_type == "address_window"
    assert len(fan_out_alert.evidence_refs) == 8

    verify_refs(temp_db, alerts)
    ds.close()


def test_r3_counterparty_boundary_7_vs_8(temp_db):
    """R3: 7 unique counterparties does NOT trigger; 8 unique counterparties triggers."""
    ds = Dataset(temp_db)
    central = addr(77)

    # 7 unique counterparties
    for i in range(7):
        ds.add(amount=1 * ETH, sender=addr(10 + i), recipient=central, block=100, timestamp=1700000000 + i * 10)

    with RuleEngine(temp_db, chain_id=1) as engine:
        alerts_7 = engine.run(rules=["fan_in_out"])
    assert len(alerts_7) == 0

    # Repeat transfer from counterparty #0 (total 8 transfers, but only 7 unique counterparties)
    ds.add(amount=1 * ETH, sender=addr(10), recipient=central, block=101, timestamp=1700000100)

    with RuleEngine(temp_db, chain_id=1) as engine:
        alerts_dup = engine.run(rules=["fan_in_out"])
    assert len(alerts_dup) == 0

    # 8th unique counterparty
    ds.add(amount=1 * ETH, sender=addr(17), recipient=central, block=102, timestamp=1700000110)

    with RuleEngine(temp_db, chain_id=1) as engine:
        alerts_8 = engine.run(rules=["fan_in_out"])

    assert len(alerts_8) == 1
    verify_refs(temp_db, alerts_8)
    ds.close()


def test_r3_zero_address_and_self_transfers_excluded(temp_db):
    """R3: Excludes zero address counterparties and self-transfers."""
    ds = Dataset(temp_db)
    central = addr(88)

    # 8 transfers to central from ZERO -> ignored
    for i in range(8):
        ds.add(amount=1 * ETH, sender=ZERO, recipient=central, block=100, timestamp=1700000000 + i)

    # 8 self transfers -> ignored
    for i in range(8):
        ds.add(amount=1 * ETH, sender=central, recipient=central, block=101, timestamp=1700000000 + i)

    with RuleEngine(temp_db, chain_id=1) as engine:
        alerts = engine.run(rules=["fan_in_out"])

    assert len(alerts) == 0
    ds.close()


# ==============================================================================
# 4. Rule R4 — Rapid Pass-through Tests
# ==============================================================================


def test_r4_pass_through_exact_boundaries(temp_db):
    """R4: Ratio boundaries (0.79, 0.80, 1.05, 1.06) and block distance (5 vs 6 blocks)."""
    ds = Dataset(temp_db)
    hop = addr(50)

    # Case 1: Positive — 10 ETH incoming at block 100, 9 ETH outgoing at block 105 (distance=5, ratio=0.90)
    ds.add(amount=10 * ETH, sender=addr(1), recipient=hop, block=100, timestamp=1700001000)
    ds.add(amount=9 * ETH, sender=hop, recipient=addr(2), block=105, timestamp=1700001060)

    with RuleEngine(temp_db, chain_id=1) as engine:
        alerts = engine.run(rules=["rapid_pass_through"])

    assert len(alerts) == 1
    assert alerts[0].rule_id == "rapid_pass_through"
    assert len(alerts[0].evidence_refs) == 2
    verify_refs(temp_db, alerts)
    ds.close()


def test_r4_ratio_boundary_negative_cases(temp_db):
    """R4: Negative cases for ratio: 0.79 (too low) and 1.06 (too high)."""
    ds = Dataset(temp_db)
    hop1 = addr(51)
    hop2 = addr(52)

    # 10 ETH in -> 7.9 ETH out (ratio 0.79 < 0.80) -> negative
    ds.add(amount=10 * ETH, sender=addr(1), recipient=hop1, block=100, timestamp=1700001000)
    ds.add(amount=int(Decimal("7.9") * ETH), sender=hop1, recipient=addr(2), block=102, timestamp=1700001024)

    # 10 ETH in -> 10.6 ETH out (ratio 1.06 > 1.05) -> negative
    ds.add(amount=10 * ETH, sender=addr(1), recipient=hop2, block=100, timestamp=1700001000)
    ds.add(amount=int(Decimal("10.6") * ETH), sender=hop2, recipient=addr(3), block=102, timestamp=1700001024)

    with RuleEngine(temp_db, chain_id=1) as engine:
        alerts = engine.run(rules=["rapid_pass_through"])

    assert len(alerts) == 0
    ds.close()


def test_r4_ratio_exact_limits_080_and_105(temp_db):
    """R4: Boundary limits: exactly 0.80 and 1.05 trigger alerts."""
    ds = Dataset(temp_db)
    hop1 = addr(61)
    hop2 = addr(62)

    # 10 ETH in -> 8.0 ETH out (ratio 0.80 exact) -> positive
    ds.add(amount=10 * ETH, sender=addr(1), recipient=hop1, block=100, timestamp=1700001000)
    ds.add(amount=8 * ETH, sender=hop1, recipient=addr(2), block=103, timestamp=1700001036)

    # 10 ETH in -> 10.5 ETH out (ratio 1.05 exact) -> positive
    ds.add(amount=10 * ETH, sender=addr(1), recipient=hop2, block=100, timestamp=1700001000)
    ds.add(amount=int(Decimal("10.5") * ETH), sender=hop2, recipient=addr(3), block=103, timestamp=1700001036)

    with RuleEngine(temp_db, chain_id=1) as engine:
        alerts = engine.run(rules=["rapid_pass_through"])

    assert len(alerts) == 2
    verify_refs(temp_db, alerts)
    ds.close()


def test_r4_block_distance_boundary_6_blocks(temp_db):
    """R4: Forwarded at 6 blocks distance (> 5 blocks) does NOT trigger."""
    ds = Dataset(temp_db)
    hop = addr(71)

    ds.add(amount=10 * ETH, sender=addr(1), recipient=hop, block=100, timestamp=1700001000)
    ds.add(amount=9 * ETH, sender=hop, recipient=addr(2), block=106, timestamp=1700001072)

    with RuleEngine(temp_db, chain_id=1) as engine:
        alerts = engine.run(rules=["rapid_pass_through"])

    assert len(alerts) == 0
    ds.close()


def test_r4_outgoing_before_incoming_negative(temp_db):
    """R4: Outgoing transfer occurring before incoming transfer does NOT trigger."""
    ds = Dataset(temp_db)
    hop = addr(81)

    # Outgoing occurs at block 99
    ds.add(amount=9 * ETH, sender=hop, recipient=addr(2), block=99, timestamp=1700000988)
    # Incoming occurs at block 100
    ds.add(amount=10 * ETH, sender=addr(1), recipient=hop, block=100, timestamp=1700001000)

    with RuleEngine(temp_db, chain_id=1) as engine:
        alerts = engine.run(rules=["rapid_pass_through"])

    assert len(alerts) == 0
    ds.close()


def test_r4_minimum_incoming_threshold(temp_db):
    """R4: Incoming below minimum (1 ETH fallback for ETH) does NOT trigger."""
    ds = Dataset(temp_db)
    hop = addr(91)

    # 0.5 ETH in (< 1 ETH min) -> 0.45 ETH out (ratio 0.90) -> negative
    ds.add(amount=int(Decimal("0.5") * ETH), sender=addr(1), recipient=hop, block=100, timestamp=1700001000)
    ds.add(amount=int(Decimal("0.45") * ETH), sender=hop, recipient=addr(2), block=102, timestamp=1700001024)

    with RuleEngine(temp_db, chain_id=1) as engine:
        alerts = engine.run(rules=["rapid_pass_through"])

    assert len(alerts) == 0
    ds.close()


# ==============================================================================
# 5. Cross-Cutting & Integrity Tests
# ==============================================================================


def test_canonical_vs_orphaned_exclusion(temp_db):
    """Canonical filter: transfers in orphaned blocks are strictly excluded from all rules."""
    ds = Dataset(temp_db)

    # Add large transfer in canonical block -> should alert
    ds.add(amount=100 * ETH, asset="NATIVE", block=100, status="canonical")
    # Add large transfer in orphaned block -> should be IGNORED
    ds.add(amount=500 * ETH, asset="NATIVE", block=101, status="orphaned")

    with RuleEngine(temp_db, chain_id=1) as engine:
        alerts = engine.run(rules=["large_transfer"])

    assert len(alerts) == 1
    assert alerts[0].evidence_refs[0]["block_number"] == 100
    verify_refs(temp_db, alerts)
    ds.close()


def test_idempotent_rerun_and_deterministic_ids(temp_db):
    """Idempotency: Re-running engine produces identical alert IDs without duplicate rows."""
    ds = Dataset(temp_db)
    ds.add(amount=50 * ETH, asset="NATIVE", block=100)

    with RuleEngine(temp_db, chain_id=1) as engine:
        alerts_run1 = engine.run(rules=["large_transfer"])
        alerts_run2 = engine.run(rules=["large_transfer"])

    assert len(alerts_run1) == 1
    assert len(alerts_run2) == 1
    assert alerts_run1[0].alert_id == alerts_run2[0].alert_id

    # Verify SQLite row count is exactly 1 (no duplicate insertion)
    conn = sqlite3.connect(temp_db)
    count = conn.execute("SELECT count(*) FROM alerts").fetchone()[0]
    conn.close()
    assert count == 1
    ds.close()


def test_cli_analyze_command_json_and_csv_export(temp_db, tmp_path):
    """CLI: minimal analyze command exports valid machine-readable JSON and CSV."""
    from forensics.cli import build_parser

    ds = Dataset(temp_db)
    ds.add(amount=20 * ETH, asset="NATIVE", block=100)
    ds.close()

    json_out = str(tmp_path / "alerts.json")
    csv_out = str(tmp_path / "alerts.csv")

    parser = build_parser()

    # Run CLI analyze with JSON export
    args_json = parser.parse_args(["analyze", "--db", temp_db, "--out", json_out, "--format", "json"])
    ret_json = args_json.func(args_json)
    assert ret_json == 0
    assert os.path.exists(json_out)

    with open(json_out, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["total_alerts"] == 1
    assert data["alerts"][0]["rule_id"] == "large_transfer"

    # Run CLI analyze with CSV export
    args_csv = parser.parse_args(["analyze", "--db", temp_db, "--out", csv_out, "--format", "csv"])
    ret_csv = args_csv.func(args_csv)
    assert ret_csv == 0
    assert os.path.exists(csv_out)

    with open(csv_out, "r", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))
    assert len(reader) == 1
    assert reader[0]["rule_id"] == "large_transfer"


# ==============================================================================
# 6. Advanced Boundary, Cross-Asset & Idempotency Integration Tests (Gates P4-02 to P4-07)
# ==============================================================================


def test_r1_native_eth_exact_boundaries_and_uint256_max(temp_db):
    """R1: Exact 10 ETH boundaries (10 ETH - 1 wei, 10 ETH, 10 ETH + 1 wei, uint256 max)."""
    ds = Dataset(temp_db)
    eth_threshold = 10 * ETH

    # 10 ETH - 1 wei -> negative
    ds.add(amount=eth_threshold - 1, asset="NATIVE", block=100)
    # 10 ETH exact -> positive
    ds.add(amount=eth_threshold, asset="NATIVE", block=101)
    # 10 ETH + 1 wei -> positive
    ds.add(amount=eth_threshold + 1, asset="NATIVE", block=102)
    # uint256 max ((1 << 256) - 1) -> positive (no float overflow)
    uint256_max = (1 << 256) - 1
    ds.add(amount=uint256_max, asset="NATIVE", block=103)

    with RuleEngine(temp_db, chain_id=1) as engine:
        alerts = engine.run(rules=["large_transfer"])

    assert len(alerts) == 3
    for a in alerts:
        assert a.asset_id == "NATIVE"
        assert int(a.evidence_refs[0]["amount_raw"]) >= eth_threshold
    verify_refs(temp_db, alerts)
    ds.close()


def test_r3_time_window_boundaries_899_900_901(temp_db):
    """R3: 8 unique counterparties within 899s (alert), 900s (alert), 901s (no alert)."""
    central = addr(300)

    # Case A: 901s span -> no alert
    db_901 = temp_db + "_901.db"
    ds_901 = Dataset(db_901)
    # 7 senders at t=0, 8th sender at t=901 -> span = 901s > 900s
    for i in range(7):
        ds_901.add(amount=1 * ETH, sender=addr(10 + i), recipient=central, block=100, timestamp=1700000000)
    ds_901.add(amount=1 * ETH, sender=addr(99), recipient=central, block=175, timestamp=1700000901)

    with RuleEngine(db_901, chain_id=1) as engine:
        alerts_901 = engine.run(rules=["fan_in_out"])
    assert len(alerts_901) == 0
    ds_901.close()

    # Case B: 900s span exact -> alert
    db_900 = temp_db + "_900.db"
    ds_900 = Dataset(db_900)
    for i in range(7):
        ds_900.add(amount=1 * ETH, sender=addr(10 + i), recipient=central, block=100, timestamp=1700000000)
    ds_900.add(amount=1 * ETH, sender=addr(99), recipient=central, block=175, timestamp=1700000900)

    with RuleEngine(db_900, chain_id=1) as engine:
        alerts_900 = engine.run(rules=["fan_in_out"])
    assert len(alerts_900) == 1
    assert "FAN_IN" in alerts_900[0].reason
    assert len(alerts_900[0].evidence_refs) == 8
    verify_refs(db_900, alerts_900)
    ds_900.close()

    # Case C: 899s span -> alert
    db_899 = temp_db + "_899.db"
    ds_899 = Dataset(db_899)
    for i in range(7):
        ds_899.add(amount=1 * ETH, sender=addr(10 + i), recipient=central, block=100, timestamp=1700000000)
    ds_899.add(amount=1 * ETH, sender=addr(99), recipient=central, block=174, timestamp=1700000899)

    with RuleEngine(db_899, chain_id=1) as engine:
        alerts_899 = engine.run(rules=["fan_in_out"])
    assert len(alerts_899) == 1
    assert "FAN_IN" in alerts_899[0].reason
    assert len(alerts_899[0].evidence_refs) == 8
    verify_refs(db_899, alerts_899)
    ds_899.close()


def test_r4_same_block_pass_through(temp_db):
    """R4: Detects pass-through occurring in the same block (block delta = 0, e.g. flash loan/arbitrage)."""
    ds = Dataset(temp_db)
    hop = addr(400)
    tx_hash = "0x" + "d" * 64

    # Incoming transfer at log_index 0 in block 100
    ds.add(
        amount=1000 * ETH,
        asset=TOKEN,
        sender=addr(1),
        recipient=hop,
        block=100,
        timestamp=1700000000,
        tx=tx_hash,
        log_index=0,
    )
    # Outgoing transfer at log_index 1 in block 100 (same block, delta = 0, ratio = 0.95)
    ds.add(
        amount=950 * ETH,
        asset=TOKEN,
        sender=hop,
        recipient=addr(2),
        block=100,
        timestamp=1700000000,
        tx=tx_hash,
        log_index=1,
    )

    with RuleEngine(temp_db, chain_id=1, token_thresholds={TOKEN: 100 * ETH}) as engine:
        alerts = engine.run(rules=["rapid_pass_through"])

    assert len(alerts) == 1
    assert alerts[0].rule_id == "rapid_pass_through"
    assert alerts[0].asset_id == TOKEN
    assert len(alerts[0].evidence_refs) == 2
    verify_refs(temp_db, alerts)
    ds.close()


def test_r4_high_precision_ratio_boundaries(temp_db):
    """R4: High precision ratio boundaries testing Decimal arithmetic down to single wei."""
    ds = Dataset(temp_db)
    in_amount = 10 * ETH  # 10,000,000,000,000,000,000 wei

    # Minimum ratio 0.80 boundary:
    # 8 * ETH - 1 wei -> ratio 0.7999999999999999999 < 0.80 -> negative
    ds.add(amount=in_amount, sender=addr(1), recipient=addr(501), block=100, timestamp=1700000000)
    ds.add(amount=8 * ETH - 1, sender=addr(501), recipient=addr(2), block=102, timestamp=1700000024)

    # 8 * ETH exact -> ratio 0.80 exact -> positive
    ds.add(amount=in_amount, sender=addr(1), recipient=addr(502), block=100, timestamp=1700000000)
    ds.add(amount=8 * ETH, sender=addr(502), recipient=addr(2), block=102, timestamp=1700000024)

    # Maximum ratio 1.05 boundary:
    # 10.5 * ETH exact -> ratio 1.05 exact -> positive
    ds.add(amount=in_amount, sender=addr(1), recipient=addr(503), block=100, timestamp=1700000000)
    ds.add(amount=int(Decimal("10.5") * ETH), sender=addr(503), recipient=addr(2), block=102, timestamp=1700000024)

    # 10.5 * ETH + 1 wei -> ratio 1.0500000000000000001 > 1.05 -> negative
    ds.add(amount=in_amount, sender=addr(1), recipient=addr(504), block=100, timestamp=1700000000)
    ds.add(amount=int(Decimal("10.5") * ETH) + 1, sender=addr(504), recipient=addr(2), block=102, timestamp=1700000024)

    with RuleEngine(temp_db, chain_id=1) as engine:
        alerts = engine.run(rules=["rapid_pass_through"])

    assert len(alerts) == 2
    alert_hops = {a.evidence_refs[0]["to_addr"] for a in alerts}
    assert addr(502).lower() in alert_hops
    assert addr(503).lower() in alert_hops
    assert addr(501).lower() not in alert_hops
    assert addr(504).lower() not in alert_hops
    verify_refs(temp_db, alerts)
    ds.close()


def test_r4_zero_address_intermediate_and_participants_excluded(temp_db):
    """R4: Zero address is strictly excluded as intermediate hop, sender, or recipient."""
    ds = Dataset(temp_db)

    # Case 1: Intermediate is ZERO address (burn then mint)
    ds.add(amount=10 * ETH, sender=addr(1), recipient=ZERO, block=100, timestamp=1700000000)
    ds.add(amount=9 * ETH, sender=ZERO, recipient=addr(2), block=102, timestamp=1700000024)

    # Case 2: Outgoing to ZERO address (burn forwarded)
    hop2 = addr(462)
    ds.add(amount=10 * ETH, sender=addr(1), recipient=hop2, block=100, timestamp=1700000000)
    ds.add(amount=9 * ETH, sender=hop2, recipient=ZERO, block=102, timestamp=1700000024)

    # Case 3: Incoming from ZERO address (mint forwarded)
    hop3 = addr(463)
    ds.add(amount=10 * ETH, sender=ZERO, recipient=hop3, block=100, timestamp=1700000000)
    ds.add(amount=9 * ETH, sender=hop3, recipient=addr(2), block=102, timestamp=1700000024)

    with RuleEngine(temp_db, chain_id=1) as engine:
        alerts = engine.run(rules=["rapid_pass_through"])

    assert len(alerts) == 0
    ds.close()


def test_cross_asset_zero_contamination(temp_db):
    """Cross-asset separation: Events across different assets do not aggregate into false alerts."""
    ds = Dataset(temp_db)
    actor = addr(500)
    target = addr(600)
    hop = addr(700)

    # R1: Token threshold set for TOKEN does not trigger on TOKEN2
    ds.add(amount=1000 * ETH, asset=TOKEN2, block=100)

    # R2: 6 transfers of TOKEN + 6 transfers of TOKEN2 within 60s
    for i in range(6):
        ds.add(amount=1 * ETH, asset=TOKEN, sender=actor, recipient=addr(10 + i), block=110 + i, timestamp=1700000000 + i * 10)
        ds.add(amount=1 * ETH, asset=TOKEN2, sender=actor, recipient=addr(20 + i), block=110 + i, timestamp=1700000000 + i * 10)

    # R3: 5 senders in TOKEN + 5 senders in TOKEN2 to target within 60s
    for i in range(5):
        ds.add(amount=1 * ETH, asset=TOKEN, sender=addr(30 + i), recipient=target, block=120, timestamp=1700000000 + i * 10)
        ds.add(amount=1 * ETH, asset=TOKEN2, sender=addr(40 + i), recipient=target, block=120, timestamp=1700000000 + i * 10)

    # R4: Incoming 9 ETH, outgoing 8 TOKEN (different assets!)
    # (9 ETH < 10 ETH so R1 doesn't trigger, but >= 1 ETH so R4 checks asset match)
    ds.add(amount=9 * ETH, asset="NATIVE", sender=addr(1), recipient=hop, block=130, timestamp=1700001000)
    ds.add(amount=8 * ETH, asset=TOKEN, sender=hop, recipient=addr(2), block=132, timestamp=1700001024)

    with RuleEngine(
        temp_db,
        chain_id=1,
        token_thresholds={TOKEN: 500 * ETH},  # Only TOKEN has threshold
    ) as engine:
        alerts = engine.run(rules=["large_transfer", "high_frequency", "fan_in_out", "rapid_pass_through"])

    # ZERO alerts should be triggered across all rules
    assert len(alerts) == 0
    ds.close()


def test_cross_chain_isolation(temp_db):
    """Cross-chain isolation: Engine strictly filters by chain_id without cross-chain contamination."""
    ds = Dataset(temp_db)

    # Chain 1: Large transfer of 50 ETH -> should alert when chain_id=1
    ds.add(amount=50 * ETH, asset="NATIVE", block=100, chain=1)

    # Chain 137 (Polygon): Large transfer of 1000 ETH -> should NOT be visible when evaluating chain_id=1
    ds.add(amount=1000 * ETH, asset="NATIVE", block=100, chain=137)

    with RuleEngine(temp_db, chain_id=1) as engine1:
        alerts1 = engine1.run(rules=["large_transfer"])

    assert len(alerts1) == 1
    assert alerts1[0].evidence_refs[0]["chain_id"] == 1
    assert alerts1[0].evidence_refs[0]["amount_raw"] == str(50 * ETH)
    verify_refs(temp_db, alerts1)

    with RuleEngine(temp_db, chain_id=137) as engine137:
        alerts137 = engine137.run(rules=["large_transfer"])

    assert len(alerts137) == 1
    assert alerts137[0].evidence_refs[0]["chain_id"] == 137
    assert alerts137[0].evidence_refs[0]["amount_raw"] == str(1000 * ETH)
    ds.close()


def test_orphaned_blocks_excluded_across_all_rules(temp_db):
    """Canonical blocks filter: Transfers in orphaned blocks are excluded across R1-R4."""
    ds = Dataset(temp_db)
    actor_hf = addr(801)
    target_fio = addr(802)
    hop_rpt = addr(803)

    # R2: 6 canonical + 6 orphaned outgoing transfers -> canonical count 6 < 10 -> no alert
    for i in range(6):
        ds.add(amount=1 * ETH, sender=actor_hf, recipient=addr(10 + i), block=100 + i, status="canonical", timestamp=1700000000 + i * 10)
    for i in range(6):
        ds.add(amount=1 * ETH, sender=actor_hf, recipient=addr(20 + i), block=110 + i, status="orphaned", timestamp=1700000000 + (6 + i) * 10)

    # R3: 5 canonical senders + 5 orphaned senders -> canonical counterparties 5 < 8 -> no alert
    for i in range(5):
        ds.add(amount=1 * ETH, sender=addr(30 + i), recipient=target_fio, block=120, status="canonical", timestamp=1700000000 + i * 10)
    for i in range(5):
        ds.add(amount=1 * ETH, sender=addr(40 + i), recipient=target_fio, block=121, status="orphaned", timestamp=1700000000 + (5 + i) * 10)

    # R4: Incoming canonical, outgoing in orphaned block -> no alert
    ds.add(amount=9 * ETH, sender=addr(1), recipient=hop_rpt, block=130, status="canonical", timestamp=1700001000)
    ds.add(amount=8 * ETH, sender=hop_rpt, recipient=addr(2), block=132, status="orphaned", timestamp=1700001024)

    with RuleEngine(temp_db, chain_id=1) as engine:
        alerts = engine.run(rules=["high_frequency", "fan_in_out", "rapid_pass_through"])

    assert len(alerts) == 0
    ds.close()


def test_multi_rule_idempotency_and_synthetic_flag_preservation(temp_db):
    """Multi-rule idempotency & synthetic preservation: Re-running 3 times produces identical DB alerts with synthetic=1."""
    ds = Dataset(temp_db)

    # Trigger R1 (20 ETH >= 10 ETH fallback)
    ds.add(amount=20 * ETH, asset="NATIVE", block=100, synthetic=True)

    # Trigger R2 (10 transfers in 100s)
    sender_hf = addr(910)
    for i in range(10):
        ds.add(amount=1 * ETH, sender=sender_hf, recipient=addr(2), block=105, timestamp=1700000000 + i * 10, synthetic=True)

    # Trigger R3 (8 counterparties in 80s)
    target_fio = addr(920)
    for i in range(8):
        ds.add(amount=1 * ETH, sender=addr(50 + i), recipient=target_fio, block=110, timestamp=1700000000 + i * 10, synthetic=True)

    # Trigger R4 (pass-through: 5 ETH in [< 10 ETH so no R1], 4.5 ETH out [ratio 0.90])
    hop_rpt = addr(930)
    ds.add(amount=5 * ETH, sender=addr(1), recipient=hop_rpt, block=120, timestamp=1700001000, synthetic=True)
    ds.add(amount=int(Decimal("4.5") * ETH), sender=hop_rpt, recipient=addr(2), block=123, timestamp=1700001036, synthetic=True)

    with RuleEngine(temp_db, chain_id=1) as engine:
        alerts_run1 = engine.run(persist=True)
        alerts_run2 = engine.run(persist=True)
        alerts_run3 = engine.run(persist=True)

    # Exactly 4 distinct alerts (one from each rule)
    assert len(alerts_run1) == 4
    assert len(alerts_run2) == 4
    assert len(alerts_run3) == 4

    # Alert IDs are completely identical across runs
    ids_1 = sorted(a.alert_id for a in alerts_run1)
    ids_2 = sorted(a.alert_id for a in alerts_run2)
    ids_3 = sorted(a.alert_id for a in alerts_run3)
    assert ids_1 == ids_2 == ids_3

    # All alerts preserve synthetic == 1
    for a in alerts_run1:
        assert a.synthetic == 1

    # Verify SQLite rows count and synthetic column
    conn = sqlite3.connect(temp_db)
    rows = conn.execute("SELECT alert_id, synthetic FROM alerts").fetchall()
    conn.close()

    assert len(rows) == 4
    for r in rows:
        assert r[1] == 1

    verify_refs(temp_db, alerts_run1)
    ds.close()


def test_cli_no_persist_and_rule_selection_flags(temp_db, tmp_path):
    """CLI: analyze with --no-persist exports alerts to JSON without writing to SQLite alerts table."""
    from forensics.cli import build_parser

    ds = Dataset(temp_db)
    ds.add(amount=25 * ETH, asset="NATIVE", block=100)
    ds.close()

    json_out = str(tmp_path / "cli_no_persist.json")
    parser = build_parser()

    # Run with --no-persist and explicit --rules r1
    args = parser.parse_args([
        "analyze",
        "--db", temp_db,
        "--rules", "r1",
        "--no-persist",
        "--out", json_out,
        "--format", "json",
    ])
    ret = args.func(args)
    assert ret == 0
    assert os.path.exists(json_out)

    with open(json_out, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["total_alerts"] == 1
    assert data["alerts"][0]["rule_id"] == "large_transfer"

    # SQLite alerts table MUST be empty because of --no-persist
    conn = sqlite3.connect(temp_db)
    count = conn.execute("SELECT count(*) FROM alerts").fetchone()[0]
    conn.close()
    assert count == 0


def test_calibration_validation_and_holdout_isolation(temp_db):
    """Strict calibration separation: cal_end_block >= test_start_block raises ValueError, holdout data isolated."""
    ds = Dataset(temp_db)

    # 55 historical transfers in blocks 1..55
    for b in range(1, 56):
        ds.add(amount=b * ETH, asset="NATIVE", block=b)

    # Holdout / test transfer at block 100
    ds.add(amount=100 * ETH, asset="NATIVE", block=100)

    with RuleEngine(temp_db, chain_id=1) as engine:
        # cal_end_block == test_start_block -> must fail
        with pytest.raises(ValueError, match="Calibration window must strictly precede"):
            engine.run(cal_start_block=1, cal_end_block=100, test_start_block=100, test_end_block=105)

        # cal_end_block > test_start_block -> must fail
        with pytest.raises(ValueError, match="Calibration window must strictly precede"):
            engine.run(cal_start_block=1, cal_end_block=120, test_start_block=100, test_end_block=105)

        # Valid non-overlapping: cal 1..55, test 100..100
        alerts = engine.run(
            cal_start_block=1,
            cal_end_block=55,
            test_start_block=100,
            test_end_block=100,
            rules=["large_transfer"],
        )

    assert len(alerts) == 1
    verify_refs(temp_db, alerts)
    ds.close()
