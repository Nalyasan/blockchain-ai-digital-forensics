"""Phase 4 Smoke Test Runner: Rule Engine (R1-R4), Calibration, Persistence & CLI.
Executes end-to-end anomaly detection on isolated temporary databases.
Verifies all gates for Phase 4 rule engine implementation.
"""
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from decimal import Decimal
from pathlib import Path

# Add project root to sys.path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from forensics.rules.base import compute_alert_id
from forensics.rules.engine import RuleEngine
from forensics.rules.fan_in_out import FanInOutRule
from forensics.rules.high_frequency import HighFrequencyRule
from forensics.rules.large_transfer import LargeTransferRule
from forensics.rules.rapid_pass_through import RapidPassThroughRule
from tests.rule_fixtures import ETH, TOKEN, ZERO, Dataset, addr, verify_refs


def test_smoke_r1_large_transfer(temp_dir: str):
    print("-> Testing R1: Large Transfer...")
    db_path = os.path.join(temp_dir, "r1.db")
    ds = Dataset(db_path)
    # Native ETH: 10 ETH fallback
    ds.add(amount=5 * ETH, asset="NATIVE", block=10)   # below -> no alert
    ds.add(amount=10 * ETH, asset="NATIVE", block=11)  # exact -> alert
    ds.add(amount=25 * ETH, asset="NATIVE", block=12)  # above -> alert

    # ERC-20: explicit threshold 500 tokens
    thresh = 500 * ETH
    ds.add(amount=499 * ETH, asset=TOKEN, block=20)    # below -> no alert
    ds.add(amount=500 * ETH, asset=TOKEN, block=21)    # exact -> alert

    with RuleEngine(db_path, chain_id=1, token_thresholds={TOKEN: thresh}) as engine:
        alerts = engine.run(rules=["large_transfer"])

    assert len(alerts) == 3, f"Expected 3 alerts for R1, got {len(alerts)}"
    verify_refs(db_path, alerts)
    ds.close()
    print("   [PASS] R1 Large Transfer correctly detects ETH and ERC-20 thresholds")


def test_smoke_r2_high_frequency(temp_dir: str):
    print("-> Testing R2: High Frequency...")
    db_path = os.path.join(temp_dir, "r2.db")
    ds = Dataset(db_path)
    sender = addr(1)
    recipient = addr(2)

    # 10 outgoing events within 200s (window = 300s)
    for i in range(10):
        ds.add(amount=1 * ETH, sender=sender, recipient=recipient, block=100 + i, timestamp=1700000000 + i * 20)

    with RuleEngine(db_path, chain_id=1) as engine:
        alerts = engine.run(rules=["high_frequency"])

    assert len(alerts) == 1, f"Expected 1 alert for R2, got {len(alerts)}"
    assert alerts[0].rule_id == "high_frequency"
    assert len(alerts[0].evidence_refs) == 10
    verify_refs(db_path, alerts)
    ds.close()
    print("   [PASS] R2 High Frequency correctly detects 10 events in rolling 300s window")


def test_smoke_r3_fan_in_out(temp_dir: str):
    print("-> Testing R3: Fan-in / Fan-out...")
    db_path = os.path.join(temp_dir, "r3.db")
    ds = Dataset(db_path)
    collector = addr(10)
    distributor = addr(20)

    # FAN_IN: collector receives from 8 unique counterparties
    for i in range(8):
        ds.add(amount=1 * ETH, sender=addr(100 + i), recipient=collector, block=100, timestamp=1700000000 + i * 10)

    # FAN_OUT: distributor sends to 8 unique counterparties
    for i in range(8):
        ds.add(amount=1 * ETH, sender=distributor, recipient=addr(200 + i), block=101, timestamp=1700000000 + i * 10)

    with RuleEngine(db_path, chain_id=1) as engine:
        alerts = engine.run(rules=["fan_in_out"])

    assert len(alerts) == 2, f"Expected 2 alerts for R3, got {len(alerts)}"
    patterns = {a.reason.split(":")[0] for a in alerts}
    assert "FAN_IN" in patterns and "FAN_OUT" in patterns
    verify_refs(db_path, alerts)
    ds.close()
    print("   [PASS] R3 Fan-in / Fan-out correctly identifies both patterns with >= 8 counterparties")


def test_smoke_r4_rapid_pass_through(temp_dir: str):
    print("-> Testing R4: Rapid Pass-through...")
    db_path = os.path.join(temp_dir, "r4.db")
    ds = Dataset(db_path)
    hop = addr(30)

    # In: 10 ETH at block 100
    ds.add(amount=10 * ETH, sender=addr(1), recipient=hop, block=100, timestamp=1700000000)
    # Out: 9.5 ETH at block 104 (delta = 4 blocks <= 5, ratio = 0.95 in [0.80, 1.05])
    ds.add(amount=int(Decimal("9.5") * ETH), sender=hop, recipient=addr(2), block=104, timestamp=1700000048)

    with RuleEngine(db_path, chain_id=1) as engine:
        alerts = engine.run(rules=["rapid_pass_through"])

    assert len(alerts) == 1, f"Expected 1 alert for R4, got {len(alerts)}"
    assert alerts[0].rule_id == "rapid_pass_through"
    assert len(alerts[0].evidence_refs) == 2
    verify_refs(db_path, alerts)
    ds.close()
    print("   [PASS] R4 Rapid Pass-through correctly detects flow forwarded within 5 blocks")


def test_smoke_calibration_and_persistence(temp_dir: str):
    print("-> Testing Calibration provenance, Idempotency & Persistence...")
    db_path = os.path.join(temp_dir, "cal_persist.db")
    ds = Dataset(db_path)

    # 55 calibration transfers (1 to 55 ETH) in blocks 1..55
    for b in range(1, 56):
        ds.add(amount=b * ETH, asset="NATIVE", block=b)

    # Test event at block 100
    ds.add(amount=55 * ETH, asset="NATIVE", block=100)

    with RuleEngine(db_path, chain_id=1) as engine:
        alerts1 = engine.run(
            cal_start_block=1,
            cal_end_block=55,
            test_start_block=100,
            test_end_block=100,
            rules=["large_transfer"],
            persist=True,
        )
        alerts2 = engine.run(
            cal_start_block=1,
            cal_end_block=55,
            test_start_block=100,
            test_end_block=100,
            rules=["large_transfer"],
            persist=True,
        )

    assert len(alerts1) == 1
    assert len(alerts2) == 1
    assert alerts1[0].alert_id == alerts2[0].alert_id

    # Verify SQLite rows
    conn = sqlite3.connect(db_path)
    alert_count = conn.execute("SELECT count(*) FROM alerts").fetchone()[0]
    cal_count = conn.execute("SELECT count(*) FROM rule_calibrations").fetchone()[0]
    conn.close()

    assert alert_count == 1, f"Expected 1 alert in DB, got {alert_count}"
    assert cal_count >= 1, f"Expected >= 1 calibration record in DB, got {cal_count}"
    ds.close()
    print("   [PASS] Calibration provenance recorded, alert IDs deterministic, idempotent rerun verified")


def main():
    print("=" * 70)
    print("  PHASE 4 ANOMALY DETECTION RULE ENGINE — INTEGRATION SMOKE RUNNER")
    print("=" * 70)

    temp_dir = tempfile.mkdtemp(prefix="p4_smoke_")
    try:
        test_smoke_r1_large_transfer(temp_dir)
        test_smoke_r2_high_frequency(temp_dir)
        test_smoke_r3_fan_in_out(temp_dir)
        test_smoke_r4_rapid_pass_through(temp_dir)
        test_smoke_calibration_and_persistence(temp_dir)
        print("=" * 70)
        print("  ALL PHASE 4 SMOKE CHECKS PASSED (5/5)")
        print("=" * 70)
        return 0
    except Exception as e:
        print(f"\n[FAIL] Smoke check failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
