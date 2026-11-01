"""Unit tests for Phase 4 Real Dataset Anomaly Detection Rules Execution.

Verifies:
1. Rule calibration computes genuine thresholds for Euler DAI and Curve alETH without facades.
2. Rules execute on data/real_p4.db without errors.
3. Generated alerts have valid deterministic IDs and canonical 10-field evidence references.
4. Zero threshold mutations occurred (rules maintain baseline thresholds and logic).
5. Real incident transactions (Euler frontrun 0xc310..., Curve exploit 0xb676...,
   and internal ETH transfers) are accurately detected and cross-referenced.
6. Zero-alert results and coverage limitations are genuinely documented.
7. Alert records export file results/p4/real_data_alerts.json is valid and complete.
"""
from __future__ import annotations

from decimal import Decimal
import json
from pathlib import Path
import sqlite3
import pytest

from forensics.rules.base import (
    ZERO_ADDRESS,
    Alert,
    calculate_percentile,
    calculate_snapshot_hash,
    compute_alert_id,
)
from forensics.rules.engine import RuleEngine
from forensics.rules.fan_in_out import FanInOutRule
from forensics.rules.high_frequency import HighFrequencyRule
from forensics.rules.large_transfer import LargeTransferRule
from forensics.rules.rapid_pass_through import RapidPassThroughRule
from scripts.run_real_rules import (
    CURVE_ALETH_ASSET,
    CURVE_ALETH_CALIBRATION_BOUNDS,
    CURVE_ALETH_TEST_BOUNDS,
    CURVE_EXPLOIT_TX,
    DEFAULT_DB_PATH,
    DEFAULT_OUT_JSON,
    EULER_DAI_ASSET,
    EULER_DAI_CALIBRATION_BOUNDS,
    EULER_DAI_TEST_BOUNDS,
    EULER_FRONTRUN_TX,
    EXPECTED_REF_FIELDS,
    NATIVE_ASSET,
    execute_real_rules,
    verify_alert_integrity,
)


@pytest.fixture(scope="module")
def real_db_path() -> Path:
    """Fixture providing verified path to real_p4.db."""
    assert DEFAULT_DB_PATH.exists(), f"Target database missing: {DEFAULT_DB_PATH}"
    return DEFAULT_DB_PATH


@pytest.fixture(scope="module")
def execution_results(real_db_path: Path) -> dict:
    """Run real rules once and share verified results across all module tests."""
    return execute_real_rules(db_path=real_db_path, chain_id=1, persist=False, out_json=None)


# ==============================================================================
# 1. Genuine Calibration Tests (Euler DAI & Curve alETH)
# ==============================================================================


def test_euler_dai_rule_calibration(real_db_path: Path):
    """Verify RuleEngine calibrates genuine empirical percentiles for Euler DAI."""
    with RuleEngine(real_db_path, chain_id=1) as engine:
        cals = engine.calibrate(
            cal_start_block=EULER_DAI_CALIBRATION_BOUNDS[0],
            cal_end_block=EULER_DAI_CALIBRATION_BOUNDS[1],
            test_start_block=EULER_DAI_TEST_BOUNDS[0],
            persist=False,
        )

    # R1: LargeTransferRule
    r1_cals = cals.get("large_transfer", {})
    assert EULER_DAI_ASSET in r1_cals
    cal_r1 = r1_cals[EULER_DAI_ASSET]
    assert cal_r1.sample_count == 6042
    assert cal_r1.percentile == 99.0
    assert cal_r1.selected_threshold.isdigit()
    assert int(cal_r1.selected_threshold) > 0
    assert len(cal_r1.snapshot_hash) == 64

    # Independently verify the p99 threshold directly from the SQLite database rows
    conn = sqlite3.connect(str(real_db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT t.amount_raw
        FROM asset_transfers t
        JOIN blocks b ON t.chain_id = b.chain_id AND t.block_hash = b.hash
        WHERE b.status = 'canonical'
          AND t.chain_id = 1
          AND t.asset_id = ?
          AND t.block_number BETWEEN ? AND ?
        """,
        (EULER_DAI_ASSET, EULER_DAI_CALIBRATION_BOUNDS[0], EULER_DAI_CALIBRATION_BOUNDS[1]),
    ).fetchall()
    conn.close()

    assert len(rows) == 6042
    raw_amounts = sorted(int(r["amount_raw"]) for r in rows)
    expected_p99 = calculate_percentile(raw_amounts, 99.0)
    assert int(cal_r1.selected_threshold) == expected_p99

    # R4: RapidPassThroughRule
    r4_cals = cals.get("rapid_pass_through", {})
    assert EULER_DAI_ASSET in r4_cals
    cal_r4 = r4_cals[EULER_DAI_ASSET]
    assert cal_r4.sample_count == 6042
    assert cal_r4.percentile == 90.0
    expected_p90 = calculate_percentile(raw_amounts, 90.0)
    assert int(cal_r4.selected_threshold) == expected_p90

    # NATIVE Fallback Verification
    assert NATIVE_ASSET in r1_cals
    assert int(r1_cals[NATIVE_ASSET].selected_threshold) == 10 * 10**18
    assert int(r4_cals[NATIVE_ASSET].selected_threshold) == 10**18


def test_curve_aleth_rule_calibration(real_db_path: Path):
    """Verify RuleEngine calibrates genuine empirical percentiles for Curve alETH."""
    with RuleEngine(real_db_path, chain_id=1) as engine:
        cals = engine.calibrate(
            cal_start_block=CURVE_ALETH_CALIBRATION_BOUNDS[0],
            cal_end_block=CURVE_ALETH_CALIBRATION_BOUNDS[1],
            test_start_block=CURVE_ALETH_TEST_BOUNDS[0],
            persist=False,
        )

    # R1: LargeTransferRule
    r1_cals = cals.get("large_transfer", {})
    assert CURVE_ALETH_ASSET in r1_cals
    cal_r1 = r1_cals[CURVE_ALETH_ASSET]
    assert cal_r1.sample_count == 246
    assert cal_r1.percentile == 99.0
    assert len(cal_r1.snapshot_hash) == 64

    # Independently verify from database rows
    conn = sqlite3.connect(str(real_db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT t.amount_raw
        FROM asset_transfers t
        JOIN blocks b ON t.chain_id = b.chain_id AND t.block_hash = b.hash
        WHERE b.status = 'canonical'
          AND t.chain_id = 1
          AND t.asset_id = ?
          AND t.block_number BETWEEN ? AND ?
        """,
        (CURVE_ALETH_ASSET, CURVE_ALETH_CALIBRATION_BOUNDS[0], CURVE_ALETH_CALIBRATION_BOUNDS[1]),
    ).fetchall()
    conn.close()

    assert len(rows) == 246
    raw_amounts = sorted(int(r["amount_raw"]) for r in rows)
    expected_p99 = calculate_percentile(raw_amounts, 99.0)
    assert int(cal_r1.selected_threshold) == expected_p99

    # R4: RapidPassThroughRule
    r4_cals = cals.get("rapid_pass_through", {})
    assert CURVE_ALETH_ASSET in r4_cals
    cal_r4 = r4_cals[CURVE_ALETH_ASSET]
    assert cal_r4.sample_count == 246
    assert cal_r4.percentile == 90.0
    expected_p90 = calculate_percentile(raw_amounts, 90.0)
    assert int(cal_r4.selected_threshold) == expected_p90


# ==============================================================================
# 2. Rule Execution & Alert Count Verification
# ==============================================================================


def test_rules_execute_without_errors(execution_results: dict):
    """Verify all 4 rules execute without errors and produce expected alert counts."""
    meta = execution_results["metadata"]
    assert meta["total_alerts"] == 172

    euler = meta["windows"]["euler_dai"]
    assert euler["total_alerts"] == 58
    assert euler["rule_breakdown"]["large_transfer"] == 26
    assert euler["rule_breakdown"]["rapid_pass_through"] == 25
    assert euler["rule_breakdown"]["fan_in_out"] == 6
    assert euler["rule_breakdown"]["high_frequency"] == 1

    curve = meta["windows"]["curve_aleth"]
    assert curve["total_alerts"] == 114
    assert curve["rule_breakdown"]["large_transfer"] == 56
    assert curve["rule_breakdown"]["rapid_pass_through"] == 46
    assert curve["rule_breakdown"]["high_frequency"] == 10
    assert curve["rule_breakdown"]["fan_in_out"] == 2


# ==============================================================================
# 3. Deterministic Alert IDs & Evidence References Schema
# ==============================================================================


def test_alert_ids_match_compute_alert_id_determinism(execution_results: dict):
    """Verify every alert ID strictly matches compute_alert_id() formula."""
    alerts = execution_results["alerts"]
    assert len(alerts) == 172

    seen_ids = set()
    for d in alerts:
        alert = Alert(
            alert_id=d["alert_id"],
            rule_id=d["rule_id"],
            rule_version=d["rule_version"],
            unit_type=d["unit_type"],
            unit_key=d["unit_key"],
            asset_id=d["asset_id"],
            severity=d["severity"],
            score=d["score"],
            reason=d["reason"],
            evidence_refs=d["evidence_refs"],
            window_start=d["window_start"],
            window_end=d["window_end"],
            created_at=d["created_at"],
            status=d.get("status", "new"),
            synthetic=d.get("synthetic", 0),
        )

        expected_id = compute_alert_id(
            chain_id=1,
            rule_id=alert.rule_id,
            rule_version=alert.rule_version,
            unit_type=alert.unit_type,
            unit_key=alert.unit_key,
            asset_id=alert.asset_id,
            evidence_refs=alert.evidence_refs,
        )

        assert alert.alert_id == expected_id, f"Alert ID mismatch for {alert.rule_id}: {alert.alert_id} != {expected_id}"
        assert len(alert.alert_id) == 64
        assert int(alert.alert_id, 16) > 0  # Valid hex string
        seen_ids.add(alert.alert_id)

    assert len(seen_ids) == 172, "Duplicate alert IDs found across detection execution"


def test_evidence_refs_10_field_schema_and_db_linkage(execution_results: dict, real_db_path: Path):
    """Verify evidence_refs schema conforms to the 10-field dictionary format and links to real_p4.db."""
    alerts = execution_results["alerts"]
    expected_keys = set(EXPECTED_REF_FIELDS)

    conn = sqlite3.connect(str(real_db_path))
    conn.row_factory = sqlite3.Row

    for d in alerts:
        refs = d["evidence_refs"]
        assert len(refs) >= 1
        for ref in refs:
            # 1. Exact 10 fields check
            assert set(ref.keys()) == expected_keys, f"Ref keys mismatch: {set(ref.keys()) ^ expected_keys}"

            # 2. Field type and validity checks
            assert isinstance(ref["chain_id"], int) and ref["chain_id"] == 1
            assert isinstance(ref["block_number"], int) and ref["block_number"] > 0
            assert isinstance(ref["block_hash"], str) and ref["block_hash"].startswith("0x")
            assert isinstance(ref["block_timestamp"], int) and ref["block_timestamp"] > 0
            assert isinstance(ref["tx_hash"], str) and ref["tx_hash"].startswith("0x")
            assert isinstance(ref["log_index"], int)
            assert isinstance(ref["asset_id"], str) and len(ref["asset_id"]) > 0
            assert isinstance(ref["from_addr"], str) and ref["from_addr"].startswith("0x")
            assert isinstance(ref["to_addr"], str) and ref["to_addr"].startswith("0x")
            assert isinstance(ref["amount_raw"], str) and ref["amount_raw"].isdigit()

            # 3. Ground truth linkage against asset_transfers table
            db_row = conn.execute(
                """
                SELECT transfer_id, amount_raw, from_addr, to_addr, asset_id
                FROM asset_transfers
                WHERE chain_id = ? AND block_hash = ? AND tx_hash = ? AND log_index = ?
                """,
                (ref["chain_id"], ref["block_hash"], ref["tx_hash"], ref["log_index"]),
            ).fetchone()

            assert db_row is not None, f"Evidence ref not found in asset_transfers: {ref}"
            assert db_row["amount_raw"] == ref["amount_raw"]
            assert db_row["from_addr"] == ref["from_addr"]
            assert db_row["to_addr"] == ref["to_addr"]
            assert db_row["asset_id"] == ref["asset_id"]

    conn.close()


# ==============================================================================
# 4. Zero Threshold Mutations Verification
# ==============================================================================


def test_zero_threshold_mutations_occurred():
    """Verify that rule thresholds and core configuration match baseline defaults exactly."""
    # R1: LargeTransferRule
    r1 = LargeTransferRule()
    assert r1.fallback_eth_threshold == 10 * 10**18, "R1 ETH threshold mutated"
    assert r1.percentile == 99.0, "R1 percentile mutated"
    assert r1.min_calibration_samples == 50, "R1 min samples mutated"

    # R2: HighFrequencyRule
    r2 = HighFrequencyRule()
    assert r2.count_threshold == 10, "R2 count threshold mutated"
    assert r2.window_seconds == 300, "R2 window_seconds mutated"

    # R3: FanInOutRule
    r3 = FanInOutRule()
    assert r3.counterparty_threshold == 8, "R3 counterparty threshold mutated"
    assert r3.window_seconds == 900, "R3 window_seconds mutated"

    # R4: RapidPassThroughRule
    r4 = RapidPassThroughRule()
    assert r4.fallback_eth_min == 10**18, "R4 ETH min amount mutated"
    assert r4.percentile == 90.0, "R4 percentile mutated"
    assert r4.min_calibration_samples == 50, "R4 min samples mutated"
    assert r4.max_block_delta == 5, "R4 max block delta mutated"
    assert r4.min_ratio == Decimal("0.80"), "R4 min ratio mutated"
    assert r4.max_ratio == Decimal("1.05"), "R4 max ratio mutated"


# ==============================================================================
# 5. Incident Cross-Referencing & Internal Transfers
# ==============================================================================


def test_euler_frontrun_incident_cross_reference(execution_results: dict):
    """Verify Euler frontrun transaction 0xc310... triggers genuine detections."""
    meta = execution_results["metadata"]
    cross = meta["incident_cross_references"]["euler_frontrun_tx_0xc310"]
    assert cross["matched_alerts_count"] == 10
    assert "large_transfer" in cross["rules_triggered"]
    assert "rapid_pass_through" in cross["rules_triggered"]


def test_curve_exploit_incident_cross_reference(execution_results: dict):
    """Verify Curve exploit transaction 0xb676... triggers genuine detections."""
    meta = execution_results["metadata"]
    cross = meta["incident_cross_references"]["curve_exploit_tx_0xb676"]
    assert cross["matched_alerts_count"] == 10
    assert "large_transfer" in cross["rules_triggered"]
    assert "rapid_pass_through" in cross["rules_triggered"]


def test_internal_eth_transfers_alerts(execution_results: dict):
    """Verify normalized internal ETH transfers (log_index < -1) trigger genuine alerts."""
    meta = execution_results["metadata"]
    internal_eth = meta["incident_cross_references"]["internal_eth_transfers"]
    assert internal_eth["euler_internal_eth_alerts_count"] == 3
    assert internal_eth["curve_internal_eth_alerts_count"] == 11


# ==============================================================================
# 6. Real Data Alerts JSON File Validation
# ==============================================================================


def test_real_data_alerts_json_file_exists_and_matches():
    """Verify results/p4/real_data_alerts.json exists and conforms to required schema."""
    assert DEFAULT_OUT_JSON.exists(), f"Alerts JSON missing at {DEFAULT_OUT_JSON}"
    with open(DEFAULT_OUT_JSON, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["total_alerts"] == 172
    assert len(data["alerts"]) == 172
    assert "metadata" in data
    assert "zero_alert_results" in data["metadata"]
    assert "coverage_limitations" in data["metadata"]
    assert len(data["metadata"]["zero_alert_results"]["records"]) >= 5
