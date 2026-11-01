"""Rule R1: Large Transfer (unit: tx).

Detects individual asset transfers meeting or exceeding calibrated p99 threshold or fallback.
- Native ETH fallback: 10 ETH (10 * 10**18 wei)
- ERC-20 fallback: explicit threshold from token_thresholds config or skip if unconfigured (< 50 samples)
- Exact integer arithmetic (no binary float precision loss)
- Canonical blocks only; single chain; separates ETH and ERC-20 contracts.
"""
import logging
import sqlite3
import uuid
from typing import Any

from forensics.rules.base import (
    Alert,
    BaseRule,
    CalibrationRecord,
    calculate_percentile,
    calculate_snapshot_hash,
    compute_alert_id,
    make_transfer_ref,
    normalize_address,
    ts_to_iso,
)

log = logging.getLogger("forensics.rules.large_transfer")

ETH_FALLBACK_WEI = 10 * (10**18)  # 10 ETH in wei


class LargeTransferRule(BaseRule):
    rule_id = "large_transfer"
    rule_version = "1.0.0"
    unit_type = "tx"

    def __init__(
        self,
        fallback_eth_threshold: int = ETH_FALLBACK_WEI,
        token_thresholds: dict[str, int | str] | None = None,
        min_calibration_samples: int = 50,
        percentile: float = 99.0,
    ):
        self.fallback_eth_threshold = int(fallback_eth_threshold)
        self.token_thresholds = {
            (k if k == "NATIVE" else normalize_address(k)): int(v)
            for k, v in (token_thresholds or {}).items()
        }
        self.min_calibration_samples = min_calibration_samples
        self.percentile = percentile

    def calibrate(
        self,
        conn: sqlite3.Connection,
        chain_id: int,
        cal_start_block: int | None = None,
        cal_end_block: int | None = None,
        **kwargs: Any,
    ) -> dict[str, CalibrationRecord]:
        """Calibrate p99 thresholds per asset_id on historical canonical transfers."""
        conn.row_factory = sqlite3.Row
        calibrations: dict[str, CalibrationRecord] = {}

        # Fetch canonical transfers in calibration window
        sql = """
            SELECT t.chain_id, t.block_number, t.block_hash, t.tx_hash, t.log_index,
                   t.asset_id, t.amount_raw
            FROM asset_transfers t
            JOIN blocks b ON t.chain_id = b.chain_id AND t.block_hash = b.hash
            WHERE b.status = 'canonical' AND t.chain_id = ?
        """
        params: list[Any] = [chain_id]
        if cal_start_block is not None:
            sql += " AND t.block_number >= ?"
            params.append(cal_start_block)
        if cal_end_block is not None:
            sql += " AND t.block_number <= ?"
            params.append(cal_end_block)

        sql += " ORDER BY t.block_number ASC, t.tx_hash ASC, t.log_index ASC"
        rows = conn.execute(sql, params).fetchall()

        # Group by asset_id
        by_asset: dict[str, list[sqlite3.Row]] = {}
        for r in rows:
            asset = r["asset_id"] if r["asset_id"] == "NATIVE" else normalize_address(r["asset_id"])
            by_asset.setdefault(asset, []).append(r)

        # Include NATIVE and configured tokens even if 0 rows in calibration window
        all_assets = set(by_asset.keys()) | {"NATIVE"} | set(self.token_thresholds.keys())

        now_utc = ts_to_iso(None)

        for asset in all_assets:
            asset_rows = by_asset.get(asset, [])
            sample_count = len(asset_rows)
            snapshot_hash = calculate_snapshot_hash(asset_rows) if asset_rows else "0" * 64
            cal_id = f"cal-r1-{chain_id}-{asset[:10]}-{uuid.uuid4().hex[:8]}"

            if sample_count >= self.min_calibration_samples:
                # Calibrate p99 from integer amounts
                amounts = sorted(int(r["amount_raw"]) for r in asset_rows)
                threshold = calculate_percentile(amounts, self.percentile)
                notes = f"Calibrated p{self.percentile} from {sample_count} samples"
            elif asset == "NATIVE":
                threshold = self.fallback_eth_threshold
                notes = f"Fallback 10 ETH default used (samples {sample_count} < {self.min_calibration_samples})"
            elif asset in self.token_thresholds:
                threshold = self.token_thresholds[asset]
                notes = f"Explicit configured threshold used (samples {sample_count} < {self.min_calibration_samples})"
            else:
                log.info("Asset %s skipped for R1: insufficient samples (%d) and no threshold configured", asset, sample_count)
                continue

            record = CalibrationRecord(
                calibration_id=cal_id,
                rule_id=self.rule_id,
                rule_version=self.rule_version,
                chain_id=chain_id,
                asset_id=asset,
                start_block=cal_start_block,
                end_block=cal_end_block,
                sample_count=sample_count,
                percentile=self.percentile if sample_count >= self.min_calibration_samples else 0.0,
                selected_threshold=str(threshold),
                snapshot_hash=snapshot_hash,
                created_at=now_utc,
                notes=notes,
            )
            calibrations[asset] = record

        return calibrations

    def evaluate(
        self,
        conn: sqlite3.Connection,
        chain_id: int,
        test_start_block: int | None = None,
        test_end_block: int | None = None,
        calibrations: dict[str, CalibrationRecord] | None = None,
        **kwargs: Any,
    ) -> list[Alert]:
        """Evaluate test window canonical transfers against thresholds."""
        conn.row_factory = sqlite3.Row
        alerts: list[Alert] = []

        # Prepare effective thresholds per asset
        effective_thresholds: dict[str, int] = {}
        if calibrations:
            for asset, cal in calibrations.items():
                effective_thresholds[asset] = int(cal.selected_threshold)

        # Fallbacks for any uncalibrated assets
        if "NATIVE" not in effective_thresholds:
            effective_thresholds["NATIVE"] = self.fallback_eth_threshold
        for token, thresh in self.token_thresholds.items():
            if token not in effective_thresholds:
                effective_thresholds[token] = thresh

        sql = """
            SELECT t.chain_id, t.block_number, t.block_hash, t.block_timestamp,
                   t.tx_hash, t.log_index, t.asset_id, t.from_addr, t.to_addr,
                   t.amount_raw, t.synthetic
            FROM asset_transfers t
            JOIN blocks b ON t.chain_id = b.chain_id AND t.block_hash = b.hash
            WHERE b.status = 'canonical' AND t.chain_id = ?
        """
        params: list[Any] = [chain_id]
        if test_start_block is not None:
            sql += " AND t.block_number >= ?"
            params.append(test_start_block)
        if test_end_block is not None:
            sql += " AND t.block_number <= ?"
            params.append(test_end_block)

        sql += " ORDER BY t.block_number ASC, t.tx_hash ASC, t.log_index ASC"
        rows = conn.execute(sql, params).fetchall()

        now_utc = ts_to_iso(None)

        for row in rows:
            asset = row["asset_id"] if row["asset_id"] == "NATIVE" else normalize_address(row["asset_id"])
            if asset not in effective_thresholds:
                continue

            threshold = effective_thresholds[asset]
            amount = int(row["amount_raw"])

            if amount >= threshold:
                evidence = [make_transfer_ref(row)]
                unit_key = f"{row['chain_id']}:{row['tx_hash']}:{row['log_index']}"
                alert_id = compute_alert_id(
                    chain_id=chain_id,
                    rule_id=self.rule_id,
                    rule_version=self.rule_version,
                    unit_type=self.unit_type,
                    unit_key=unit_key,
                    asset_id=row["asset_id"],
                    evidence_refs=evidence,
                )
                ts_str = ts_to_iso(row["block_timestamp"])
                reason = (
                    f"Large transfer: {amount} >= threshold {threshold} "
                    f"for asset {row['asset_id']} (tx: {row['tx_hash']})"
                )
                alert = Alert(
                    alert_id=alert_id,
                    rule_id=self.rule_id,
                    rule_version=self.rule_version,
                    unit_type=self.unit_type,
                    unit_key=unit_key,
                    asset_id=row["asset_id"],
                    severity="HIGH",
                    score=1.0,
                    reason=reason,
                    evidence_refs=evidence,
                    window_start=ts_str,
                    window_end=ts_str,
                    created_at=now_utc,
                    status="new",
                    synthetic=int(row["synthetic"]),
                )
                alerts.append(alert)

        return alerts
