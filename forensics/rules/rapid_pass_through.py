"""Rule R4: Rapid Pass-through (unit: address_window).

Detects an intermediate address receiving an incoming transfer of an asset (>= minimum pass amount)
and forwarding the same asset within <= delta_b blocks (default 5 blocks), where the forwarding
ratio is between alpha_min and alpha_max (default 0.80 to 1.05).
- Minimum pass amount:
  - Native ETH: 1 ETH (10**18 wei) fallback
  - ERC-20: calibrated p90 from calibration window (if samples >= 50) or explicit token_threshold
- Exact Decimal / integer arithmetic (no binary float loss)
- Excludes zero address (0x0...0) as intermediate, sender, or recipient
- Canonical blocks only; single chain; separate ETH and ERC-20 contracts
- Outgoing must not precede incoming.
"""
import logging
import sqlite3
import uuid
from decimal import Decimal
from typing import Any

from forensics.rules.base import (
    Alert,
    BaseRule,
    CalibrationRecord,
    calculate_percentile,
    calculate_snapshot_hash,
    compute_alert_id,
    is_zero_address,
    make_transfer_ref,
    normalize_address,
    ts_to_iso,
)

log = logging.getLogger("forensics.rules.rapid_pass_through")

ETH_MIN_PASS_AMOUNT = 10**18  # 1 ETH in wei
DEFAULT_MIN_RATIO = Decimal("0.80")
DEFAULT_MAX_RATIO = Decimal("1.05")
DEFAULT_MAX_BLOCK_DELTA = 5


class RapidPassThroughRule(BaseRule):
    rule_id = "rapid_pass_through"
    rule_version = "1.0.0"
    unit_type = "address_window"

    def __init__(
        self,
        max_block_delta: int = DEFAULT_MAX_BLOCK_DELTA,
        min_ratio: Decimal | float = DEFAULT_MIN_RATIO,
        max_ratio: Decimal | float = DEFAULT_MAX_RATIO,
        fallback_eth_min: int = ETH_MIN_PASS_AMOUNT,
        token_min_amounts: dict[str, int | str] | None = None,
        min_calibration_samples: int = 50,
        percentile: float = 90.0,
    ):
        self.max_block_delta = int(max_block_delta)
        self.min_ratio = Decimal(str(min_ratio))
        self.max_ratio = Decimal(str(max_ratio))
        self.fallback_eth_min = int(fallback_eth_min)
        self.token_min_amounts = {
            (k if k == "NATIVE" else normalize_address(k)): int(v)
            for k, v in (token_min_amounts or {}).items()
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
        """Calibrate p90 minimum incoming thresholds per asset on historical canonical transfers."""
        conn.row_factory = sqlite3.Row
        calibrations: dict[str, CalibrationRecord] = {}

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

        by_asset: dict[str, list[sqlite3.Row]] = {}
        for r in rows:
            asset = r["asset_id"] if r["asset_id"] == "NATIVE" else normalize_address(r["asset_id"])
            by_asset.setdefault(asset, []).append(r)

        all_assets = set(by_asset.keys()) | {"NATIVE"} | set(self.token_min_amounts.keys())
        now_utc = ts_to_iso(None)

        for asset in all_assets:
            asset_rows = by_asset.get(asset, [])
            sample_count = len(asset_rows)
            snapshot_hash = calculate_snapshot_hash(asset_rows) if asset_rows else "0" * 64
            cal_id = f"cal-r4-{chain_id}-{asset[:10]}-{uuid.uuid4().hex[:8]}"

            if sample_count >= self.min_calibration_samples:
                amounts = sorted(int(r["amount_raw"]) for r in asset_rows)
                threshold = calculate_percentile(amounts, self.percentile)
                notes = f"Calibrated p{self.percentile} from {sample_count} samples"
            elif asset == "NATIVE":
                threshold = self.fallback_eth_min
                notes = f"Fallback 1 ETH default used (samples {sample_count} < {self.min_calibration_samples})"
            elif asset in self.token_min_amounts:
                threshold = self.token_min_amounts[asset]
                notes = f"Explicit configured min amount used (samples {sample_count} < {self.min_calibration_samples})"
            else:
                log.info("Asset %s skipped for R4: insufficient samples (%d) and no threshold configured", asset, sample_count)
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
        """Detect intermediate addresses receiving and forwarding within delta_b blocks."""
        conn.row_factory = sqlite3.Row
        alerts: list[Alert] = []

        effective_mins: dict[str, int] = {}
        if calibrations:
            for asset, cal in calibrations.items():
                effective_mins[asset] = int(cal.selected_threshold)

        if "NATIVE" not in effective_mins:
            effective_mins["NATIVE"] = self.fallback_eth_min
        for token, thresh in self.token_min_amounts.items():
            if token not in effective_mins:
                effective_mins[token] = thresh

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
            # Query with a buffer to handle pass-through crossing window boundaries if needed
            sql += " AND t.block_number >= ?"
            params.append(test_start_block)
        if test_end_block is not None:
            sql += " AND t.block_number <= ?"
            params.append(test_end_block)

        sql += " ORDER BY t.block_number ASC, t.block_timestamp ASC, t.tx_hash ASC, t.log_index ASC"
        rows = conn.execute(sql, params).fetchall()

        # Group transfers by (asset, address): incoming and outgoing
        # intermediate A != 0x0, sender != 0x0, recipient != 0x0, sender != A, recipient != A
        incoming_by_wallet: dict[tuple[str, str], list[sqlite3.Row]] = {}
        outgoing_by_wallet: dict[tuple[str, str], list[sqlite3.Row]] = {}

        for r in rows:
            from_a = normalize_address(r["from_addr"])
            to_a = normalize_address(r["to_addr"])
            if is_zero_address(from_a) or is_zero_address(to_a) or from_a == to_a:
                continue
            asset = r["asset_id"] if r["asset_id"] == "NATIVE" else normalize_address(r["asset_id"])

            incoming_by_wallet.setdefault((asset, to_a), []).append(r)
            outgoing_by_wallet.setdefault((asset, from_a), []).append(r)

        now_utc = ts_to_iso(None)

        def _is_ordered_after(out_row: sqlite3.Row, in_row: sqlite3.Row) -> bool:
            """Ensure outgoing event strictly follows incoming event."""
            if out_row["block_number"] > in_row["block_number"]:
                return True
            if out_row["block_number"] < in_row["block_number"]:
                return False
            # Same block: check timestamp or tx/log order
            if out_row["block_timestamp"] > in_row["block_timestamp"]:
                return True
            if out_row["block_timestamp"] < in_row["block_timestamp"]:
                return False
            # Same block and timestamp: distinct tx or higher log_index
            if out_row["tx_hash"] != in_row["tx_hash"]:
                return True
            return int(out_row["log_index"]) > int(in_row["log_index"])

        for (asset, wallet), inc_list in incoming_by_wallet.items():
            if asset not in effective_mins:
                continue
            min_amount = effective_mins[asset]
            out_list = outgoing_by_wallet.get((asset, wallet), [])
            if not out_list:
                continue

            for in_tx in inc_list:
                in_amount = int(in_tx["amount_raw"])
                if in_amount < min_amount:
                    continue

                in_block = int(in_tx["block_number"])

                for out_tx in out_list:
                    out_block = int(out_tx["block_number"])
                    block_delta = out_block - in_block

                    # Must be within [0, max_block_delta]
                    if block_delta < 0 or block_delta > self.max_block_delta:
                        continue

                    # Must strictly follow incoming
                    if not _is_ordered_after(out_tx, in_tx):
                        continue

                    out_amount = int(out_tx["amount_raw"])
                    ratio = Decimal(out_amount) / Decimal(in_amount)

                    if self.min_ratio <= ratio <= self.max_ratio:
                        evidence = [make_transfer_ref(in_tx), make_transfer_ref(out_tx)]
                        unit_key = (
                            f"{chain_id}:{wallet}:{asset}:"
                            f"{in_tx['tx_hash']}:{in_tx['log_index']}:"
                            f"{out_tx['tx_hash']}:{out_tx['log_index']}"
                        )
                        alert_id = compute_alert_id(
                            chain_id=chain_id,
                            rule_id=self.rule_id,
                            rule_version=self.rule_version,
                            unit_type=self.unit_type,
                            unit_key=unit_key,
                            asset_id=in_tx["asset_id"],
                            evidence_refs=evidence,
                        )
                        win_start = ts_to_iso(in_tx["block_timestamp"])
                        win_end = ts_to_iso(out_tx["block_timestamp"])
                        synth = 1 if (int(in_tx["synthetic"]) == 1 or int(out_tx["synthetic"]) == 1) else 0

                        reason = (
                            f"Rapid pass-through: Address {wallet} received {in_amount} {in_tx['asset_id']} "
                            f"at block {in_block} and forwarded {out_amount} at block {out_block} "
                            f"(ratio: {ratio:.4f}, block delta: {block_delta})"
                        )
                        alert = Alert(
                            alert_id=alert_id,
                            rule_id=self.rule_id,
                            rule_version=self.rule_version,
                            unit_type=self.unit_type,
                            unit_key=unit_key,
                            asset_id=in_tx["asset_id"],
                            severity="HIGH",
                            score=1.0,
                            reason=reason,
                            evidence_refs=evidence,
                            window_start=win_start,
                            window_end=win_end,
                            created_at=now_utc,
                            status="new",
                            synthetic=synth,
                        )
                        alerts.append(alert)

        return alerts
