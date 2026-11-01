"""Rule R2: High Frequency (unit: address_window).

Detects an address sending >= N qualifying outgoing asset transfers within a rolling
delta_t window (default N = 10, delta_t = 300s) partitioned by chain_id, address, and asset.
- Ingestion: normalized asset_transfers (correctly handles multiple ERC-20 Transfer logs per tx)
- Excludes zero address (0x0...0) as sender or recipient
- Canonical blocks only; single-chain evaluation; separates ETH and ERC-20 tokens
- Deterministic sliding window detection.
"""
import logging
import sqlite3
from typing import Any

from forensics.rules.base import (
    Alert,
    BaseRule,
    CalibrationRecord,
    compute_alert_id,
    is_zero_address,
    make_transfer_ref,
    normalize_address,
    ts_to_iso,
)

log = logging.getLogger("forensics.rules.high_frequency")


class HighFrequencyRule(BaseRule):
    rule_id = "high_frequency"
    rule_version = "1.0.0"
    unit_type = "address_window"

    def __init__(self, count_threshold: int = 10, window_seconds: int = 300):
        self.count_threshold = int(count_threshold)
        self.window_seconds = int(window_seconds)

    def calibrate(
        self,
        conn: sqlite3.Connection,
        chain_id: int,
        cal_start_block: int | None = None,
        cal_end_block: int | None = None,
        **kwargs: Any,
    ) -> dict[str, CalibrationRecord]:
        """High frequency has structural default parameters; returns empty or informative record."""
        return {}

    def evaluate(
        self,
        conn: sqlite3.Connection,
        chain_id: int,
        test_start_block: int | None = None,
        test_end_block: int | None = None,
        calibrations: dict[str, CalibrationRecord] | None = None,
        **kwargs: Any,
    ) -> list[Alert]:
        """Detect addresses sending >= count_threshold outgoing transfers within window_seconds."""
        conn.row_factory = sqlite3.Row
        alerts: list[Alert] = []

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

        sql += " ORDER BY t.block_timestamp ASC, t.block_number ASC, t.tx_hash ASC, t.log_index ASC"
        rows = conn.execute(sql, params).fetchall()

        # Group qualifying outgoing transfers by (asset_id, from_addr)
        # Exclude zero address
        streams: dict[tuple[str, str], list[sqlite3.Row]] = {}
        for r in rows:
            from_a = normalize_address(r["from_addr"])
            to_a = normalize_address(r["to_addr"])
            if is_zero_address(from_a) or is_zero_address(to_a):
                continue
            asset = r["asset_id"] if r["asset_id"] == "NATIVE" else normalize_address(r["asset_id"])
            streams.setdefault((asset, from_a), []).append(r)

        now_utc = ts_to_iso(None)

        for (asset, from_addr), events in streams.items():
            if len(events) < self.count_threshold:
                continue

            i = 0
            n = len(events)
            while i < n:
                # Find all events starting at i within window_seconds
                t_start = events[i]["block_timestamp"]
                j = i
                while j < n and (events[j]["block_timestamp"] - t_start) <= self.window_seconds:
                    j += 1

                count = j - i
                if count >= self.count_threshold:
                    # We have a qualifying burst from i to j-1
                    burst_events = events[i:j]
                    evidence = [make_transfer_ref(e) for e in burst_events]
                    win_start = ts_to_iso(burst_events[0]["block_timestamp"])
                    win_end = ts_to_iso(burst_events[-1]["block_timestamp"])
                    time_span = burst_events[-1]["block_timestamp"] - burst_events[0]["block_timestamp"]

                    unit_key = f"{chain_id}:{from_addr}:{asset}:{win_start}:{win_end}"
                    alert_id = compute_alert_id(
                        chain_id=chain_id,
                        rule_id=self.rule_id,
                        rule_version=self.rule_version,
                        unit_type=self.unit_type,
                        unit_key=unit_key,
                        asset_id=burst_events[0]["asset_id"],
                        evidence_refs=evidence,
                    )
                    synth = 1 if any(int(e["synthetic"]) == 1 for e in burst_events) else 0
                    reason = (
                        f"High frequency: Address {from_addr} sent {count} outgoing transfers "
                        f"for {burst_events[0]['asset_id']} within {time_span}s (threshold >= {self.count_threshold} in {self.window_seconds}s)"
                    )
                    alert = Alert(
                        alert_id=alert_id,
                        rule_id=self.rule_id,
                        rule_version=self.rule_version,
                        unit_type=self.unit_type,
                        unit_key=unit_key,
                        asset_id=burst_events[0]["asset_id"],
                        severity="MEDIUM",
                        score=min(1.0, count / (self.count_threshold * 2.0)),
                        reason=reason,
                        evidence_refs=evidence,
                        window_start=win_start,
                        window_end=win_end,
                        created_at=now_utc,
                        status="new",
                        synthetic=synth,
                    )
                    alerts.append(alert)
                    # Advance i past this window to avoid duplicate alerts for the same burst
                    i = j
                else:
                    i += 1

        return alerts
