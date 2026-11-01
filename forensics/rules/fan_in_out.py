"""Rule R3: Fan-in / Fan-out (unit: address_window).

Detects an address interacting with >= M unique counterparties within delta_t seconds (default M = 8, delta_t = 900s).
- Distinguishes FAN_IN (>= 8 unique senders) and FAN_OUT (>= 8 unique destinations).
- Excludes zero address (0x0...0) as counterparty and as central wallet.
- Excludes self-transfers (from_addr == to_addr).
- Canonical blocks only; single chain; separates ETH and ERC-20 tokens.
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

log = logging.getLogger("forensics.rules.fan_in_out")


class FanInOutRule(BaseRule):
    rule_id = "fan_in_out"
    rule_version = "1.0.0"
    unit_type = "address_window"

    def __init__(self, counterparty_threshold: int = 8, window_seconds: int = 900):
        self.counterparty_threshold = int(counterparty_threshold)
        self.window_seconds = int(window_seconds)

    def calibrate(
        self,
        conn: sqlite3.Connection,
        chain_id: int,
        cal_start_block: int | None = None,
        cal_end_block: int | None = None,
        **kwargs: Any,
    ) -> dict[str, CalibrationRecord]:
        """Fan-in/out has structural default parameters; returns empty record dict."""
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
        """Detect FAN_IN and FAN_OUT patterns exceeding counterparty_threshold within window_seconds."""
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

        # Build incoming and outgoing streams:
        # fan_in_streams: (asset_id, to_addr) -> list of incoming transfers from distinct counterparties
        # fan_out_streams: (asset_id, from_addr) -> list of outgoing transfers to distinct counterparties
        fan_in_streams: dict[tuple[str, str], list[sqlite3.Row]] = {}
        fan_out_streams: dict[tuple[str, str], list[sqlite3.Row]] = {}

        for r in rows:
            from_a = normalize_address(r["from_addr"])
            to_a = normalize_address(r["to_addr"])
            if is_zero_address(from_a) or is_zero_address(to_a) or from_a == to_a:
                continue
            asset = r["asset_id"] if r["asset_id"] == "NATIVE" else normalize_address(r["asset_id"])

            # FAN_IN: to_a is central recipient, from_a is counterparty
            fan_in_streams.setdefault((asset, to_a), []).append(r)
            # FAN_OUT: from_a is central sender, to_a is counterparty
            fan_out_streams.setdefault((asset, from_a), []).append(r)

        now_utc = ts_to_iso(None)

        def _evaluate_stream(
            pattern: str,
            asset: str,
            central_addr: str,
            events: list[sqlite3.Row],
            counterparty_col: str,
        ):
            if len(events) < self.counterparty_threshold:
                return

            i = 0
            n = len(events)
            while i < n:
                t_start = events[i]["block_timestamp"]
                j = i
                unique_counterparties: set[str] = set()
                while j < n and (events[j]["block_timestamp"] - t_start) <= self.window_seconds:
                    cp = normalize_address(events[j][counterparty_col])
                    unique_counterparties.add(cp)
                    j += 1

                if len(unique_counterparties) >= self.counterparty_threshold:
                    burst_events = events[i:j]
                    evidence = [make_transfer_ref(e) for e in burst_events]
                    win_start = ts_to_iso(burst_events[0]["block_timestamp"])
                    win_end = ts_to_iso(burst_events[-1]["block_timestamp"])
                    time_span = burst_events[-1]["block_timestamp"] - burst_events[0]["block_timestamp"]

                    unit_key = f"{chain_id}:{pattern}:{central_addr}:{asset}:{win_start}:{win_end}"
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
                    cp_name = "senders" if pattern == "FAN_IN" else "destinations"
                    action_name = "received from" if pattern == "FAN_IN" else "distributed to"
                    reason = (
                        f"{pattern}: Address {central_addr} {action_name} {len(unique_counterparties)} "
                        f"unique {cp_name} for {burst_events[0]['asset_id']} within {time_span}s "
                        f"(threshold >= {self.counterparty_threshold} in {self.window_seconds}s)"
                    )
                    alert = Alert(
                        alert_id=alert_id,
                        rule_id=self.rule_id,
                        rule_version=self.rule_version,
                        unit_type=self.unit_type,
                        unit_key=unit_key,
                        asset_id=burst_events[0]["asset_id"],
                        severity="HIGH",
                        score=min(1.0, len(unique_counterparties) / (self.counterparty_threshold * 1.5)),
                        reason=reason,
                        evidence_refs=evidence,
                        window_start=win_start,
                        window_end=win_end,
                        created_at=now_utc,
                        status="new",
                        synthetic=synth,
                    )
                    alerts.append(alert)
                    i = j
                else:
                    i += 1

        # Evaluate FAN_IN
        for (asset, to_addr), events in fan_in_streams.items():
            _evaluate_stream("FAN_IN", asset, to_addr, events, "from_addr")

        # Evaluate FAN_OUT
        for (asset, from_addr), events in fan_out_streams.items():
            _evaluate_stream("FAN_OUT", asset, from_addr, events, "to_addr")

        return alerts
