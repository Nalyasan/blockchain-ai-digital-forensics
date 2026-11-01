"""Rule Engine Coordinator for Phase 4 Anomaly Detection.

Orchestrates Rules R1–R4, enforces calibration-test window separation,
handles deterministic alert persistence to SQLite, and provides JSON/CSV export.
"""
from forensics.persistence import insert_verified

import csv
import json
import logging
import os
import sqlite3
from pathlib import Path
from typing import Any

from forensics.rules.base import Alert, BaseRule, CalibrationRecord
from forensics.rules.fan_in_out import FanInOutRule
from forensics.rules.high_frequency import HighFrequencyRule
from forensics.rules.large_transfer import LargeTransferRule
from forensics.rules.rapid_pass_through import RapidPassThroughRule
from forensics.schemas import init_db

log = logging.getLogger("forensics.rules.engine")

ALL_RULE_IDS = [
    "large_transfer",
    "high_frequency",
    "fan_in_out",
    "rapid_pass_through",
]

RULE_ALIASES = {
    "r1": "large_transfer",
    "r2": "high_frequency",
    "r3": "fan_in_out",
    "r4": "rapid_pass_through",
    "large_transfer": "large_transfer",
    "high_frequency": "high_frequency",
    "fan_in_out": "fan_in_out",
    "rapid_pass_through": "rapid_pass_through",
}


class RuleEngine:
    """Central engine managing rule calibration, evaluation, and alert persistence."""

    def __init__(
        self,
        db_path_or_conn: str | Path | sqlite3.Connection | None = None,
        chain_id: int = 1,
        token_thresholds: dict[str, int | str] | None = None,
        token_pass_mins: dict[str, int | str] | None = None,
        rules: list[BaseRule] | None = None,
    ):
        self.chain_id = int(chain_id)
        self.token_thresholds = token_thresholds or {}
        self.token_pass_mins = token_pass_mins or self.token_thresholds

        if isinstance(db_path_or_conn, sqlite3.Connection):
            self.conn = db_path_or_conn
            self._owns_conn = False
            self.db_path = None
        else:
            self.db_path = str(db_path_or_conn or os.environ.get("DB_PATH", "data/forensics.db"))
            self.conn = init_db(self.db_path)
            self._owns_conn = True

        if rules is not None:
            self.rules: dict[str, BaseRule] = {r.rule_id: r for r in rules}
        else:
            self.rules = {
                "large_transfer": LargeTransferRule(token_thresholds=self.token_thresholds),
                "high_frequency": HighFrequencyRule(),
                "fan_in_out": FanInOutRule(),
                "rapid_pass_through": RapidPassThroughRule(token_min_amounts=self.token_pass_mins),
            }

        self.calibrations: dict[str, dict[str, CalibrationRecord]] = {}

    def close(self) -> None:
        if self._owns_conn and self.conn:
            self.conn.close()

    def __enter__(self) -> "RuleEngine":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def calibrate(
        self,
        cal_start_block: int | None = None,
        cal_end_block: int | None = None,
        test_start_block: int | None = None,
        rule_ids: list[str] | None = None,
        persist: bool = True,
    ) -> dict[str, dict[str, CalibrationRecord]]:
        """Calibrate thresholds across selected rules with strict window separation check."""
        # Enforce non-overlapping window constraint
        if test_start_block is not None and cal_end_block is not None:
            if cal_end_block >= test_start_block:
                raise ValueError(
                    f"Calibration window must strictly precede and not overlap test window: "
                    f"cal_end_block ({cal_end_block}) >= test_start_block ({test_start_block})"
                )

        selected = self._resolve_rules(rule_ids)
        calibrations: dict[str, dict[str, CalibrationRecord]] = {}

        for rule in selected:
            cals = rule.calibrate(
                self.conn,
                chain_id=self.chain_id,
                cal_start_block=cal_start_block,
                cal_end_block=cal_end_block,
            )
            calibrations[rule.rule_id] = cals
            if persist:
                for record in cals.values():
                    record.save_to_db(self.conn)

        if persist:
            self.conn.commit()

        self.calibrations.update(calibrations)
        return calibrations

    def run(
        self,
        test_start_block: int | None = None,
        test_end_block: int | None = None,
        cal_start_block: int | None = None,
        cal_end_block: int | None = None,
        rules: list[str] | None = None,
        persist: bool = True,
    ) -> list[Alert]:
        """Execute selected rules over test window, persist alerts, and return generated alerts."""
        # Strict calibration separation if both windows provided
        if cal_end_block is not None or cal_start_block is not None:
            self.calibrate(
                cal_start_block=cal_start_block,
                cal_end_block=cal_end_block,
                test_start_block=test_start_block,
                rule_ids=rules,
                persist=persist,
            )

        selected = self._resolve_rules(rules)
        all_alerts: list[Alert] = []

        for rule in selected:
            rule_cals = self.calibrations.get(rule.rule_id, {})
            rule_alerts = rule.evaluate(
                self.conn,
                chain_id=self.chain_id,
                test_start_block=test_start_block,
                test_end_block=test_end_block,
                calibrations=rule_cals,
            )
            all_alerts.extend(rule_alerts)

        if persist:
            self.persist_alerts(all_alerts)

        return all_alerts

    def persist_alerts(self, alerts: list[Alert]) -> int:
        """Persist alerts to SQLite alerts table idempotently using deterministic alert_id."""
        if not alerts:
            return 0

        saved = 0
        with self.conn:
            for alert in alerts:
                refs_json = json.dumps(alert.evidence_refs, sort_keys=True)
                record = alert.to_dict()
                record["evidence_refs"] = refs_json
                record["synthetic"] = int(alert.synthetic)
                insert_verified(
                    self.conn, "alerts", record, ("alert_id",),
                    replay_metadata=("created_at",), json_fields=("evidence_refs",),
                )
                saved += 1

        log.info("Persisted %d alerts to SQLite table alerts", saved)
        return saved

    def get_alerts(
        self,
        rule_id: str | None = None,
        asset_id: str | None = None,
        min_severity: str | None = None,
    ) -> list[Alert]:
        """Query persisted alerts from database."""
        self.conn.row_factory = sqlite3.Row
        sql = "SELECT * FROM alerts WHERE 1=1"
        params: list[Any] = []
        if rule_id:
            canon_rule = RULE_ALIASES.get(rule_id.lower(), rule_id)
            sql += " AND rule_id = ?"
            params.append(canon_rule)
        if asset_id:
            sql += " AND asset_id = ?"
            params.append(asset_id)
        if min_severity:
            sev_levels = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            req_level = sev_levels.get(min_severity.upper(), 1)
            allowed = [k for k, v in sev_levels.items() if v >= req_level]
            placeholders = ",".join("?" for _ in allowed)
            sql += f" AND severity IN ({placeholders})"
            params.extend(allowed)

        sql += " ORDER BY window_start ASC, created_at ASC"
        rows = self.conn.execute(sql, params).fetchall()
        return [Alert.from_row(r) for r in rows]

    def _resolve_rules(self, rule_names: list[str] | None) -> list[BaseRule]:
        """Resolve rule names or aliases to BaseRule instances."""
        if not rule_names:
            return list(self.rules.values())

        resolved: list[BaseRule] = []
        for name in rule_names:
            canon = RULE_ALIASES.get(name.lower(), name)
            if canon in self.rules:
                resolved.append(self.rules[canon])
            else:
                log.warning("Unknown rule name: %s (available: %s)", name, list(self.rules.keys()))
        return resolved

    @staticmethod
    def export_json(alerts: list[Alert | dict[str, Any]], out_path: str | Path) -> None:
        """Export alerts list to formatted JSON file."""
        p = Path(out_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        serializable = [a.to_dict() if isinstance(a, Alert) else a for a in alerts]
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"total_alerts": len(serializable), "alerts": serializable}, f, indent=2)
        log.info("Exported %d alerts to JSON: %s", len(serializable), p)

    @staticmethod
    def export_csv(alerts: list[Alert | dict[str, Any]], out_path: str | Path) -> None:
        """Export alerts list to flat CSV file."""
        p = Path(out_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        fieldnames = [
            "alert_id",
            "rule_id",
            "rule_version",
            "unit_type",
            "unit_key",
            "asset_id",
            "severity",
            "score",
            "reason",
            "window_start",
            "window_end",
            "created_at",
            "status",
            "synthetic",
            "evidence_count",
            "evidence_txs",
        ]
        with open(p, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for a in alerts:
                d = a.to_dict() if isinstance(a, Alert) else dict(a)
                refs = d.get("evidence_refs", [])
                if isinstance(refs, str):
                    refs = json.loads(refs)
                tx_hashes = ",".join(str(r.get("tx_hash", "")) for r in refs)
                row = {
                    "alert_id": d.get("alert_id"),
                    "rule_id": d.get("rule_id"),
                    "rule_version": d.get("rule_version"),
                    "unit_type": d.get("unit_type"),
                    "unit_key": d.get("unit_key"),
                    "asset_id": d.get("asset_id"),
                    "severity": d.get("severity"),
                    "score": d.get("score"),
                    "reason": d.get("reason"),
                    "window_start": d.get("window_start"),
                    "window_end": d.get("window_end"),
                    "created_at": d.get("created_at"),
                    "status": d.get("status"),
                    "synthetic": d.get("synthetic", 0),
                    "evidence_count": len(refs),
                    "evidence_txs": tx_hashes,
                }
                writer.writerow(row)
        log.info("Exported %d alerts to CSV: %s", len(alerts), p)
