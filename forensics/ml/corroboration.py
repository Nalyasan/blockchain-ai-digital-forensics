"""Dual-Engine Corroboration Mechanism (P8).

Cross-references continuous ML anomaly scores with deterministic Rule Engine (P4)
alerts from real_p4.db, classifies detection status, mathematically combines confidence
via Noisy-OR, evaluates semantic concordance, and attaches supporting transaction hashes.
"""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from dataclasses import dataclass
from typing import Any, Literal, Sequence

from forensics.rules.base import Alert
from forensics.rules.engine import RULE_ALIASES

# Semantic mapping from Rule Engine IDs to related feature drivers
RULE_TO_FEATURES_MAP: dict[str, list[str]] = {
    "large_transfer": ["volume_out_normalized", "volume_in_normalized", "max_single_out_ratio"],
    "high_frequency": ["tx_velocity", "burstiness_std"],
    "fan_in_out": ["unique_counterparties_in", "unique_counterparties_out"],
    "rapid_pass_through": ["pass_through_ratio", "turnover_latency_min"],
}


@dataclass(frozen=True)
class CorroboratedDetection:
    """Unified detection product integrating ML Anomaly and Rule Engine outputs."""
    entity_address: str
    status: Literal["CORROBORATED", "ML_ONLY", "RULE_ONLY", "NORMAL"]
    ml_score: float
    rule_score: float
    combined_score: float
    triggered_rules: list[str]
    alert_ids: list[str]
    top_xai_drivers: list[str]
    semantic_concordance: bool
    concordant_rules: list[str]
    supporting_tx_hashes: list[str]
    evidence_refs: list[str]
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_address": self.entity_address,
            "status": self.status,
            "ml_score": round(self.ml_score, 4),
            "rule_score": round(self.rule_score, 4),
            "combined_score": round(self.combined_score, 4),
            "triggered_rules": list(self.triggered_rules),
            "alert_ids": list(self.alert_ids),
            "top_xai_drivers": list(self.top_xai_drivers),
            "semantic_concordance": self.semantic_concordance,
            "concordant_rules": list(self.concordant_rules),
            "supporting_tx_hashes": list(self.supporting_tx_hashes),
            "evidence_refs": list(self.evidence_refs),
            "notes": self.notes,
        }


class DualEngineCorroborator:
    """Corroborates statistical ML anomaly scores against deterministic Rule Engine alerts."""

    def __init__(
        self,
        db_path_or_conn: str | Path | sqlite3.Connection | None = None,
        ml_anomaly_threshold: float = 0.65,
        discount_ml_only: float = 0.85,
        discount_rule_only: float = 0.90,
    ):
        self.ml_threshold = float(ml_anomaly_threshold)
        self.discount_ml = float(discount_ml_only)
        self.discount_rule = float(discount_rule_only)

        if isinstance(db_path_or_conn, sqlite3.Connection):
            self.conn = db_path_or_conn
            self._owns_conn = False
        elif db_path_or_conn is not None:
            db_uri = f"{Path(db_path_or_conn).resolve().as_uri()}?mode=ro&immutable=1"
            self.conn = sqlite3.connect(db_uri, uri=True)
            self.conn.row_factory = sqlite3.Row
            self._owns_conn = True
        else:
            self.conn = None
            self._owns_conn = False

    def close(self) -> None:
        if self._owns_conn and self.conn:
            self.conn.close()

    def get_alerts_for_address(self, address: str) -> list[Alert]:
        """Query matching alerts for target address from database."""
        if not self.conn:
            return []
        addr = address.strip().lower()
        query = (
            "SELECT * FROM alerts WHERE lower(unit_key) LIKE ? OR lower(evidence_refs) LIKE ?"
        )
        cursor = self.conn.cursor()
        cursor.execute(query, (f"%{addr}%", f"%{addr}%"))
        rows = cursor.fetchall()
        return [Alert.from_row(r) for r in rows]

    def corroborate(
        self,
        entity_address: str,
        ml_score: float,
        xai_top_drivers: list[str] | None = None,
        rule_alerts: list[Alert] | None = None,
    ) -> CorroboratedDetection:
        """Cross-references ML score and Rule alerts to produce CorroboratedDetection."""
        addr = entity_address.strip().lower()
        drivers = list(xai_top_drivers or [])

        if rule_alerts is None:
            alerts = self.get_alerts_for_address(addr)
        else:
            alerts = list(rule_alerts)

        # 1. Aggregate Rule Engine Score via Noisy-OR: 1 - prod(1 - s_i)
        triggered_rules: list[str] = sorted(list(set(a.rule_id for a in alerts)))
        alert_ids: list[str] = [a.alert_id for a in alerts]

        if alerts:
            prod_complement = 1.0
            for a in alerts:
                s = min(max(float(a.score), 0.0), 1.0)
                prod_complement *= (1.0 - s)
            rule_score = 1.0 - prod_complement
        else:
            rule_score = 0.0

        # 2. Determine Classification Status
        ml_triggers = ml_score >= self.ml_threshold
        rule_triggers = len(alerts) > 0

        if ml_triggers and rule_triggers:
            status = "CORROBORATED"
            # Evidential Noisy-OR combination: 1 - (1 - s_ml)(1 - s_rule)
            combined_score = 1.0 - ((1.0 - ml_score) * (1.0 - rule_score))
            notes = "Anomalous behavior corroborated by both statistical ML model and deterministic Rule Engine."
        elif ml_triggers and not rule_triggers:
            status = "ML_ONLY"
            combined_score = ml_score * self.discount_ml
            notes = "ML statistical anomaly uncorroborated by deterministic rules; potential novel pattern or false positive."
        elif not ml_triggers and rule_triggers:
            status = "RULE_ONLY"
            combined_score = rule_score * self.discount_rule
            notes = "Rule Engine triggered on deterministic threshold, but statistical ML vector remained below anomaly threshold."
        else:
            status = "NORMAL"
            combined_score = max(ml_score, rule_score)
            notes = "Activity within normal parameters."

        # 3. Extract and Deduplicate Supporting Transaction Hashes
        tx_hashes = self._extract_tx_hashes(alerts)

        # 4. Canonical Evidence Reference Strings
        evidence_refs: list[str] = [f"alert:{aid}" for aid in alert_ids]
        for tx in tx_hashes:
            evidence_refs.append(f"tx:{tx}")

        # 5. Evaluate Semantic Concordance between Top XAI Drivers and Triggered Rules
        concordant_rules = self._check_semantic_concordance(drivers, triggered_rules)
        is_concordant = len(concordant_rules) > 0 if status == "CORROBORATED" else False

        return CorroboratedDetection(
            entity_address=addr,
            status=status,
            ml_score=ml_score,
            rule_score=rule_score,
            combined_score=min(max(combined_score, 0.0), 1.0),
            triggered_rules=triggered_rules,
            alert_ids=alert_ids,
            top_xai_drivers=drivers,
            semantic_concordance=is_concordant,
            concordant_rules=concordant_rules,
            supporting_tx_hashes=tx_hashes,
            evidence_refs=evidence_refs,
            notes=notes,
        )

    def _extract_tx_hashes(self, alerts: list[Alert]) -> list[str]:
        """Extract all unique transaction hashes from alerts evidence_refs."""
        tx_set: set[str] = set()
        for a in alerts:
            refs = a.evidence_refs
            if isinstance(refs, str):
                try:
                    refs = json.loads(refs)
                except Exception:
                    refs = []
            for r in refs:
                if isinstance(r, dict) and "tx_hash" in r:
                    h = str(r["tx_hash"]).strip().lower()
                    if h.startswith("0x") and len(h) == 66:
                        tx_set.add(h)
        return sorted(list(tx_set))

    def _check_semantic_concordance(
        self,
        top_drivers: list[str],
        triggered_rules: list[str],
    ) -> list[str]:
        """Check if top explanatory drivers match the semantic domain of triggered rules."""
        concordant: list[str] = []
        driver_text = " ".join(top_drivers).lower()

        for rule in triggered_rules:
            canon_rule = RULE_ALIASES.get(rule.lower(), rule)
            related_features = RULE_TO_FEATURES_MAP.get(canon_rule, [])
            for feat in related_features:
                if feat in driver_text or feat.replace("_", "") in driver_text:
                    concordant.append(canon_rule)
                    break
        return sorted(list(set(concordant)))
