"""MITRE ATT&CK Mapping Engine for Blockchain & DeFi Digital Forensics (P8).

Maps detected volumetric/temporal anomalies and deterministic Rule Engine alerts
to MITRE ATT&CK Enterprise and DeFi techniques with mandatory canonical evidence grounding.

Strict Invariant:
Each generated MitreAttackMapping MUST cite at least one verified canonical on-chain
evidence reference (tx_hash or alert_id). Unsubstantiated mappings are strictly rejected.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import logging
import re
from typing import Any, Sequence

logger = logging.getLogger("forensics.ml.mitre")

HEX_TX_REGEX = re.compile(r"^0x[0-9a-fA-F]{64}$")
ALERT_ID_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")
EVIDENCE_REF_REGEX = re.compile(
    r"^(tx:0x[0-9a-fA-F]{64}|alert:[a-zA-Z0-9_\-]+|block:\d+|transfer:\d+|address:0x[0-9a-fA-F]{40})$"
)


class UnsubstantiatedMappingError(ValueError):
    """Raised when a MITRE ATT&CK technique mapping lacks verified evidence references."""
    pass


@dataclass(frozen=True)
class MitreTechniqueDefinition:
    """Canonical definition of a MITRE ATT&CK technique adapted for DeFi forensics."""
    technique_id: str
    technique_name: str
    tactic: str
    sub_tactic_defi: str
    description: str


MITRE_DEFI_TAXONOMY: dict[str, MitreTechniqueDefinition] = {
    "T1566.002": MitreTechniqueDefinition(
        technique_id="T1566.002",
        technique_name="Phishing: Spearphishing Link / Approval Scam",
        tactic="Initial Access",
        sub_tactic_defi="Token Approval Drain & Permit Exploitation",
        description="Adversary tricks victims into granting ERC-20 allowances or signing permit messages to drain assets.",
    ),
    "T1027": MitreTechniqueDefinition(
        technique_id="T1027",
        technique_name="Obfuscated Files or Information: Mixer Layering",
        tactic="Defense Evasion",
        sub_tactic_defi="Peeling Chains, Mixer Ingestion, and Token Hopping",
        description="Adversary fragments and disperses funds across multiple intermediary contracts and tokens to evade graph tracing.",
    ),
    "T1048.003": MitreTechniqueDefinition(
        technique_id="T1048.003",
        technique_name="Exfiltration Over Alternative Protocol: Bridge Hop",
        tactic="Exfiltration",
        sub_tactic_defi="Rapid Liquidity Siphoning & Cross-Chain Extraction",
        description="Adversary rapidly siphons exploited capital through cross-chain bridges or unmonitored liquidity protocols.",
    ),
    "T1499.004": MitreTechniqueDefinition(
        technique_id="T1499.004",
        technique_name="Endpoint Denial of Service: Application or Gas Exhaustion",
        tactic="Impact",
        sub_tactic_defi="Mempool Burst Spamming & Liquidation Frontrunning",
        description="Adversary floods block space or mempool with rapid transaction bursts to exhaust gas or block liquidation.",
    ),
    "T1565.001": MitreTechniqueDefinition(
        technique_id="T1565.001",
        technique_name="Data Manipulation: Stored Data / State Manipulation",
        tactic="Impact",
        sub_tactic_defi="Flash Loan Price Oracle Distortion",
        description="Adversary executes flash borrowing to distort spot price state in automated market maker reserves.",
    ),
}


@dataclass(frozen=True)
class MitreAttackMapping:
    """Formal MITRE ATT&CK mapping with mandatory documented evidence citations."""
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    evidence_refs: list[str]
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "confidence": round(self.confidence, 4),
            "evidence_refs": list(self.evidence_refs),
            "rationale": self.rationale,
        }


def validate_canonical_evidence_refs(refs: Sequence[str]) -> list[str]:
    """Validates and filters evidence references, ensuring canonical formatting."""
    valid_refs: list[str] = []
    seen: set[str] = set()

    for r in refs:
        if not r or not isinstance(r, str):
            continue
        cleaned = r.strip()
        if not cleaned:
            continue

        norm_ref = cleaned
        if cleaned.startswith("0x") and len(cleaned) == 66 and HEX_TX_REGEX.match(cleaned):
            norm_ref = f"tx:{cleaned.lower()}"
        elif len(cleaned) == 64 and ALERT_ID_REGEX.match(cleaned):
            norm_ref = f"alert:{cleaned.lower()}"

        if EVIDENCE_REF_REGEX.match(norm_ref):
            if norm_ref not in seen:
                seen.add(norm_ref)
                valid_refs.append(norm_ref)

    return valid_refs


class MitreMappingEngine:
    """Engine that maps ML anomaly metrics and Rule Engine detections to MITRE ATT&CK techniques."""

    def __init__(self, strict_evidence: bool = True):
        self.strict_evidence = strict_evidence

    def map_anomaly(
        self,
        features: dict[str, float],
        anomaly_score: float,
        rule_alerts: Sequence[Any] = (),
        evidence_refs: Sequence[str] = (),
    ) -> list[dict[str, Any]]:
        """Maps an evaluated entity's features and rule alerts to MITRE ATT&CK techniques.

        Raises:
            UnsubstantiatedMappingError: If strict_evidence=True and any candidate mapping
                                         lacks at least one verified canonical evidence ref.
        """
        valid_refs = validate_canonical_evidence_refs(evidence_refs)

        # Harvest references embedded inside rule_alerts
        triggered_rule_ids: set[str] = set()
        for a in rule_alerts:
            if isinstance(a, dict):
                r_id = a.get("rule_id", "")
                a_id = a.get("alert_id")
                e_refs = a.get("evidence_refs") or []
            else:
                r_id = getattr(a, "rule_id", "")
                a_id = getattr(a, "alert_id", None)
                e_refs = getattr(a, "evidence_refs", []) or []

            if r_id:
                triggered_rule_ids.add(str(r_id).strip().lower())

            if a_id:
                norm_a = f"alert:{str(a_id).strip().lower()}"
                if norm_a not in valid_refs:
                    valid_refs.append(norm_a)

            if isinstance(e_refs, str):
                import json
                try:
                    e_refs = json.loads(e_refs)
                except Exception:
                    e_refs = []

            for r in e_refs:
                if isinstance(r, dict):
                    tx_h = r.get("tx_hash")
                    if tx_h:
                        norm_tx = f"tx:{str(tx_h).strip().lower()}"
                        if norm_tx not in valid_refs:
                            valid_refs.append(norm_tx)
                elif isinstance(r, str):
                    for v in validate_canonical_evidence_refs([r]):
                        if v not in valid_refs:
                            valid_refs.append(v)

        mappings: list[dict[str, Any]] = []

        # 1. Evaluate T1566.002 (Approval Scam / Large Transfer Drain)
        single_out = float(features.get("max_single_out_ratio", 0.0))
        vol_out = float(features.get("volume_out_normalized", 0.0))
        if (
            "large_transfer" in triggered_rule_ids
            or "r1" in triggered_rule_ids
            or single_out >= 0.70
            or (anomaly_score >= 0.65 and vol_out >= 3.0)
        ):
            tech = MITRE_DEFI_TAXONOMY["T1566.002"]
            conf = min(0.95, round(0.50 + 0.30 * single_out + 0.20 * anomaly_score, 2))
            mappings.append(
                self._build_mapping(
                    tech=tech,
                    confidence=conf,
                    evidence_refs=valid_refs,
                    rationale=(
                        f"Detected massive single-target asset drainage (max_single_out_ratio: {single_out:.2f}, "
                        f"volume_out_normalized: {vol_out:.2f}) correlated with Rule Engine detections "
                        f"{sorted(triggered_rule_ids)}, characteristic of approval poisoning or wallet drain."
                    ),
                )
            )

        # 2. Evaluate T1048.003 (Rapid Exfiltration / Pass-Through)
        pass_through = float(features.get("pass_through_ratio", 0.0))
        latency = float(features.get("turnover_latency_min", 999.0))
        if (
            "rapid_pass_through" in triggered_rule_ids
            or "r4" in triggered_rule_ids
            or (pass_through >= 0.80 and latency <= 5.0)
            or (anomaly_score >= 0.70 and pass_through >= 0.75)
        ):
            tech = MITRE_DEFI_TAXONOMY["T1048.003"]
            conf = min(0.95, round(0.55 + 0.25 * min(pass_through, 1.0) + 0.15 * anomaly_score, 2))
            mappings.append(
                self._build_mapping(
                    tech=tech,
                    confidence=conf,
                    evidence_refs=valid_refs,
                    rationale=(
                        f"Rapid capital pass-through with low turnover latency (pass_through_ratio: {pass_through:.2f}, "
                        f"turnover_latency_min: {latency} blocks) indicating immediate exfiltration via bridge or DEX."
                    ),
                )
            )

        # 3. Evaluate T1027 (Mixer Layering & Obfuscation)
        tokens = float(features.get("token_diversity", 1.0))
        out_degree = float(features.get("unique_counterparties_out", 0.0))
        if (
            "fan_in_out" in triggered_rule_ids
            or "r3" in triggered_rule_ids
            or (out_degree >= 3.0 and tokens >= 2.0)
            or (anomaly_score >= 0.60 and out_degree >= 4.0)
        ):
            tech = MITRE_DEFI_TAXONOMY["T1027"]
            conf = min(0.90, round(0.50 + 0.20 * min(tokens / 5.0, 1.0) + 0.20 * min(out_degree / 10.0, 1.0), 2))
            mappings.append(
                self._build_mapping(
                    tech=tech,
                    confidence=conf,
                    evidence_refs=valid_refs,
                    rationale=(
                        f"Multi-counterparty dispersal (unique_counterparties_out: {out_degree}, "
                        f"token_diversity: {tokens}) indicating transactional layering and obfuscation."
                    ),
                )
            )

        # 4. Evaluate T1499.004 (High-Frequency Burst / DoS)
        velocity = float(features.get("tx_velocity", 0.0))
        burst_std = float(features.get("burstiness_std", 999.0))
        if (
            "high_frequency" in triggered_rule_ids
            or "r2" in triggered_rule_ids
            or (velocity >= 5.0 and burst_std <= 2.5)
        ):
            tech = MITRE_DEFI_TAXONOMY["T1499.004"]
            conf = min(0.90, round(0.50 + 0.30 * min(velocity / 10.0, 1.0) + 0.15 * anomaly_score, 2))
            mappings.append(
                self._build_mapping(
                    tech=tech,
                    confidence=conf,
                    evidence_refs=valid_refs,
                    rationale=(
                        f"High-frequency transaction burst (tx_velocity: {velocity} tx/window, "
                        f"burstiness_std: {burst_std:.2f}) indicating automated frontrunning or mempool congestion."
                    ),
                )
            )

        return mappings

    def _build_mapping(
        self,
        tech: MitreTechniqueDefinition,
        confidence: float,
        evidence_refs: list[str],
        rationale: str,
    ) -> dict[str, Any]:
        """Constructs and validates a single MITRE ATT&CK mapping entry."""
        if not evidence_refs:
            msg = (
                f"MITRE mapping for technique {tech.technique_id} ({tech.technique_name}) "
                f"rejected: zero verified canonical evidence references provided."
            )
            if self.strict_evidence:
                raise UnsubstantiatedMappingError(msg)
            else:
                logger.warning(msg)

        return {
            "technique_id": tech.technique_id,
            "technique_name": tech.technique_name,
            "tactic": tech.tactic,
            "confidence": float(confidence),
            "evidence_refs": list(evidence_refs),
            "rationale": str(rationale),
        }
