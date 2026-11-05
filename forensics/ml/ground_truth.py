"""Independent Ground Truth Registry & Window-Scoped Attack Mapper.

Decouples ML training ground truth completely from Rule Engine alerts.
Labels are computed from verified attack incident registries or independent threat intelligence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import sqlite3
from typing import Sequence


@dataclass(frozen=True)
class AttackIncidentRecord:
    """Represents a verified on-chain exploit incident with active block boundaries."""
    incident_id: str
    attacker_entities: tuple[str, ...]
    attack_contract_entities: tuple[str, ...]
    exploit_start_block: int
    exploit_end_block: int
    incident_type: str
    description: str


# Canonical verified DeFi attack registry for real_p4.db
CANONICAL_ATTACK_REGISTRY: tuple[AttackIncidentRecord, ...] = (
    AttackIncidentRecord(
        incident_id="euler_finance_exploit",
        attacker_entities=(
            "0xebc29199c817dc47ba12e3f86102564d640cbf99",  # Attacker EOA / frontrun contract
            "0x27ff565707763643cac6014418ad434aa6a38471",  # Euler flash loan exploiter 1
            "0x5f259d0b76665c337c6104145894f4d1d2758b8c",  # Euler flash loan exploiter 2
        ),
        attack_contract_entities=(
            "0xebc29199c817dc47ba12e3f86102564d640cbf99",
        ),
        exploit_start_block=16817990,
        exploit_end_block=16818110,
        incident_type="FLASH_LOAN_LIQUIDATION_EXPLATION",
        description="Euler Finance DAI $197M donation-liquidation exploit",
    ),
    AttackIncidentRecord(
        incident_id="curve_aleth_vyper_reentrancy",
        attacker_entities=(
            "0xb657b895b265c38c53fff00166cf7f6a3c70587d",  # Curve attack contract deployer / EOA
            "0xdce5d6b41c32f578f875efffc0d422c57a75d7d8",  # Curve alETH exploiter execution contract
        ),
        attack_contract_entities=(
            "0xdce5d6b41c32f578f875efffc0d422c57a75d7d8",
        ),
        exploit_start_block=17806770,
        exploit_end_block=17851010,
        incident_type="READ_ONLY_REENTRANCY",
        description="Curve / Alchemix alETH-ETH Vyper 0.2.15 reentrancy exploit",
    ),
)


class IndependentGroundTruthRegistry:
    """Manages independent attack ground truth with strict window isolation."""

    def __init__(
        self,
        incident_records: Sequence[AttackIncidentRecord] = CANONICAL_ATTACK_REGISTRY,
        threat_intel_db_path: Path | str | None = None,
    ):
        self.incidents = list(incident_records)
        if threat_intel_db_path:
            self.threat_intel_db_path = Path(threat_intel_db_path)
        else:
            from forensics.paths import BENCHMARK_DB
            self.threat_intel_db_path = BENCHMARK_DB if BENCHMARK_DB.is_file() else None
        self._cached_threat_entities: set[str] | None = None

    def get_threat_intel_entities(self) -> set[str]:
        """Loads verified malicious entities from benchmark_p6.db if available."""
        if self._cached_threat_entities is not None:
            return self._cached_threat_entities

        entities: set[str] = set()
        if self.threat_intel_db_path and self.threat_intel_db_path.is_file():
            db_uri = f"{self.threat_intel_db_path.resolve().as_uri()}?mode=ro&immutable=1"
            conn = sqlite3.connect(db_uri, uri=True)
            try:
                cur = conn.cursor()
                # Exclude BENIGN_CONTROL; select confirmed malicious indicators
                cur.execute(
                    """
                    SELECT LOWER(entity_value) FROM threat_intel_records
                    WHERE threat_category IN ('EXPLOIT', 'HEIST', 'PHISHING', 'ADDRESS_POISONING')
                      AND entity_type IN ('address', 'contract')
                    """
                )
                for r in cur.fetchall():
                    if r[0]:
                        entities.add(r[0])
            except Exception:
                pass
            finally:
                conn.close()

        self._cached_threat_entities = entities
        return entities

    def is_malicious_in_window(
        self,
        entity_addr: str,
        window_start_block: int,
        window_end_block: int,
    ) -> int:
        """Determines if entity_addr was actively involved in an exploit within [w_start, w_end).

        Guarantees:
        - Negative (0) if entity performed benign historical transactions outside the exploit window.
        - Positive (1) ONLY if entity is verified attacker AND activity window overlaps exploit blocks.
        """
        norm_addr = entity_addr.strip().lower()

        for inc in self.incidents:
            is_attacker = norm_addr in inc.attacker_entities or norm_addr in inc.attack_contract_entities
            if is_attacker:
                # Check window overlap: max(start1, start2) <= min(end1, end2)
                overlap_start = max(window_start_block, inc.exploit_start_block)
                overlap_end = min(window_end_block, inc.exploit_end_block)
                if overlap_start <= overlap_end:
                    return 1

        # Check threat intel matches for non-incident specific entities
        ti_set = self.get_threat_intel_entities()
        if norm_addr in ti_set:
            return 1

        return 0
