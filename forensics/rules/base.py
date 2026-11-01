"""Base models, utilities, and abstract rule definitions for Phase 4 Rule Engine."""
import hashlib
import json
import math
import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Mapping

from forensics.persistence import insert_verified

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


def is_zero_address(addr: str | None) -> bool:
    """Check if address is zero address (0x0...0) or null."""
    if not addr:
        return True
    a = addr.strip().lower()
    return a == ZERO_ADDRESS or a == "0x" + "0" * 40


def normalize_address(addr: str | None) -> str:
    """Normalize address to lowercase standard string."""
    return addr.strip().lower() if addr else ""


def ts_to_iso(ts: int | float | None) -> str:
    """Convert unix timestamp to UTC ISO-8601 string with Z suffix."""
    if ts is None:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return datetime.fromtimestamp(int(ts), timezone.utc).isoformat().replace("+00:00", "Z")


def make_transfer_ref(row: Mapping[str, Any] | sqlite3.Row) -> dict[str, Any]:
    """Build canonical transfer evidence reference dictionary matching asset_transfers."""
    return {
        "chain_id": int(row["chain_id"]),
        "block_number": int(row["block_number"]),
        "block_hash": str(row["block_hash"]),
        "block_timestamp": int(row["block_timestamp"]),
        "tx_hash": str(row["tx_hash"]),
        "log_index": int(row["log_index"]),
        "asset_id": str(row["asset_id"]),
        "from_addr": str(row["from_addr"]),
        "to_addr": str(row["to_addr"]),
        "amount_raw": str(row["amount_raw"]),
    }


def compute_alert_id(
    chain_id: int,
    rule_id: str,
    rule_version: str,
    unit_type: str,
    unit_key: str,
    asset_id: str,
    evidence_refs: list[dict[str, Any]],
) -> str:
    """Compute deterministic SHA-256 alert ID from canonical tuple and sorted evidence identities."""
    identities = sorted(
        f"{r['chain_id']}:{r['block_hash']}:{r['tx_hash']}:{r['log_index']}"
        for r in evidence_refs
    )
    payload = {
        "chain_id": int(chain_id),
        "rule_id": str(rule_id),
        "rule_version": str(rule_version),
        "unit_type": str(unit_type),
        "unit_key": str(unit_key),
        "asset_id": str(asset_id),
        "evidence_identities": identities,
    }
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def calculate_percentile(sorted_amounts: list[int], percentile: float) -> int:
    """Compute exact nearest-rank percentile on a sorted list of integer amounts."""
    if not sorted_amounts:
        raise ValueError("Cannot calculate percentile of an empty list")
    n = len(sorted_amounts)
    # Nearest rank index formula (1-based rank converted to 0-based index)
    rank = math.ceil((percentile / 100.0) * n)
    idx = max(0, min(n - 1, rank - 1))
    return sorted_amounts[idx]


def calculate_snapshot_hash(rows: list[Mapping[str, Any] | sqlite3.Row]) -> str:
    """Calculate deterministic SHA-256 snapshot hash of calibration transfer rows."""
    canonical = [
        f"{r['chain_id']}:{r['block_hash']}:{r['tx_hash']}:{r['log_index']}:{r['amount_raw']}"
        for r in rows
    ]
    canonical.sort()
    return hashlib.sha256("\n".join(canonical).encode("utf-8")).hexdigest()


@dataclass
class Alert:
    alert_id: str
    rule_id: str
    rule_version: str
    unit_type: str
    unit_key: str
    asset_id: str
    severity: str
    score: float
    reason: str
    evidence_refs: list[dict[str, Any]]
    window_start: str
    window_end: str
    created_at: str
    status: str = "new"
    synthetic: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "unit_type": self.unit_type,
            "unit_key": self.unit_key,
            "asset_id": self.asset_id,
            "severity": self.severity,
            "score": self.score,
            "reason": self.reason,
            "evidence_refs": self.evidence_refs,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "created_at": self.created_at,
            "status": self.status,
            "synthetic": self.synthetic,
        }

    # Dict-like access for compatibility with verify_refs and existing tests
    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def __contains__(self, key: str) -> bool:
        return hasattr(self, key)

    def keys(self):
        return self.to_dict().keys()

    def values(self):
        return self.to_dict().values()

    def items(self):
        return self.to_dict().items()

    @classmethod
    def from_row(cls, row: Mapping[str, Any] | sqlite3.Row) -> "Alert":
        refs = row["evidence_refs"]
        if isinstance(refs, str):
            refs = json.loads(refs)
        return cls(
            alert_id=str(row["alert_id"]),
            rule_id=str(row["rule_id"]),
            rule_version=str(row["rule_version"]),
            unit_type=str(row["unit_type"]),
            unit_key=str(row["unit_key"]),
            asset_id=str(row["asset_id"]),
            severity=str(row["severity"]),
            score=float(row["score"]),
            reason=str(row["reason"]),
            evidence_refs=refs,
            window_start=str(row["window_start"]),
            window_end=str(row["window_end"]),
            created_at=str(row["created_at"]),
            status=str(row["status"]),
            synthetic=int(row["synthetic"]) if "synthetic" in row and row["synthetic"] is not None else 0,
        )


@dataclass
class CalibrationRecord:
    calibration_id: str
    rule_id: str
    rule_version: str
    chain_id: int
    asset_id: str
    start_block: int | None
    end_block: int | None
    sample_count: int
    percentile: float
    selected_threshold: str
    snapshot_hash: str
    created_at: str
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "calibration_id": self.calibration_id,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "chain_id": self.chain_id,
            "asset_id": self.asset_id,
            "start_block": self.start_block,
            "end_block": self.end_block,
            "sample_count": self.sample_count,
            "percentile": self.percentile,
            "selected_threshold": self.selected_threshold,
            "snapshot_hash": self.snapshot_hash,
            "created_at": self.created_at,
            "notes": self.notes,
        }

    def save_to_db(self, conn: sqlite3.Connection) -> None:
        insert_verified(
            conn, "rule_calibrations", self.to_dict(), ("calibration_id",),
            replay_metadata=("created_at",),
        )


class BaseRule(ABC):
    """Abstract base class for Phase 4 detection rules."""

    rule_id: str
    rule_version: str
    unit_type: str

    @abstractmethod
    def calibrate(
        self,
        conn: sqlite3.Connection,
        chain_id: int,
        cal_start_block: int | None = None,
        cal_end_block: int | None = None,
        **kwargs: Any,
    ) -> dict[str, CalibrationRecord]:
        """Calibrate thresholds from historical canonical transfers."""
        pass

    @abstractmethod
    def evaluate(
        self,
        conn: sqlite3.Connection,
        chain_id: int,
        test_start_block: int | None = None,
        test_end_block: int | None = None,
        calibrations: dict[str, CalibrationRecord] | None = None,
        **kwargs: Any,
    ) -> list[Alert]:
        """Evaluate rule over test window and return alerts."""
        pass
