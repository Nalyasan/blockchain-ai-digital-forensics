"""Threat intelligence intermediate data model and normalization primitives.

Preserves cryptographic provenance across heterogeneous external security datasets
(CSV, XLSX, JSON) into an immutable, verifiable intermediate representation.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Optional

ETH_ADDRESS_PATTERN = re.compile(r"^(?:0x)?[0-9a-fA-F]{40}$")
TX_HASH_PATTERN = re.compile(r"^(?:0x)?[0-9a-fA-F]{64}$")
FORMULA_PREFIXES = ("=", "@", "+", "-", "\t", "\r")


def current_iso_utc() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def compute_file_sha256(file_path: Path | str) -> str:
    """Compute hex SHA-256 digest of a file on disk."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_payload_sha256(payload: bytes | str) -> str:
    """Compute hex SHA-256 digest of an in-memory string or bytes payload."""
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def is_valid_eth_address(address: Any) -> bool:
    """Validate whether the given string is a 40-hex Ethereum address."""
    if not isinstance(address, str):
        return False
    return bool(ETH_ADDRESS_PATTERN.match(address.strip()))


def normalize_eth_address(address: Any) -> str:
    """Normalize Ethereum address to lowercase 0x-prefixed 40-hex character string.

    Raises:
        ValueError: If address is not a valid 40-hex Ethereum address.
    """
    if not is_valid_eth_address(address):
        raise ValueError(f"Invalid Ethereum address: {address!r}")
    addr_str = str(address).strip().lower()
    if addr_str.startswith("0x"):
        return addr_str
    return f"0x{addr_str}"


def is_valid_tx_hash(tx_hash: Any) -> bool:
    """Validate whether the given string is a 64-hex transaction hash."""
    if not isinstance(tx_hash, str):
        return False
    return bool(TX_HASH_PATTERN.match(tx_hash.strip()))


def normalize_tx_hash(tx_hash: Any) -> str:
    """Normalize transaction hash to lowercase 0x-prefixed 64-hex string.

    Raises:
        ValueError: If tx_hash is not a valid 64-hex hash.
    """
    if not is_valid_tx_hash(tx_hash):
        raise ValueError(f"Invalid transaction hash: {tx_hash!r}")
    h_str = str(tx_hash).strip().lower()
    if h_str.startswith("0x"):
        return h_str
    return f"0x{h_str}"


def sanitize_formula_injection(value: Any) -> Any:
    """Sanitize string values against CSV formula injection (CWE-1236).

    Prefixes '=', '@', '+', '-', '\\t', '\\r' characters with a single apostrophe.
    """
    if not isinstance(value, str):
        return value
    stripped = value.strip()
    if stripped.startswith(FORMULA_PREFIXES):
        return "'" + value
    return value


def sanitize_metadata_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively sanitize string values in a metadata dictionary."""
    sanitized: dict[str, Any] = {}
    for k, v in data.items():
        if isinstance(v, str):
            sanitized[k] = sanitize_formula_injection(v)
        elif isinstance(v, dict):
            sanitized[k] = sanitize_metadata_dict(v)
        elif isinstance(v, list):
            sanitized[k] = [
                sanitize_formula_injection(item) if isinstance(item, str) else item
                for item in v
            ]
        else:
            sanitized[k] = v
    return sanitized


@dataclass(frozen=True)
class ThreatIntelRecord:
    """Immutable, provenance-preserving intermediate threat intelligence record."""

    source_file_path: str
    source_file_sha256: str
    source_commit: str
    row_identifier: str
    raw_payload_sha256: str
    entity_type: str  # "address" | "contract" | "tx_hash"
    entity_value: str  # lowercase normalized 40-hex (or 64-hex)
    threat_category: str  # "PHISHING", "EXPLOIT", "HEIST", "SCAM", "MALICIOUS_CONTRACT", etc.
    threat_sub_tactic: Optional[str] = None
    confidence_score: float = 1.0
    data_source: str = ""
    raw_metadata_json: str = "{}"
    ingestion_timestamp: str = field(default_factory=current_iso_utc)

    def to_dict(self) -> dict[str, Any]:
        """Convert record to a dictionary matching database column names."""
        return asdict(self)


@dataclass
class ThreatIntelBatch:
    """Batch container for ingested threat intelligence records and rejections."""

    source_id: str
    source_name: str
    file_path: str
    file_sha256: str
    source_commit: str
    records: list[ThreatIntelRecord] = field(default_factory=list)
    rejections: list[dict[str, Any]] = field(default_factory=list)
    total_raw_records: int = 0
    valid_records: int = 0
    rejected_records: int = 0
    duplicate_records: int = 0
