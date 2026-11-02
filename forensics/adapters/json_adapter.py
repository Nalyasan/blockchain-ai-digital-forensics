"""Data adapter for MyEtherWallet (MEW) Darklist JSON security datasets.

Reads addresses-darklist.json, normalizes varied date formats (ISO, US short M/D/YY,
empty strings to None), validates 40-hex Ethereum addresses, sanitizes comment fields,
and preserves cryptographic provenance into ThreatIntelBatch instances.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any, Optional

from forensics.adapters.base import (
    ThreatIntelBatch,
    ThreatIntelRecord,
    compute_file_sha256,
    compute_payload_sha256,
    current_iso_utc,
    is_valid_eth_address,
    normalize_eth_address,
    sanitize_formula_injection,
    sanitize_metadata_dict,
)

# Standard MEW Darklist commit hash from discovery manifest
DEFAULT_MEW_COMMIT = "8f86cba9b58db79608ece8fa784775b3c41e2e26"
MAX_JSON_FILE_SIZE = 50 * 1024 * 1024  # 50 MB limit


def normalize_mew_date(raw_date: Any) -> Optional[str]:
    """Normalize varied date format strings to ISO-8601 UTC timestamp or None.

    Supports:
    - ISO format 'YYYY-MM-DD' -> 'YYYY-MM-DDT00:00:00Z'
    - US short legacy 'M/D/YY' (e.g. '7/22/17') -> '2017-07-22T00:00:00Z'
    - US format 'M/D/YYYY' -> 'YYYY-MM-DDT00:00:00Z'
    - Empty strings / null -> None
    """
    if raw_date is None:
        return None
    d_str = str(raw_date).strip()
    if not d_str:
        return None

    # Standard ISO 'YYYY-MM-DD'
    if re.match(r"^\d{4}-\d{2}-\d{2}$", d_str):
        return f"{d_str}T00:00:00Z"

    # US short legacy 'M/D/YY' (e.g. '7/22/17')
    if re.match(r"^\d{1,2}/\d{1,2}/\d{2}$", d_str):
        try:
            parsed = datetime.strptime(d_str, "%m/%d/%y")
            return parsed.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT00:00:00Z")
        except ValueError:
            pass

    # US 'M/D/YYYY'
    if re.match(r"^\d{1,2}/\d{1,2}/\d{4}$", d_str):
        try:
            parsed = datetime.strptime(d_str, "%m/%d/%Y")
            return parsed.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT00:00:00Z")
        except ValueError:
            pass

    # ISO-8601 full string
    try:
        parsed = datetime.fromisoformat(d_str.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass

    return None


def parse_mew_darklist_json(
    file_path: Path | str,
    source_commit: str = DEFAULT_MEW_COMMIT,
    source_id: Optional[str] = None,
) -> ThreatIntelBatch:
    """Parse MEW Darklist JSON file into ThreatIntelBatch.

    Args:
        file_path: Path to addresses-darklist.json.
        source_commit: Authoritative git commit hash.
        source_id: Custom source ID override.

    Returns:
        ThreatIntelBatch with validated records and rejections.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"JSON file not found: {path}")

    file_size = path.stat().st_size
    if file_size > MAX_JSON_FILE_SIZE:
        raise ValueError(f"JSON file exceeds maximum size limit ({file_size} > {MAX_JSON_FILE_SIZE} bytes)")

    file_sha256 = compute_file_sha256(path)
    src_id = source_id or f"mew_{path.stem}"

    batch = ThreatIntelBatch(
        source_id=src_id,
        source_name="mew_darklist",
        file_path=str(path),
        file_sha256=file_sha256,
        source_commit=source_commit,
    )

    with open(path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as exc:
            batch.rejections.append({
                "rejection_id": compute_payload_sha256(f"{file_sha256}:json_syntax_error"),
                "source_file_sha256": file_sha256,
                "row_identifier": "root",
                "raw_payload": str(exc),
                "rejection_reason": f"MALFORMED_JSON_SYNTAX: {exc}",
                "rejected_at": current_iso_utc(),
            })
            batch.rejected_records += 1
            return batch

    if not isinstance(data, list):
        batch.rejections.append({
            "rejection_id": compute_payload_sha256(f"{file_sha256}:root_not_list"),
            "source_file_sha256": file_sha256,
            "row_identifier": "root",
            "raw_payload": type(data).__name__,
            "rejection_reason": f"SCHEMA_VIOLATION: Expected root list, got {type(data).__name__}",
            "rejected_at": current_iso_utc(),
        })
        batch.rejected_records += 1
        return batch

    for idx, item in enumerate(data):
        batch.total_raw_records += 1
        row_id = f"item_{idx}"

        if not isinstance(item, dict):
            batch.rejections.append({
                "rejection_id": compute_payload_sha256(f"{file_sha256}:{row_id}:not_dict"),
                "source_file_sha256": file_sha256,
                "row_identifier": row_id,
                "raw_payload": str(item),
                "rejection_reason": f"INVALID_ITEM_TYPE: Expected object, got {type(item).__name__}",
                "rejected_at": current_iso_utc(),
            })
            batch.rejected_records += 1
            continue

        raw_addr = item.get("address")
        raw_comment = item.get("comment", "")
        raw_date = item.get("date")

        raw_payload_bytes = json.dumps(item, sort_keys=True, separators=(",", ":"))
        payload_sha256 = compute_payload_sha256(raw_payload_bytes)

        if not is_valid_eth_address(raw_addr):
            batch.rejections.append({
                "rejection_id": compute_payload_sha256(f"{file_sha256}:{row_id}:invalid_addr"),
                "source_file_sha256": file_sha256,
                "row_identifier": row_id,
                "raw_payload": raw_payload_bytes,
                "rejection_reason": f"INVALID_ADDRESS_SYNTAX: {raw_addr!r}",
                "rejected_at": current_iso_utc(),
            })
            batch.rejected_records += 1
            continue

        normalized_addr = normalize_eth_address(raw_addr)
        normalized_date = normalize_mew_date(raw_date)

        # Sanitize comment against CSV formula injection & prompt injection
        sanitized_comment = sanitize_formula_injection(str(raw_comment)) if raw_comment else None

        metadata_dict = {
            "comment": sanitized_comment,
            "reported_date": normalized_date,
            "original_date": raw_date,
        }
        sanitized_metadata = sanitize_metadata_dict(metadata_dict)

        record = ThreatIntelRecord(
            source_file_path=str(path),
            source_file_sha256=file_sha256,
            source_commit=source_commit,
            row_identifier=row_id,
            raw_payload_sha256=payload_sha256,
            entity_type="address",
            entity_value=normalized_addr,
            threat_category="PHISHING",
            threat_sub_tactic="MEW_DARKLIST",
            confidence_score=1.0,
            data_source="mew_darklist",
            raw_metadata_json=json.dumps(sanitized_metadata, separators=(",", ":")),
            ingestion_timestamp=current_iso_utc(),
        )
        batch.records.append(record)
        batch.valid_records += 1

    return batch


def parse_json_file(
    file_path: Path | str,
    source_commit: str = DEFAULT_MEW_COMMIT,
    source_id: Optional[str] = None,
) -> ThreatIntelBatch:
    """Convenience alias for JSON darklist parsing."""
    return parse_mew_darklist_json(file_path, source_commit, source_id)
