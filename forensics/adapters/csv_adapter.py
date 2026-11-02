"""Data adapter for Forta Web3 threat intelligence CSV datasets.

Parses phishing_scams.csv, malicious_smart_contracts.csv, and etherscan_malicious_labels.csv.
Sanitizes formula injection characters, validates 40-hex Ethereum addresses, and preserves
cryptographic provenance into ThreatIntelBatch instances.
"""
from __future__ import annotations

import csv
from datetime import datetime, timezone
import json
from pathlib import Path
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

# Standard Forta commit hash from discovery manifest
DEFAULT_FORTA_COMMIT = "40a9c2f2bd7e9ddfdd0f3540db589f0288e1e88a"

CATEGORY_MAPPING = {
    "phish-hack": "PHISHING",
    "phishing": "PHISHING",
    "exploit": "EXPLOIT",
    "heist": "HEIST",
    "scam": "SCAM",
    "malicious_contract": "MALICIOUS_CONTRACT",
    "malicious-smart-contract": "MALICIOUS_CONTRACT",
    "etherscan-phish-hack-list": "PHISHING",
    "etherscan-exploit-list": "EXPLOIT",
    "etherscan-heist-list": "HEIST",
}


def map_threat_category(raw_val: Optional[str]) -> str:
    """Map external threat label string to canonical threat category."""
    if not raw_val:
        return "UNKNOWN_THREAT"
    normalized = str(raw_val).strip().lower()
    return CATEGORY_MAPPING.get(normalized, "UNKNOWN_THREAT")


def parse_forta_csv(
    file_path: Path | str,
    source_commit: str = DEFAULT_FORTA_COMMIT,
    source_id: Optional[str] = None,
) -> ThreatIntelBatch:
    """Parse a Forta threat intelligence CSV dataset into ThreatIntelBatch.

    Args:
        file_path: Path to CSV dataset file.
        source_commit: Authoritative git commit hash.
        source_id: Unique identifier for this data source.

    Returns:
        ThreatIntelBatch containing verified records and rejections.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"CSV file not found: {path}")

    file_sha256 = compute_file_sha256(path)
    file_name = path.name.lower()
    src_id = source_id or f"forta_{path.stem}"

    batch = ThreatIntelBatch(
        source_id=src_id,
        source_name="forta",
        file_path=str(path),
        file_sha256=file_sha256,
        source_commit=source_commit,
    )

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if not header:
            return batch

        # Normalize header column names
        header_cols = [c.strip().lower() for c in header]

        # Determine file schema type
        is_phishing_scams = "is_contract" in header_cols and "etherscan_labels" in header_cols
        is_smart_contracts = "contract_address" in header_cols and "contract_creator" in header_cols
        is_etherscan_labels = "banned_address" in header_cols and "wallet_tag" in header_cols

        line_number = 1
        for row in reader:
            line_number += 1
            batch.total_raw_records += 1
            raw_line = ",".join(row)
            payload_sha256 = compute_payload_sha256(raw_line)
            row_id = str(line_number)

            if len(row) < len(header_cols):
                batch.rejections.append({
                    "rejection_id": compute_payload_sha256(f"{file_sha256}:{row_id}:short_row"),
                    "source_file_sha256": file_sha256,
                    "row_identifier": row_id,
                    "raw_payload": raw_line,
                    "rejection_reason": f"MALFORMED_ROW: expected {len(header_cols)} columns, got {len(row)}",
                    "rejected_at": current_iso_utc(),
                })
                batch.rejected_records += 1
                continue

            row_dict = {
                header_cols[i]: sanitize_formula_injection(row[i])
                for i in range(min(len(header_cols), len(row)))
            }

            # Extract address and metadata per schema
            raw_addr: str = ""
            entity_type = "address"
            category = "UNKNOWN_THREAT"
            sub_tactic: Optional[str] = None
            conf_score = 1.0

            if is_phishing_scams:
                raw_addr = row_dict.get("address", "").strip()
                is_contract_val = str(row_dict.get("is_contract", "")).strip().lower() == "true"
                if is_contract_val:
                    entity_type = "contract"
                category = map_threat_category(row_dict.get("etherscan_labels"))
                sub_tactic = row_dict.get("etherscan_tag") or None

            elif is_smart_contracts:
                raw_addr = row_dict.get("contract_address", "").strip()
                entity_type = "contract"
                creator_label = row_dict.get("contract_creator_etherscan_label")
                contract_tag = row_dict.get("contract_tag")
                category = map_threat_category(creator_label or contract_tag)
                sub_tactic = contract_tag or None

            elif is_etherscan_labels:
                raw_addr = row_dict.get("banned_address", "").strip()
                data_source_val = row_dict.get("data_source")
                category = map_threat_category(data_source_val)
                sub_tactic = row_dict.get("wallet_tag") or None

            else:
                # Fallback heuristic for generic CSV
                for cand in ("address", "contract_address", "banned_address", "addr"):
                    if cand in row_dict:
                        raw_addr = row_dict[cand].strip()
                        break
                label_val = row_dict.get("label") or row_dict.get("category") or row_dict.get("threat_type")
                category = map_threat_category(label_val)

            # Validate address syntax
            if not is_valid_eth_address(raw_addr):
                batch.rejections.append({
                    "rejection_id": compute_payload_sha256(f"{file_sha256}:{row_id}:invalid_addr"),
                    "source_file_sha256": file_sha256,
                    "row_identifier": row_id,
                    "raw_payload": raw_line,
                    "rejection_reason": f"INVALID_ADDRESS_SYNTAX: {raw_addr!r}",
                    "rejected_at": current_iso_utc(),
                })
                batch.rejected_records += 1
                continue

            normalized_addr = normalize_eth_address(raw_addr)
            metadata_sanitized = sanitize_metadata_dict(row_dict)

            record = ThreatIntelRecord(
                source_file_path=str(path),
                source_file_sha256=file_sha256,
                source_commit=source_commit,
                row_identifier=row_id,
                raw_payload_sha256=payload_sha256,
                entity_type=entity_type,
                entity_value=normalized_addr,
                threat_category=category,
                threat_sub_tactic=sub_tactic,
                confidence_score=conf_score,
                data_source="forta",
                raw_metadata_json=json.dumps(metadata_sanitized, separators=(",", ":")),
                ingestion_timestamp=current_iso_utc(),
            )
            batch.records.append(record)
            batch.valid_records += 1

    return batch


def parse_csv_file(
    file_path: Path | str,
    source_commit: str = DEFAULT_FORTA_COMMIT,
    source_id: Optional[str] = None,
) -> ThreatIntelBatch:
    """Convenience alias for CSV parsing."""
    return parse_forta_csv(file_path, source_commit, source_id)
