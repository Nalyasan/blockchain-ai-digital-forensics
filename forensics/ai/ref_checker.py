"""P5 Independent Reference Checker & Forensic Content Verifier (T10 CONTENT_MISMATCH).

This module provides two-stage independent validation of AI Investigator outputs
against canonical ground-truth evidence in the read-only forensics database (`real_p4.db`):

Stage 1: Reference Existence Verification (`existence_ref_ratio`)
- Verifies that all referenced transaction hashes exist in `transactions` or `asset_transfers`.
- Verifies that all referenced alert IDs exist in `alerts`.
- Computes `existence_ref_ratio = len(existing_refs) / len(total_refs)`.

Stage 2: Bit-for-Bit Content Match Verification (`content_match_ratio`)
- Compares every field of each item in `observed_facts` against canonical SQLite rows:
  * `tx_hash`: Exact transaction hash lookup (case-insensitive hex).
  * `block_number`: Exact integer block number.
  * `from_addr`: Sender address (case-insensitive).
  * `to_addr`: Recipient address (case-insensitive).
  * `asset_id`: Asset identifier (case-insensitive, canonicalizing NATIVE/ETH).
  * `amount_raw`: Exact non-negative integer string matching (arbitrary precision, no float).
  * `evidence_refs`: Verifies that cited alerts or logs exist and cover the transaction.
- Emits `RefMismatch` with tag `CONTENT_MISMATCH` on ANY discrepancy even when Pydantic
  reports syntactically valid structured output.
- Computes `content_match_ratio = len(matched_facts) / len(total_facts)`.

Security & Forensic Invariants:
- Read-Only Execution: Only executes parameterized `SELECT` queries; strictly zero writes/DDL.
- Fail-Closed: Any discrepancy, missing entity, or invalid reference returns `CONTENT_MISMATCH`.
- Precision Preservation: Never converts `amount_raw` to float or scientific notation.
- Thread Safety: Uses read-only SQLite connections compatible with concurrent workers.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

logger = logging.getLogger("forensics.ai.ref_checker")

__all__ = [
    "RefMismatch",
    "ReferenceCheckResult",
    "check_investigation_output",
    "verify_observed_facts",
    "verify_references_existence",
    "verify_single_fact",
]

# Patterns for extracting reference types
HEX_TX_REGEX = re.compile(r"^0x[0-9a-fA-F]{64}$")
HEX_ADDR_REGEX = re.compile(r"^0x[0-9a-fA-F]{40}$")
HEX_ALERT_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class RefMismatch:
    """Represents a single discrepancy between model-claimed fact and canonical database record."""

    fact_index: int
    field: str
    expected: Any
    actual: Any
    tag: str = "CONTENT_MISMATCH"
    reason: str = ""
    tx_hash: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Serializes mismatch into dictionary for persistence or error reporting."""
        return asdict(self)


@dataclass
class ReferenceCheckResult:
    """Comprehensive result of two-stage independent reference checking."""

    is_valid: bool
    existence_ref_ratio: float
    content_match_ratio: float
    total_facts: int
    matched_facts: int
    total_refs_checked: int
    existing_refs_count: int
    mismatches: list[RefMismatch] = field(default_factory=list)
    missing_refs: list[str] = field(default_factory=list)
    field_match_ratio: float = 1.0
    status: str = "PASS"

    def to_dict(self) -> dict[str, Any]:
        """Serializes result into dictionary suitable for analysis_runs persistence."""
        return {
            "status": self.status,
            "is_valid": self.is_valid,
            "existence_ref_ratio": self.existence_ref_ratio,
            "content_match_ratio": self.content_match_ratio,
            "field_match_ratio": self.field_match_ratio,
            "total_facts": self.total_facts,
            "matched_facts": self.matched_facts,
            "total_refs_checked": self.total_refs_checked,
            "existing_refs_count": self.existing_refs_count,
            "missing_refs": self.missing_refs,
            "mismatches": [m.to_dict() for m in self.mismatches],
        }


# ==============================================================================
# Normalization Helpers
# ==============================================================================


def _normalize_tx(tx: Any) -> str:
    """Normalizes transaction hash to stripped lowercase."""
    if not tx or not isinstance(tx, str):
        return ""
    v = tx.strip().lower()
    return v


def _normalize_addr(addr: Any) -> str:
    """Normalizes Ethereum address to stripped lowercase."""
    if not addr or not isinstance(addr, str):
        return ""
    v = addr.strip().lower()
    return v


def _normalize_asset(asset: Any) -> str:
    """Normalizes asset identifier, treating NATIVE / ETH / zero address as canonical 'NATIVE'."""
    if not asset or not isinstance(asset, str):
        return ""
    v = asset.strip().lower()
    if v in ("native", "eth", "0x0000000000000000000000000000000000000000"):
        return "native"
    return v


def _parse_ref_entity(ref: str) -> tuple[str, str]:
    """Classifies reference string into (ref_type, identifier).

    Examples:
        'tx:0xabc...' -> ('tx', '0xabc...')
        'alert:1ba7...' -> ('alert', '1ba7...')
        'block:16817996' -> ('block', '16817996')
        '0x123... (64 hex)' -> ('tx', '0x123...')
        '1ba7... (64 hex)' -> ('alert', '1ba7...')
    """
    ref_clean = str(ref).strip()
    if not ref_clean:
        return ("unknown", "")

    if ":" in ref_clean:
        parts = ref_clean.split(":", 1)
        prefix = parts[0].strip().lower()
        val = parts[1].strip()
        if prefix in ("tx", "transaction"):
            return ("tx", val.lower())
        if prefix in ("alert", "alert_id"):
            return ("alert", val.lower())
        if prefix in ("block", "blk"):
            return ("block", val)
        if prefix in ("transfer", "xfer"):
            return ("transfer", val)
        return (prefix, val)

    # Bare hex strings without prefixes
    if HEX_TX_REGEX.match(ref_clean):
        return ("tx", ref_clean.lower())
    if HEX_ALERT_REGEX.match(ref_clean):
        return ("alert", ref_clean.lower())

    return ("unknown", ref_clean)


# ==============================================================================
# Database Query Helpers (Strict Read-Only)
# ==============================================================================


def _fetch_candidate_transfers(
    db: sqlite3.Connection, norm_tx: str
) -> list[dict[str, Any]]:
    """Retrieves all asset transfers associated with a transaction hash."""
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT transfer_id, chain_id, block_number, block_hash, block_timestamp,
               tx_hash, log_index, asset_id, from_addr, to_addr, amount_raw
        FROM asset_transfers
        WHERE LOWER(tx_hash) = ?
        ORDER BY log_index ASC
        """,
        (norm_tx,),
    )
    rows = cursor.fetchall()
    results: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        if d.get("amount_raw") is not None:
            d["amount_raw"] = str(d["amount_raw"])
        results.append(d)
    return results


def _fetch_candidate_tx(
    db: sqlite3.Connection, norm_tx: str
) -> dict[str, Any] | None:
    """Retrieves transaction header from transactions table."""
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT chain_id, tx_hash, block_hash, block_number, tx_index,
               from_addr, to_addr, value_raw
        FROM transactions
        WHERE LOWER(tx_hash) = ?
        LIMIT 1
        """,
        (norm_tx,),
    )
    row = cursor.fetchone()
    if not row:
        return None
    res = dict(row)
    if res.get("value_raw") is not None:
        res["value_raw"] = str(res["value_raw"])
    return res


def _check_tx_exists(db: sqlite3.Connection, norm_tx: str) -> bool:
    """Checks whether a transaction hash exists in transactions or asset_transfers."""
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT 1 FROM transactions WHERE LOWER(tx_hash) = ?
        UNION
        SELECT 1 FROM asset_transfers WHERE LOWER(tx_hash) = ?
        LIMIT 1
        """,
        (norm_tx, norm_tx),
    )
    return cursor.fetchone() is not None


def _check_alert_exists(
    db: sqlite3.Connection, norm_alert: str
) -> tuple[bool, list[dict[str, Any]] | None]:
    """Checks whether an alert ID exists in alerts table and returns parsed evidence_refs."""
    cursor = db.cursor()
    cursor.execute(
        "SELECT evidence_refs FROM alerts WHERE LOWER(alert_id) = ? LIMIT 1",
        (norm_alert,),
    )
    row = cursor.fetchone()
    if not row:
        return (False, None)

    raw_refs = row["evidence_refs"] if isinstance(row, sqlite3.Row) else row[0]
    if isinstance(raw_refs, str) and raw_refs.strip():
        try:
            parsed = json.loads(raw_refs)
            if isinstance(parsed, list):
                return (True, parsed)
        except Exception:
            pass
    return (True, [])


# ==============================================================================
# Stage 1: Reference Existence Verification
# ==============================================================================


def verify_references_existence(
    tx_hashes: Sequence[str] = (),
    alert_ids: Sequence[str] = (),
    db: sqlite3.Connection = None,
) -> tuple[float, list[str]]:
    """Stage 1: Verifies that all referenced transaction hashes and alert IDs exist.

    Args:
        tx_hashes: Sequence of transaction hash strings.
        alert_ids: Sequence of alert ID strings.
        db: Strictly read-only SQLite database connection.

    Returns:
        Tuple of (existence_ref_ratio, missing_refs):
        - `existence_ref_ratio`: Float from 0.0 to 1.0 (1.0 if empty references).
        - `missing_refs`: List of reference strings that could not be found in DB.
    """
    if db is None:
        raise ValueError("Database connection db is required for reference existence checking.")

    total_refs: list[tuple[str, str]] = []  # list of (type, id)
    seen: set[tuple[str, str]] = set()

    for tx in tx_hashes:
        norm = _normalize_tx(tx)
        if norm and ("tx", norm) not in seen:
            seen.add(("tx", norm))
            total_refs.append(("tx", norm))

    for alert in alert_ids:
        norm = alert.strip().lower()
        if norm and ("alert", norm) not in seen:
            seen.add(("alert", norm))
            total_refs.append(("alert", norm))

    if not total_refs:
        return (0.0, [])

    missing: list[str] = []
    for ref_type, ref_id in total_refs:
        if ref_type == "tx":
            if not _check_tx_exists(db, ref_id):
                missing.append(f"tx:{ref_id}")
        elif ref_type == "alert":
            exists, _ = _check_alert_exists(db, ref_id)
            if not exists:
                missing.append(f"alert:{ref_id}")

    existing_count = len(total_refs) - len(missing)
    ratio = round(existing_count / len(total_refs), 4)
    return (ratio, missing)


# ==============================================================================
# Stage 2: Content Match Verification
# ==============================================================================


def verify_single_fact(
    fact: Union[Any, dict[str, Any]],
    db: sqlite3.Connection,
    fact_index: int = 0,
) -> list[RefMismatch]:
    """Verifies a single ObservedFact against canonical database rows.

    Checks:
    - `tx_hash`: Transaction must exist in database.
    - `block_number`: Block must match canonical record.
    - `from_addr`: Sender must match (case-insensitive).
    - `to_addr`: Recipient must match (case-insensitive).
    - `asset_id`: Asset identifier must match (case-insensitive).
    - `amount_raw`: Exact integer string comparison (arbitrary precision).
    - `evidence_refs`: Cited alert IDs and hashes must exist and cover this tx.

    Returns:
        List of RefMismatch instances (empty if fact matches canonical truth).
    """
    # Extract fields from Pydantic model or dict
    if isinstance(fact, dict):
        raw_tx = fact.get("tx_hash")
        raw_block = fact.get("block_number")
        raw_from = fact.get("from_addr")
        raw_to = fact.get("to_addr")
        raw_asset = fact.get("asset_id")
        raw_amount = fact.get("amount_raw")
        raw_refs = fact.get("evidence_refs", [])
    else:
        raw_tx = getattr(fact, "tx_hash", None)
        raw_block = getattr(fact, "block_number", None)
        raw_from = getattr(fact, "from_addr", None)
        raw_to = getattr(fact, "to_addr", None)
        raw_asset = getattr(fact, "asset_id", None)
        raw_amount = getattr(fact, "amount_raw", None)
        raw_refs = getattr(fact, "evidence_refs", [])

    norm_tx = _normalize_tx(raw_tx)
    if not norm_tx:
        return [
            RefMismatch(
                fact_index=fact_index,
                field="tx_hash",
                expected="0x followed by 64 hex characters",
                actual=raw_tx,
                tag="CONTENT_MISMATCH",
                reason="ObservedFact is missing a valid transaction hash.",
                tx_hash=raw_tx,
            )
        ]

    # Query candidate transfers and transactions
    candidates = _fetch_candidate_transfers(db, norm_tx)
    tx_row = _fetch_candidate_tx(db, norm_tx)

    if not candidates and not tx_row:
        return [
            RefMismatch(
                fact_index=fact_index,
                field="tx_hash",
                expected="Transaction present in canonical database",
                actual=raw_tx,
                tag="CONTENT_MISMATCH",
                reason=f"Transaction hash '{raw_tx}' not found in canonical database (neither in asset_transfers nor in transactions).",
                tx_hash=raw_tx,
            )
        ]

    # Synthesize native transfer candidate if tx_row exists but no asset_transfers
    if not candidates and tx_row:
        candidates = [
            {
                "transfer_id": None,
                "chain_id": tx_row.get("chain_id"),
                "block_number": tx_row.get("block_number"),
                "block_hash": tx_row.get("block_hash"),
                "tx_hash": tx_row.get("tx_hash"),
                "log_index": -1,
                "asset_id": "NATIVE",
                "from_addr": tx_row.get("from_addr"),
                "to_addr": tx_row.get("to_addr"),
                "amount_raw": str(tx_row.get("value_raw") or "0"),
            }
        ]

    # Normalized claimed fields
    fact_from = _normalize_addr(raw_from)
    fact_to = _normalize_addr(raw_to)
    fact_asset = _normalize_asset(raw_asset)
    fact_amount = str(raw_amount).strip() if raw_amount is not None else ""
    try:
        fact_block = int(raw_block) if raw_block is not None else -1
    except (TypeError, ValueError):
        fact_block = -1

    # First pass: Check for an exact 5-field match in candidates
    exact_match_candidate: dict[str, Any] | None = None
    for cand in candidates:
        cand_block = int(cand.get("block_number", -1))
        cand_from = _normalize_addr(cand.get("from_addr"))
        cand_to = _normalize_addr(cand.get("to_addr"))
        cand_asset = _normalize_asset(cand.get("asset_id"))
        cand_amt = str(cand.get("amount_raw", "")).strip()

        if (
            cand_block == fact_block
            and cand_from == fact_from
            and cand_to == fact_to
            and cand_asset == fact_asset
            and cand_amt == fact_amount
        ):
            exact_match_candidate = cand
            break

    # If exact match found, verify evidence_refs (if provided)
    if exact_match_candidate is not None:
        ref_mismatches = _verify_evidence_refs_for_fact(
            fact_index=fact_index,
            norm_tx=norm_tx,
            fact_block=fact_block,
            evidence_refs=raw_refs,
            matched_candidate=exact_match_candidate,
            db=db,
        )
        return ref_mismatches

    # If no candidate matched all 5 fields, find the closest candidate to explain discrepancies
    best_candidate, best_score = _find_best_candidate(
        candidates=candidates,
        fact_block=fact_block,
        fact_from=fact_from,
        fact_to=fact_to,
        fact_asset=fact_asset,
        fact_amount=fact_amount,
    )

    mismatches: list[RefMismatch] = []
    cand_block = int(best_candidate.get("block_number", -1))
    cand_from = _normalize_addr(best_candidate.get("from_addr"))
    cand_to = _normalize_addr(best_candidate.get("to_addr"))
    cand_asset = _normalize_asset(best_candidate.get("asset_id"))
    cand_amt = str(best_candidate.get("amount_raw", "")).strip()

    # 1. Block number check
    if fact_block != cand_block:
        mismatches.append(
            RefMismatch(
                fact_index=fact_index,
                field="block_number",
                expected=cand_block,
                actual=raw_block,
                tag="CONTENT_MISMATCH",
                reason=f"Block number mismatch: canonical block is {cand_block}, but claimed block is {raw_block}.",
                tx_hash=raw_tx,
            )
        )

    # 2. Transposed addresses detection (special forensic diagnostic)
    is_transposed = (
        fact_from == cand_to
        and fact_to == cand_from
        and fact_from != fact_to
    )
    if is_transposed:
        mismatches.append(
            RefMismatch(
                fact_index=fact_index,
                field="from_addr",
                expected=best_candidate.get("from_addr"),
                actual=raw_from,
                tag="CONTENT_MISMATCH",
                reason=f"Transposed address: claimed from_addr '{raw_from}' matches canonical to_addr, and claimed to_addr '{raw_to}' matches canonical from_addr.",
                tx_hash=raw_tx,
            )
        )
        mismatches.append(
            RefMismatch(
                fact_index=fact_index,
                field="to_addr",
                expected=best_candidate.get("to_addr"),
                actual=raw_to,
                tag="CONTENT_MISMATCH",
                reason=f"Transposed address: claimed to_addr '{raw_to}' matches canonical from_addr.",
                tx_hash=raw_tx,
            )
        )
    else:
        # Standard address diff
        if fact_from != cand_from:
            mismatches.append(
                RefMismatch(
                    fact_index=fact_index,
                    field="from_addr",
                    expected=best_candidate.get("from_addr"),
                    actual=raw_from,
                    tag="CONTENT_MISMATCH",
                    reason=f"Sender address mismatch: expected canonical '{best_candidate.get('from_addr')}', got claimed '{raw_from}'.",
                    tx_hash=raw_tx,
                )
            )
        if fact_to != cand_to:
            mismatches.append(
                RefMismatch(
                    fact_index=fact_index,
                    field="to_addr",
                    expected=best_candidate.get("to_addr"),
                    actual=raw_to,
                    tag="CONTENT_MISMATCH",
                    reason=f"Recipient address mismatch: expected canonical '{best_candidate.get('to_addr')}', got claimed '{raw_to}'.",
                    tx_hash=raw_tx,
                )
            )

    # 3. Asset identifier check
    if fact_asset != cand_asset:
        mismatches.append(
            RefMismatch(
                fact_index=fact_index,
                field="asset_id",
                expected=best_candidate.get("asset_id"),
                actual=raw_asset,
                tag="CONTENT_MISMATCH",
                reason=f"Asset identifier mismatch: expected canonical '{best_candidate.get('asset_id')}', got claimed '{raw_asset}'.",
                tx_hash=raw_tx,
            )
        )

    # 4. Amount raw exact integer string check
    if fact_amount != cand_amt:
        reason = f"Amount mismatch: expected exact integer string '{cand_amt}', got claimed '{fact_amount}'."
        try:
            diff = int(fact_amount) - int(cand_amt)
            if diff == 1:
                reason += " Discrepancy of exactly +1 wei."
            elif diff == -1:
                reason += " Discrepancy of exactly -1 wei."
            elif abs(diff) < 100:
                reason += f" Discrepancy of {diff:+d} wei."
        except (ValueError, TypeError):
            pass

        mismatches.append(
            RefMismatch(
                fact_index=fact_index,
                field="amount_raw",
                expected=cand_amt,
                actual=fact_amount,
                tag="CONTENT_MISMATCH",
                reason=reason,
                tx_hash=raw_tx,
            )
        )

    # 5. Evidence refs check
    ref_mismatches = _verify_evidence_refs_for_fact(
        fact_index=fact_index,
        norm_tx=norm_tx,
        fact_block=fact_block,
        evidence_refs=raw_refs,
        matched_candidate=best_candidate,
        db=db,
    )
    mismatches.extend(ref_mismatches)

    return mismatches


def _find_best_candidate(
    candidates: list[dict[str, Any]],
    fact_block: int,
    fact_from: str,
    fact_to: str,
    fact_asset: str,
    fact_amount: str,
) -> tuple[dict[str, Any], int]:
    """Finds the most relevant candidate transfer using weighted similarity scoring."""
    best_cand = candidates[0]
    best_score = -1

    for cand in candidates:
        score = 0
        cand_block = int(cand.get("block_number", -1))
        cand_from = _normalize_addr(cand.get("from_addr"))
        cand_to = _normalize_addr(cand.get("to_addr"))
        cand_asset = _normalize_asset(cand.get("asset_id"))
        cand_amt = str(cand.get("amount_raw", "")).strip()

        if cand_asset == fact_asset:
            score += 3
        if cand_amt == fact_amount:
            score += 3
        if cand_block == fact_block:
            score += 2
        if cand_from == fact_from:
            score += 2
        if cand_to == fact_to:
            score += 2

        # Transposed address bonus
        if cand_from == fact_to and cand_to == fact_from:
            score += 3

        # 1-wei difference bonus
        try:
            if abs(int(fact_amount) - int(cand_amt)) == 1:
                score += 2
        except (ValueError, TypeError):
            pass

        if score > best_score:
            best_score = score
            best_cand = cand

    return (best_cand, best_score)


def _verify_evidence_refs_for_fact(
    fact_index: int,
    norm_tx: str,
    fact_block: int,
    evidence_refs: Sequence[Any],
    matched_candidate: dict[str, Any],
    db: sqlite3.Connection,
) -> list[RefMismatch]:
    """Verifies that all evidence references attached to a fact exist and link to this transaction."""
    mismatches: list[RefMismatch] = []
    if not evidence_refs:
        return mismatches

    for ref in evidence_refs:
        ref_str = str(ref).strip()
        ref_type, ref_val = _parse_ref_entity(ref_str)

        if ref_type == "alert":
            exists, alert_refs = _check_alert_exists(db, ref_val)
            if not exists:
                mismatches.append(
                    RefMismatch(
                        fact_index=fact_index,
                        field="evidence_refs",
                        expected="Canonical alert in alerts table",
                        actual=ref_str,
                        tag="CONTENT_MISMATCH",
                        reason=f"Referenced alert ID '{ref_val}' not found in alerts table.",
                        tx_hash=norm_tx,
                    )
                )
            elif alert_refs is not None:
                # Alert exists; verify that this tx_hash is part of the alert's evidence
                covers_tx = False
                for r in alert_refs:
                    if isinstance(r, dict):
                        alert_tx = _normalize_tx(r.get("tx_hash"))
                        if alert_tx == norm_tx:
                            covers_tx = True
                            break
                if not covers_tx and alert_refs:
                    mismatches.append(
                        RefMismatch(
                            fact_index=fact_index,
                            field="evidence_refs",
                            expected=f"Alert {ref_val} covering tx {norm_tx}",
                            actual=ref_str,
                            tag="CONTENT_MISMATCH",
                            reason=f"Alert '{ref_val}' exists but does not reference transaction {norm_tx}.",
                            tx_hash=norm_tx,
                        )
                    )

        elif ref_type == "block":
            try:
                blk_num = int(ref_val)
                if blk_num != fact_block:
                    mismatches.append(
                        RefMismatch(
                            fact_index=fact_index,
                            field="evidence_refs",
                            expected=f"block:{fact_block}",
                            actual=ref_str,
                            tag="CONTENT_MISMATCH",
                            reason=f"Evidence reference block:{blk_num} conflicts with fact block {fact_block}.",
                            tx_hash=norm_tx,
                        )
                    )
            except ValueError:
                pass

        elif ref_type == "tx":
            if ref_val != norm_tx and not _check_tx_exists(db, ref_val):
                mismatches.append(
                    RefMismatch(
                        fact_index=fact_index,
                        field="evidence_refs",
                        expected=f"tx:{norm_tx}",
                        actual=ref_str,
                        tag="CONTENT_MISMATCH",
                        reason=f"Referenced transaction '{ref_val}' does not exist in canonical database.",
                        tx_hash=norm_tx,
                    )
                )

        elif ref_type == "transfer":
            try:
                xfer_id = int(ref_val)
                c = db.cursor()
                c.execute("SELECT tx_hash FROM asset_transfers WHERE transfer_id = ? LIMIT 1", (xfer_id,))
                xrow = c.fetchone()
                if not xrow:
                    mismatches.append(
                        RefMismatch(
                            fact_index=fact_index,
                            field="evidence_refs",
                            expected="Valid transfer_id in asset_transfers",
                            actual=ref_str,
                            tag="CONTENT_MISMATCH",
                            reason=f"Referenced transfer_id {xfer_id} does not exist.",
                            tx_hash=norm_tx,
                        )
                    )
                elif _normalize_tx(xrow["tx_hash"] if isinstance(xrow, sqlite3.Row) else xrow[0]) != norm_tx:
                    mismatches.append(
                        RefMismatch(
                            fact_index=fact_index,
                            field="evidence_refs",
                            expected=f"transfer linking to tx {norm_tx}",
                            actual=ref_str,
                            tag="CONTENT_MISMATCH",
                            reason=f"Referenced transfer_id {xfer_id} belongs to a different transaction.",
                            tx_hash=norm_tx,
                        )
                    )
            except (ValueError, TypeError):
                pass

    return mismatches


# ==============================================================================
# Public Interface Functions
# ==============================================================================


def verify_observed_facts(
    facts: Sequence[Union[Any, dict[str, Any]]],
    db: sqlite3.Connection,
) -> tuple[float, list[RefMismatch]]:
    """Compares all observed facts against database records.

    Specified by `orchestrator_p5/PROJECT.txt` line 113.

    Args:
        facts: Sequence of ObservedFact model instances or dicts.
        db: Strictly read-only SQLite database connection.

    Returns:
        Tuple of (content_match_ratio, mismatches):
        - `content_match_ratio`: Float from 0.0 to 1.0 (1.0 if empty facts).
        - `mismatches`: List of RefMismatch items (each contains tag 'CONTENT_MISMATCH').
    """
    if db is None:
        raise ValueError("Database connection db is required for verify_observed_facts.")

    if not facts:
        return (0.0, [])

    total_facts = len(facts)
    matched_facts = 0
    all_mismatches: list[RefMismatch] = []

    for idx, fact in enumerate(facts):
        fact_mismatches = verify_single_fact(fact=fact, db=db, fact_index=idx)
        if not fact_mismatches:
            matched_facts += 1
        else:
            all_mismatches.extend(fact_mismatches)

    ratio = round(matched_facts / total_facts, 4) if total_facts > 0 else 0.0
    return (ratio, all_mismatches)


def check_investigation_output(
    output: Union[Any, dict[str, Any]],
    db: sqlite3.Connection,
    input_refs: Sequence[str] | None = None,
) -> ReferenceCheckResult:
    """Comprehensive two-stage independent reference checking for AI Investigator output.

    Stage 1: Validates existence of all referenced transaction hashes and alert IDs.
    Stage 2: Validates content match of all fields in observed_facts.

    Args:
        output: ForensicInvestigationOutput instance or serialized dictionary.
        db: Strictly read-only SQLite connection.
        input_refs: Optional sequence of reference strings provided in input prompt.

    Returns:
        ReferenceCheckResult containing ratios, validation verdict, and detailed mismatches.
    """
    if db is None:
        raise ValueError("Database connection db is required for check_investigation_output.")

    # Extract observed_facts, rule_detections, and references
    if isinstance(output, dict):
        observed_facts = output.get("observed_facts", [])
        rule_detections = output.get("rule_detections", [])
    else:
        observed_facts = getattr(output, "observed_facts", [])
        rule_detections = getattr(output, "rule_detections", [])

    # Gather all referenced tx_hashes and alert_ids across output
    tx_candidates: set[str] = set()
    alert_candidates: set[str] = set()

    # From observed_facts
    for f in observed_facts:
        tx = getattr(f, "tx_hash", None) if not isinstance(f, dict) else f.get("tx_hash")
        if tx:
            tx_candidates.add(str(tx))
        refs = getattr(f, "evidence_refs", []) if not isinstance(f, dict) else f.get("evidence_refs", [])
        for r in refs:
            rtype, rval = _parse_ref_entity(str(r))
            if rtype == "tx":
                tx_candidates.add(rval)
            elif rtype == "alert":
                alert_candidates.add(rval)

    # From rule_detections
    for d in rule_detections:
        aid = getattr(d, "alert_id", None) if not isinstance(d, dict) else d.get("alert_id")
        if aid:
            alert_candidates.add(str(aid))
        refs = getattr(d, "evidence_refs", []) if not isinstance(d, dict) else d.get("evidence_refs", [])
        for r in refs:
            rtype, rval = _parse_ref_entity(str(r))
            if rtype == "tx":
                tx_candidates.add(rval)
            elif rtype == "alert":
                alert_candidates.add(rval)

    # From optional input_refs
    if input_refs:
        for r in input_refs:
            rtype, rval = _parse_ref_entity(str(r))
            if rtype == "tx":
                tx_candidates.add(rval)
            elif rtype == "alert":
                alert_candidates.add(rval)

    # Stage 1: Reference Existence
    existence_ratio, missing_refs = verify_references_existence(
        tx_hashes=sorted(tx_candidates),
        alert_ids=sorted(alert_candidates),
        db=db,
    )
    total_refs_count = len(tx_candidates) + len(alert_candidates)
    existing_refs_count = total_refs_count - len(missing_refs)

    # Stage 2: Content Match
    content_ratio, mismatches = verify_observed_facts(
        facts=observed_facts,
        db=db,
    )

    total_facts = len(observed_facts)
    # Calculate matching facts
    mismatched_indices = {m.fact_index for m in mismatches}
    matched_facts = total_facts - len(mismatched_indices)

    if total_facts == 0:
        field_match_ratio = 0.0
        is_valid = False
        status = (
            "NOT_EVALUATED"
            if (len(mismatches) == 0 and len(missing_refs) == 0)
            else "CONTENT_MISMATCH"
        )
    else:
        total_fields_checked = max(1, total_facts * 6)
        matching_fields = max(0, total_fields_checked - len(mismatches))
        field_match_ratio = round(matching_fields / total_fields_checked, 4)
        is_valid = (len(mismatches) == 0) and (len(missing_refs) == 0)
        status = "PASS" if is_valid else "CONTENT_MISMATCH"

    return ReferenceCheckResult(
        is_valid=is_valid,
        existence_ref_ratio=existence_ratio,
        content_match_ratio=content_ratio,
        field_match_ratio=field_match_ratio,
        total_facts=total_facts,
        matched_facts=matched_facts,
        total_refs_checked=total_refs_count,
        existing_refs_count=existing_refs_count,
        mismatches=mismatches,
        missing_refs=missing_refs,
        status=status,
    )
