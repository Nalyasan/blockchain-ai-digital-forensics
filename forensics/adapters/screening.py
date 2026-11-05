"""Entity Screening & Counterparty Cross-Referencing Engine for Gate P6-03.

Connects strictly read-only to real_p4.db to extract on-chain counterparties
from verified Ethereum Mainnet incidents (Euler Finance DAI & Curve alETH),
cross-references them against indexed threat intelligence records in benchmark_p6.db,
and persists verified screening matches into the screening_matches table.

Strict Invariants:
1. Zero writes to real_p4.db or canonical evidence databases (read-only mode + authorizer).
2. Zero INSERT OR REPLACE and zero UPDATE statements in persistence code.
3. Strict adherence to Open World Assumption (unlisted addresses are unknown, not benign).
4. Zero synthetic transaction or dummy block fabrication.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import logging
import os
from pathlib import Path
import sqlite3
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

from forensics.adapters.base import (
    current_iso_utc,
    is_valid_eth_address,
    normalize_eth_address,
)
from forensics.adapters.persistence_benchmark import (
    DEFAULT_BENCHMARK_DB_PATH,
    assert_database_isolation,
)
from forensics.paths import REAL_P4_DB
from forensics.persistence import EvidenceConflictError, insert_verified

logger = logging.getLogger("forensics.adapters.screening")

# Canonical default paths
DEFAULT_REAL_P4_DB_PATH = REAL_P4_DB if REAL_P4_DB.exists() else (REAL_P4_DB.parents[2] / "worktrees" / "p4_real_integration" / "data" / "real_p4.db")

# Non-overlapping incident window boundaries
INCIDENT_BOUNDS: dict[str, tuple[int, int]] = {
    "euler_finance": (16816000, 16818110),
    "curve_aleth": (17700000, 17806830),
}


def _readonly_sqlite_authorizer(
    action: int,
    param1: Optional[str],
    param2: Optional[str],
    db_name: Optional[str],
    trigger_name: Optional[str],
) -> int:
    """SQLite authorizer denying any mutating or schema-modifying actions.

    Enforces read-only operation at the SQLite engine AST evaluation phase.
    """
    prohibited_actions = {
        sqlite3.SQLITE_INSERT,
        sqlite3.SQLITE_UPDATE,
        sqlite3.SQLITE_DELETE,
        sqlite3.SQLITE_DROP_TABLE,
        sqlite3.SQLITE_DROP_INDEX,
        sqlite3.SQLITE_DROP_VIEW,
        sqlite3.SQLITE_DROP_TRIGGER,
        sqlite3.SQLITE_ALTER_TABLE,
        sqlite3.SQLITE_CREATE_TABLE,
        sqlite3.SQLITE_CREATE_INDEX,
        sqlite3.SQLITE_CREATE_VIEW,
        sqlite3.SQLITE_CREATE_TRIGGER,
        sqlite3.SQLITE_ATTACH,
        sqlite3.SQLITE_DETACH,
    }
    if action in prohibited_actions:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def get_readonly_p4_connection(db_path: Path | str = DEFAULT_REAL_P4_DB_PATH) -> sqlite3.Connection:
    """Open a strictly read-only, query-only connection to canonical real_p4.db.

    Guarantees:
    - Connection opened via URI with mode=ro.
    - PRAGMA query_only = ON enforced.
    - Custom SQLite authorizer denying any INSERT, UPDATE, DELETE, or DDL operations.

    Args:
        db_path: Path to real_p4.db SQLite database.

    Returns:
        Hardened read-only sqlite3.Connection.

    Raises:
        FileNotFoundError: If db_path does not exist on disk.
    """
    path_obj = Path(db_path).resolve()
    if not path_obj.exists():
        raise FileNotFoundError(f"Canonical database not found: {path_obj}")

    # Use URI mode=ro for OS-level and SQLite-level read-only enforcement
    uri_path = f"file:///{path_obj.as_posix()}?mode=ro"
    conn = sqlite3.connect(uri_path, uri=True)
    conn.execute("PRAGMA query_only = ON;")
    conn.set_authorizer(_readonly_sqlite_authorizer)
    return conn


@dataclass(frozen=True)
class ScreeningMatch:
    """Represents an entity screening match against threat intelligence records."""

    match_id: str
    target_address: str
    source_incident: str
    canonical_category: str
    match_type: str = "EXACT_MATCH"
    matched_at: str = field(default_factory=current_iso_utc)
    source_file_path: Optional[str] = None
    data_source: Optional[str] = None
    confidence_score: float = 1.0
    threat_sub_tactic: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary matching table screening_matches columns."""
        return {
            "match_id": self.match_id,
            "target_address": self.target_address,
            "source_incident": self.source_incident,
            "canonical_category": self.canonical_category,
            "match_type": self.match_type,
            "matched_at": self.matched_at,
        }


@dataclass
class ScreeningSummary:
    """Telemetry and results summary for an incident screening run."""

    incident: str
    total_addresses_scanned: int
    unique_addresses_scanned: int
    matches_found: int
    matches: list[ScreeningMatch]
    duration_ms: float
    query_latency_ms: float  # average ms per address lookup


def extract_incident_counterparties(
    p4_conn: sqlite3.Connection,
    incident: str,
) -> list[str]:
    """Extract distinct normalized on-chain counterparties for an incident from real_p4.db.

    Queries both asset_transfers and transactions within the calibrated block window.

    Args:
        p4_conn: Read-only SQLite connection to real_p4.db.
        incident: Incident identifier ('euler_finance' or 'curve_aleth').

    Returns:
        Sorted list of distinct normalized lowercase 0x-prefixed 40-hex addresses.

    Raises:
        ValueError: If incident identifier is not recognized.
    """
    if incident not in INCIDENT_BOUNDS:
        raise ValueError(
            f"Unknown incident {incident!r}. Supported incidents: {list(INCIDENT_BOUNDS.keys())}"
        )

    start_block, end_block = INCIDENT_BOUNDS[incident]
    addresses: set[str] = set()

    # 1. Extract from asset_transfers (from_addr and to_addr)
    query_transfers = """
        SELECT DISTINCT from_addr, to_addr
        FROM asset_transfers
        WHERE block_number BETWEEN ? AND ?
    """
    for row in p4_conn.execute(query_transfers, (start_block, end_block)):
        for addr_raw in row:
            if addr_raw and is_valid_eth_address(addr_raw):
                addresses.add(normalize_eth_address(addr_raw))

    # 2. Extract from transactions (from_addr and to_addr)
    query_txs = """
        SELECT DISTINCT from_addr, to_addr
        FROM transactions
        WHERE block_number BETWEEN ? AND ?
    """
    for row in p4_conn.execute(query_txs, (start_block, end_block)):
        for addr_raw in row:
            if addr_raw and is_valid_eth_address(addr_raw):
                addresses.add(normalize_eth_address(addr_raw))

    return sorted(addresses)


def screen_addresses(
    benchmark_conn: sqlite3.Connection,
    addresses: Sequence[str],
    incident_name: str = "ad_hoc",
    chunk_size: int = 500,
) -> list[ScreeningMatch]:
    """Cross-reference a collection of Ethereum addresses against threat_intel_records.

    Performs chunked parameterized lookups to respect SQLite parameter limits.

    Args:
        benchmark_conn: SQLite connection to benchmark_p6.db.
        addresses: Sequence of Ethereum addresses to screen.
        incident_name: Incident name tag for attribution.
        chunk_size: Batch size for SQL IN clause (default: 500).

    Returns:
        List of ScreeningMatch objects for any identified threat matches.
    """
    valid_normalized: list[str] = []
    for a in addresses:
        if a and is_valid_eth_address(a):
            valid_normalized.append(normalize_eth_address(a))

    if not valid_normalized:
        return []

    # Deduplicate while preserving order for deterministic execution
    unique_addrs = list(dict.fromkeys(valid_normalized))
    matches: list[ScreeningMatch] = []

    for i in range(0, len(unique_addrs), chunk_size):
        chunk = unique_addrs[i : i + chunk_size]
        placeholders = ",".join("?" for _ in chunk)
        query = f"""
            SELECT entity_value, threat_category, source_file_path, data_source,
                   confidence_score, threat_sub_tactic
            FROM threat_intel_records
            WHERE entity_value IN ({placeholders})
              AND entity_type IN ('address', 'contract')
        """
        for row in benchmark_conn.execute(query, chunk):
            val, cat, s_path, src, conf, sub = row
            # Deterministic, unique match identifier
            raw_id = f"{val}:{incident_name}:{cat}:{src}"
            hash_digest = hashlib.sha256(raw_id.encode("utf-8")).hexdigest()[:24]
            match_id = f"sm_{hash_digest}"

            match = ScreeningMatch(
                match_id=match_id,
                target_address=val,
                source_incident=incident_name,
                canonical_category=cat,
                match_type="EXACT_MATCH",
                source_file_path=s_path,
                data_source=src,
                confidence_score=float(conf) if conf is not None else 1.0,
                threat_sub_tactic=sub,
            )
            matches.append(match)

    return matches


def screen_single_address(
    benchmark_conn: sqlite3.Connection,
    address: str,
) -> list[dict[str, Any]]:
    """Ad-hoc screening lookup for a single address (e.g. for P5 AI investigator tools).

    Args:
        benchmark_conn: SQLite connection to benchmark_p6.db.
        address: Candidate Ethereum address.

    Returns:
        List of matching threat record summaries, or empty list if no match.
    """
    if not is_valid_eth_address(address):
        return []

    norm_addr = normalize_eth_address(address)
    query = """
        SELECT entity_value, threat_category, threat_sub_tactic, confidence_score,
               data_source, source_file_path, raw_metadata_json, ingestion_timestamp
        FROM threat_intel_records
        WHERE entity_value = ? AND entity_type IN ('address', 'contract')
    """
    results: list[dict[str, Any]] = []
    for row in benchmark_conn.execute(query, (norm_addr,)):
        results.append({
            "address": row[0],
            "threat_category": row[1],
            "threat_sub_tactic": row[2],
            "confidence_score": row[3],
            "data_source": row[4],
            "source_file_path": row[5],
            "raw_metadata": row[6],
            "ingestion_timestamp": row[7],
        })
    return results


def persist_screening_matches(
    benchmark_conn: sqlite3.Connection,
    matches: Sequence[ScreeningMatch],
) -> dict[str, int]:
    """Persist screening matches into benchmark_p6.db table screening_matches.

    Enforces append-only integrity via insert_verified:
    - Zero INSERT OR REPLACE and zero UPDATE statements.
    - Idempotent replays verify identity without duplicate creation.
    - Conflicting identity data raises EvidenceConflictError.

    Args:
        benchmark_conn: SQLite connection to benchmark_p6.db (writable).
        matches: Sequence of ScreeningMatch instances to record.

    Returns:
        Dict with counts: {'total': int, 'inserted': int, 'replay': int}
    """
    if not matches:
        return {"total": 0, "inserted": 0, "replay": 0}

    new_inserts = 0
    replays = 0

    with benchmark_conn:
        for match in matches:
            record_dict = match.to_dict()
            inserted = insert_verified(
                benchmark_conn,
                "screening_matches",
                record_dict,
                keys=("match_id",),
                replay_metadata=("matched_at",),
            )
            if inserted:
                new_inserts += 1
            else:
                replays += 1

    return {"total": len(matches), "inserted": new_inserts, "replay": replays}


def run_incident_screening(
    p4_db_path: Path | str = DEFAULT_REAL_P4_DB_PATH,
    benchmark_db_path: Path | str = DEFAULT_BENCHMARK_DB_PATH,
    persist: bool = True,
) -> dict[str, Any]:
    """Execute end-to-end entity screening for all canonical on-chain incidents.

    Cross-references Euler Finance DAI and Curve alETH counterparties from real_p4.db
    against threat intelligence records in benchmark_p6.db.

    Args:
        p4_db_path: Path to canonical real_p4.db (queried read-only).
        benchmark_db_path: Path to benchmark SQLite database.
        persist: Whether to persist identified matches into screening_matches.

    Returns:
        Structured dictionary containing metrics, counts, and findings for each incident.
    """
    assert_database_isolation(benchmark_db_path)

    # 1. Connect read-only to real_p4.db
    p4_conn = get_readonly_p4_connection(p4_db_path)

    # 2. Connect read-write to benchmark_p6.db
    target_bench_path = Path(benchmark_db_path)
    bench_conn = sqlite3.connect(target_bench_path)
    bench_conn.execute("PRAGMA foreign_keys = ON;")

    summaries: dict[str, ScreeningSummary] = {}
    all_matches: list[ScreeningMatch] = []

    try:
        for incident in ("euler_finance", "curve_aleth"):
            # Extract counterparties
            t0 = time.perf_counter()
            addrs = extract_incident_counterparties(p4_conn, incident)
            extract_duration_ms = (time.perf_counter() - t0) * 1000.0

            # Screen against threat intelligence records
            t_screen = time.perf_counter()
            matches = screen_addresses(bench_conn, addrs, incident_name=incident)
            screen_duration_ms = (time.perf_counter() - t_screen) * 1000.0
            query_latency_ms = (
                screen_duration_ms / len(addrs) if addrs else 0.0
            )

            summary = ScreeningSummary(
                incident=incident,
                total_addresses_scanned=len(addrs),
                unique_addresses_scanned=len(addrs),
                matches_found=len(matches),
                matches=matches,
                duration_ms=screen_duration_ms,
                query_latency_ms=query_latency_ms,
            )
            summaries[incident] = summary
            all_matches.extend(matches)

        # 3. Persist matches if requested
        persist_stats = {"total": 0, "inserted": 0, "replay": 0}
        if persist and all_matches:
            persist_stats = persist_screening_matches(bench_conn, all_matches)

        # Format output
        total_scanned = sum(s.total_addresses_scanned for s in summaries.values())
        total_matches = len(all_matches)

        return {
            "status": "SUCCESS",
            "benchmark_db": str(benchmark_db_path),
            "total_addresses_scanned": total_scanned,
            "total_matches_found": total_matches,
            "persistence": persist_stats,
            "incidents": {
                inc: {
                    "scanned_addresses": s.total_addresses_scanned,
                    "matches_found": s.matches_found,
                    "duration_ms": round(s.duration_ms, 3),
                    "query_latency_ms_per_addr": round(s.query_latency_ms, 4),
                    "match_details": [m.to_dict() for m in s.matches],
                }
                for inc, s in summaries.items()
            },
        }
    finally:
        p4_conn.close()
        bench_conn.close()
