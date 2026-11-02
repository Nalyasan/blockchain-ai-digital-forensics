r"""Benchmark SQLite persistence engine for Phase 6 Public Dataset Benchmark.

Creates and manages D:\Projest\p6_public_benchmark\data\benchmark_p6.db.
Enforces strict append-only conflict checking via G5-02 invariant (insert_verified).
Zero INSERT OR REPLACE. Zero UPDATE on accepted forensic records.
Strictly ZERO writes to real_p4.db or canonical production tables.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Tuple, Union

from forensics.adapters.base import ThreatIntelBatch, ThreatIntelRecord, current_iso_utc
from forensics.persistence import EvidenceConflictError, insert_verified

DEFAULT_BENCHMARK_DB_PATH = Path("D:/Projest/p6_public_benchmark/data/benchmark_p6.db")

# Prohibited database targets for strict physical database isolation
FORBIDDEN_DB_NAMES = ("real_p4.db", "forensics.db", "real_p4", "forensics")


def assert_database_isolation(db_path: Path | str) -> None:
    """Enforce strict physical isolation between benchmark and canonical databases.

    Raises:
        ValueError: If db_path references production or canonical forensic databases.
    """
    path_str = str(Path(db_path).resolve()).lower().replace("\\", "/")
    for forbidden in FORBIDDEN_DB_NAMES:
        if forbidden in path_str.split("/"):
            raise ValueError(
                f"Database isolation violation: cannot target canonical database {db_path!r}."
            )
        if path_str.endswith(f"/{forbidden}") or path_str.endswith(f"/{forbidden}.db"):
            raise ValueError(
                f"Database isolation violation: cannot target canonical database {db_path!r}."
            )
    if "p4_real_integration" in path_str:
        raise ValueError(
            f"Database isolation violation: cannot target production worktree path {db_path!r}."
        )


def init_benchmark_db(
    db_path: Path | str = DEFAULT_BENCHMARK_DB_PATH,
) -> sqlite3.Connection:
    """Initialize dedicated benchmark SQLite database with strict isolated schema.

    Args:
        db_path: Path to benchmark SQLite file. Defaults to benchmark_p6.db.

    Returns:
        sqlite3.Connection initialized with WAL mode and foreign keys enabled.
    """
    assert_database_isolation(db_path)
    target_path = Path(db_path)
    os.makedirs(target_path.parent, exist_ok=True)

    conn = sqlite3.connect(target_path)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA synchronous = NORMAL;")

    # 1. Threat Intelligence Sources (Dataset Provenance Registry)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS threat_intel_sources (
        source_id TEXT PRIMARY KEY,
        source_name TEXT NOT NULL,
        file_path TEXT NOT NULL,
        file_sha256 TEXT NOT NULL,
        source_commit TEXT NOT NULL,
        total_raw_records INTEGER NOT NULL DEFAULT 0,
        valid_records INTEGER NOT NULL DEFAULT 0,
        rejected_records INTEGER NOT NULL DEFAULT 0,
        duplicate_records INTEGER NOT NULL DEFAULT 0,
        ingested_at TEXT NOT NULL
    );
    """)

    # 2. Normalized Threat Intelligence Records (Strict Append-Only)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS threat_intel_records (
        source_file_path TEXT NOT NULL,
        source_file_sha256 TEXT NOT NULL,
        source_commit TEXT NOT NULL,
        row_identifier TEXT NOT NULL,
        raw_payload_sha256 TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_value TEXT NOT NULL,
        threat_category TEXT NOT NULL,
        threat_sub_tactic TEXT,
        confidence_score REAL NOT NULL DEFAULT 1.0,
        data_source TEXT NOT NULL,
        raw_metadata_json TEXT NOT NULL,
        ingestion_timestamp TEXT NOT NULL,
        PRIMARY KEY (source_file_sha256, row_identifier, entity_value)
    );
    """)

    # 3. Threat Intelligence Rejections Log
    conn.execute("""
    CREATE TABLE IF NOT EXISTS threat_intel_rejections (
        rejection_id TEXT PRIMARY KEY,
        source_file_sha256 TEXT NOT NULL,
        row_identifier TEXT NOT NULL,
        raw_payload TEXT,
        rejection_reason TEXT NOT NULL,
        rejected_at TEXT NOT NULL
    );
    """)

    # 4. Screening Matches (for Milestone 3 Entity Screening)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS screening_matches (
        match_id TEXT PRIMARY KEY,
        target_address TEXT NOT NULL,
        source_incident TEXT NOT NULL,
        canonical_category TEXT NOT NULL,
        match_type TEXT NOT NULL,
        matched_at TEXT NOT NULL
    );
    """)

    # 5. Benchmark Runs Log (for Gate P6-03 Telemetry)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS benchmark_runs (
        run_id TEXT PRIMARY KEY,
        gate TEXT NOT NULL,
        dataset_name TEXT NOT NULL,
        records_processed INTEGER NOT NULL,
        duration_ms INTEGER NOT NULL,
        throughput_rec_per_sec REAL NOT NULL,
        peak_memory_mb REAL NOT NULL,
        metrics_json TEXT NOT NULL,
        status TEXT NOT NULL,
        started_at TEXT NOT NULL,
        completed_at TEXT NOT NULL
    );
    """)

    # Performance Indices
    conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_entity ON threat_intel_records(entity_value);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_cat ON threat_intel_records(threat_category);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_src ON threat_intel_records(data_source);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_threat_sha ON threat_intel_records(source_file_sha256);")

    conn.commit()
    return conn


def insert_intel_record(
    conn: sqlite3.Connection,
    record: Union[ThreatIntelRecord, Dict[str, Any]],
) -> bool:
    """Insert a single ThreatIntelRecord using insert_verified conflict checking.

    Args:
        conn: SQLite connection.
        record: ThreatIntelRecord instance or equivalent dictionary.

    Returns:
        True if inserted as a new record, False if identical replay.

    Raises:
        EvidenceConflictError: If a record with the same primary key exists with conflicting data.
    """
    rec_dict = record.to_dict() if isinstance(record, ThreatIntelRecord) else dict(record)

    # Primary key columns: (source_file_sha256, row_identifier, entity_value)
    keys = ("source_file_sha256", "row_identifier", "entity_value")

    return insert_verified(
        conn,
        "threat_intel_records",
        rec_dict,
        keys,
        replay_metadata=("ingestion_timestamp",),
        json_fields=("raw_metadata_json",),
    )


def insert_intel_batch(
    conn: sqlite3.Connection,
    batch: ThreatIntelBatch,
) -> Dict[str, int]:
    """Persist an entire ThreatIntelBatch into benchmark_p6.db in a single transaction.

    Enforces append-only insertion:
    - New valid records are inserted.
    - Identical duplicate replays are detected and counted (return False).
    - Conflicting records raise EvidenceConflictError and rollback.
    - Malformed row rejections are logged to threat_intel_rejections.

    Returns:
        Dict with counts: {'total': int, 'valid': int, 'duplicate': int, 'rejected': int}
    """
    new_inserts = 0
    duplicate_inserts = 0

    with conn:
        # Register or verify source entry
        source_rec = {
            "source_id": batch.source_id,
            "source_name": batch.source_name,
            "file_path": batch.file_path,
            "file_sha256": batch.file_sha256,
            "source_commit": batch.source_commit,
            "total_raw_records": batch.total_raw_records,
            "valid_records": batch.valid_records,
            "rejected_records": batch.rejected_records,
            "duplicate_records": batch.duplicate_records,
            "ingested_at": current_iso_utc(),
        }
        insert_verified(
            conn,
            "threat_intel_sources",
            source_rec,
            ("source_id",),
            replay_metadata=(
                "ingested_at",
                "total_raw_records",
                "valid_records",
                "rejected_records",
                "duplicate_records",
            ),
        )

        # Insert records with verified conflict checking
        for rec in batch.records:
            inserted = insert_intel_record(conn, rec)
            if inserted:
                new_inserts += 1
            else:
                duplicate_inserts += 1

        # Insert rejections
        for rej in batch.rejections:
            conn.execute(
                """
                INSERT OR IGNORE INTO threat_intel_rejections
                (rejection_id, source_file_sha256, row_identifier, raw_payload, rejection_reason, rejected_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    rej["rejection_id"],
                    rej["source_file_sha256"],
                    rej["row_identifier"],
                    rej.get("raw_payload"),
                    rej["rejection_reason"],
                    rej["rejected_at"],
                ),
            )

        # Update source summary stats if updated
        conn.execute(
            """
            UPDATE threat_intel_sources
            SET total_raw_records = ?, valid_records = ?, rejected_records = ?, duplicate_records = ?
            WHERE source_id = ?
            """,
            (
                batch.total_raw_records,
                new_inserts,
                len(batch.rejections),
                duplicate_inserts,
                batch.source_id,
            ),
        )

    return {
        "total": batch.total_raw_records,
        "valid": new_inserts,
        "duplicate": duplicate_inserts,
        "rejected": len(batch.rejections),
    }
