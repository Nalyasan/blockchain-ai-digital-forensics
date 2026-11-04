"""Dedicated Endpoint Evidence Store for P7.

Enforces:
1. Strict database isolation: endpoint telemetry is written exclusively to `endpoint_evidence.db`
   and is physically isolated from EVM blockchain databases (`real_p4.db`, `forensics.db`).
2. Append-only persistence: insertions use `insert_verified` with SHA-256 payload invariance
   (`payload_sha256`) and raise `EvidenceConflictError` on conflicting replay.
3. 5-layer hardened read-only connection: URI mode=ro&immutable=1, PRAGMA query_only=ON,
   SQLite authorizer callback, cursor regex guard, and fail-closed file existence verification.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence, Union

from forensics.endpoint.schemas import (
    BaseEndpointRecord,
    EventRecord,
    ProcessRecord,
    SocketRecord,
    SystemInfoRecord,
    compute_payload_sha256,
)
from forensics.paths import ENDPOINT_EVIDENCE_DB, get_endpoint_evidence_db
from forensics.persistence import EvidenceConflictError, insert_verified

logger = logging.getLogger("forensics.endpoint.store")

# Authorizer forbidden action codes
_MUTATING_ACTION_CODES = {
    sqlite3.SQLITE_INSERT,
    sqlite3.SQLITE_UPDATE,
    sqlite3.SQLITE_DELETE,
    sqlite3.SQLITE_ATTACH,
    sqlite3.SQLITE_DETACH,
    sqlite3.SQLITE_ALTER_TABLE,
    sqlite3.SQLITE_DROP_TABLE,
    sqlite3.SQLITE_DROP_INDEX,
    sqlite3.SQLITE_DROP_VIEW,
    sqlite3.SQLITE_DROP_TRIGGER,
    sqlite3.SQLITE_CREATE_TABLE,
    sqlite3.SQLITE_CREATE_INDEX,
    sqlite3.SQLITE_CREATE_VIEW,
    sqlite3.SQLITE_CREATE_TRIGGER,
}

_MUTATION_REGEX = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|REPLACE|ATTACH|DETACH|VACUUM|TRUNCATE)\b",
    re.IGNORECASE,
)


from forensics.ai.db_readonly import (
    ReadOnlyConnection,
    ReadOnlyCursor,
    get_readonly_connection as get_ai_readonly_connection,
)


def get_readonly_endpoint_connection(
    db_path: Path | str | None = None,
) -> sqlite3.Connection:
    """Returns a hardened 5-layer read-only SQLite connection to endpoint_evidence.db."""
    target_path = Path(db_path or get_endpoint_evidence_db()).resolve()
    if not target_path.exists():
        raise FileNotFoundError(f"Endpoint evidence database not found: {target_path}")
    return get_ai_readonly_connection(target_path)


ENDPOINT_STORE_SCHEMA_DDL = """
-- 1. Endpoint Running Processes
CREATE TABLE IF NOT EXISTS endpoint_processes (
    record_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    pid INTEGER NOT NULL,
    parent_pid INTEGER,
    name TEXT NOT NULL,
    path TEXT,
    cmdline TEXT,
    sha256 TEXT,
    start_time_utc TEXT,
    recorded_at_utc TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_endpoint_proc_host_pid ON endpoint_processes(host_id, pid);
CREATE INDEX IF NOT EXISTS idx_endpoint_proc_name ON endpoint_processes(name);
CREATE INDEX IF NOT EXISTS idx_endpoint_proc_recorded ON endpoint_processes(recorded_at_utc);

-- 2. Endpoint Active Sockets & Network Connections
CREATE TABLE IF NOT EXISTS endpoint_sockets (
    record_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    pid INTEGER NOT NULL,
    process_name TEXT,
    protocol TEXT NOT NULL,
    local_address TEXT NOT NULL,
    local_port INTEGER NOT NULL,
    remote_address TEXT NOT NULL,
    remote_port INTEGER NOT NULL,
    state TEXT NOT NULL,
    recorded_at_utc TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_endpoint_sock_host_pid ON endpoint_sockets(host_id, pid);
CREATE INDEX IF NOT EXISTS idx_endpoint_sock_remote ON endpoint_sockets(remote_address, remote_port);
CREATE INDEX IF NOT EXISTS idx_endpoint_sock_recorded ON endpoint_sockets(recorded_at_utc);

-- 3. Endpoint Security and System Events
CREATE TABLE IF NOT EXISTS endpoint_events (
    record_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    event_id INTEGER NOT NULL,
    provider_name TEXT,
    level TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    description TEXT,
    raw_payload_json TEXT,
    recorded_at_utc TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_endpoint_events_host_eid ON endpoint_events(host_id, event_id);
CREATE INDEX IF NOT EXISTS idx_endpoint_events_time ON endpoint_events(timestamp_utc);

-- 4. Endpoint Host & System Metadata
CREATE TABLE IF NOT EXISTS endpoint_system_info (
    record_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    os_name TEXT NOT NULL,
    os_version TEXT NOT NULL,
    os_build TEXT,
    architecture TEXT,
    cpu_brand TEXT,
    memory_total_bytes INTEGER,
    uptime_seconds INTEGER,
    collected_at_utc TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_endpoint_sys_host ON endpoint_system_info(host_id);

-- 5. AI First Responder Triage Audit Log
CREATE TABLE IF NOT EXISTS triage_audit_log (
    triage_id TEXT PRIMARY KEY,
    action_name TEXT NOT NULL,
    operator_or_agent TEXT NOT NULL,
    case_id TEXT NOT NULL,
    target_params_json TEXT,
    started_at_utc TEXT NOT NULL,
    completed_at_utc TEXT NOT NULL,
    status TEXT NOT NULL,
    records_count INTEGER NOT NULL DEFAULT 0,
    result_digest_sha256 TEXT NOT NULL,
    findings_summary TEXT,
    details_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_triage_audit_case ON triage_audit_log(case_id);
CREATE INDEX IF NOT EXISTS idx_triage_audit_time ON triage_audit_log(completed_at_utc);
"""


def init_endpoint_db(db_path: Path | str | None = None) -> Path:
    """Initializes endpoint_evidence.db with all 5 tables and indexes."""
    target_path = Path(db_path or get_endpoint_evidence_db()).resolve()
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(target_path) as conn:
        conn.executescript(ENDPOINT_STORE_SCHEMA_DDL)
        conn.commit()
    return target_path


class EndpointEvidenceStore:
    """Dedicated endpoint evidence storage manager providing verified append-only writes."""

    def __init__(self, db_path: Path | str | None = None):
        self.db_path = Path(db_path or get_endpoint_evidence_db()).resolve()
        self.init_db()

    def init_db(self) -> None:
        """Initializes tables and indexes in endpoint_evidence.db."""
        init_endpoint_db(self.db_path)

    def _get_write_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def get_readonly_connection(self) -> sqlite3.Connection:
        """Returns hardened 5-layer read-only SQLite connection."""
        return get_readonly_endpoint_connection(self.db_path)

    def insert_process(
        self, record: Union[ProcessRecord, dict[str, Any]], host_id: str | None = None
    ) -> bool:
        """Appends process execution record via insert_verified."""
        if isinstance(record, ProcessRecord):
            rec_dict = record.to_dict()
            h_id = host_id or record.source_id.split(":")[0]
            start_ts = record.start_time
        else:
            rec_dict = dict(record)
            h_id = host_id or rec_dict.get("host_id") or rec_dict.get("source_id", "").split(":")[0] or "unknown_host"
            start_ts = rec_dict.get("start_time") or rec_dict.get("start_time_utc") or ""

        now_utc = datetime.now(timezone.utc).isoformat()
        payload_hash = rec_dict.get("payload_sha256") or compute_payload_sha256(rec_dict)
        rec_id = rec_dict.get("record_id") or f"proc_{payload_hash[:16]}"

        row = {
            "record_id": str(rec_id),
            "host_id": str(h_id),
            "pid": int(rec_dict.get("pid", 0)),
            "parent_pid": int(rec_dict.get("parent_pid", 0)),
            "name": str(rec_dict.get("name", "")),
            "path": str(rec_dict.get("path", "") or ""),
            "cmdline": str(rec_dict.get("cmdline", "") or ""),
            "sha256": str(rec_dict.get("sha256", "") or ""),
            "start_time_utc": str(start_ts),
            "recorded_at_utc": str(rec_dict.get("recorded_at_utc") or now_utc),
            "payload_sha256": str(payload_hash),
        }

        with self._get_write_connection() as conn:
            inserted = insert_verified(
                conn,
                "endpoint_processes",
                row,
                keys=("record_id",),
                replay_metadata=("recorded_at_utc",),
            )
            conn.commit()
            return inserted

    def insert_socket(
        self, record: Union[SocketRecord, dict[str, Any]], host_id: str | None = None
    ) -> bool:
        """Appends socket telemetry record via insert_verified."""
        if isinstance(record, SocketRecord):
            rec_dict = record.to_dict()
            h_id = host_id or record.source_id.split(":")[0]
        else:
            rec_dict = dict(record)
            h_id = host_id or rec_dict.get("host_id") or rec_dict.get("source_id", "").split(":")[0] or "unknown_host"

        now_utc = datetime.now(timezone.utc).isoformat()
        payload_hash = rec_dict.get("payload_sha256") or compute_payload_sha256(rec_dict)
        rec_id = rec_dict.get("record_id") or f"sock_{payload_hash[:16]}"

        row = {
            "record_id": str(rec_id),
            "host_id": str(h_id),
            "pid": int(rec_dict.get("pid", 0)),
            "process_name": str(rec_dict.get("process_name", "") or ""),
            "protocol": str(rec_dict.get("protocol", "tcp")).lower(),
            "local_address": str(rec_dict.get("local_address", "") or ""),
            "local_port": int(rec_dict.get("local_port", 0)),
            "remote_address": str(rec_dict.get("remote_address", "") or ""),
            "remote_port": int(rec_dict.get("remote_port", 0)),
            "state": str(rec_dict.get("state", "Unknown")),
            "recorded_at_utc": str(rec_dict.get("recorded_at_utc") or now_utc),
            "payload_sha256": str(payload_hash),
        }

        with self._get_write_connection() as conn:
            inserted = insert_verified(
                conn,
                "endpoint_sockets",
                row,
                keys=("record_id",),
                replay_metadata=("recorded_at_utc",),
            )
            conn.commit()
            return inserted

    def insert_event(
        self, record: Union[EventRecord, dict[str, Any]], host_id: str | None = None
    ) -> bool:
        """Appends Windows Event Log record via insert_verified."""
        if isinstance(record, EventRecord):
            rec_dict = record.to_dict()
            h_id = host_id or record.source_id.split(":")[0]
            prov_name = record.source
            ts_utc = record.timestamp_utc
        else:
            rec_dict = dict(record)
            h_id = host_id or rec_dict.get("host_id") or rec_dict.get("source_id", "").split(":")[0] or "unknown_host"
            prov_name = rec_dict.get("provider_name") or rec_dict.get("source") or ""
            ts_utc = rec_dict.get("timestamp_utc") or datetime.now(timezone.utc).isoformat()

        now_utc = datetime.now(timezone.utc).isoformat()
        payload_hash = rec_dict.get("payload_sha256") or compute_payload_sha256(rec_dict)
        rec_id = rec_dict.get("record_id") or f"even_{payload_hash[:16]}"

        raw_json = rec_dict.get("raw_payload_json")
        if isinstance(raw_json, dict):
            raw_json_str = json.dumps(raw_json, sort_keys=True)
        else:
            raw_json_str = str(raw_json or "")

        row = {
            "record_id": str(rec_id),
            "host_id": str(h_id),
            "channel": str(rec_dict.get("channel", "System")),
            "event_id": int(rec_dict.get("event_id", 0)),
            "provider_name": str(prov_name),
            "level": str(rec_dict.get("level", "Information")),
            "timestamp_utc": str(ts_utc),
            "description": str(rec_dict.get("description", "") or ""),
            "raw_payload_json": raw_json_str,
            "recorded_at_utc": str(rec_dict.get("recorded_at_utc") or now_utc),
            "payload_sha256": str(payload_hash),
        }

        with self._get_write_connection() as conn:
            inserted = insert_verified(
                conn,
                "endpoint_events",
                row,
                keys=("record_id",),
                replay_metadata=("recorded_at_utc",),
            )
            conn.commit()
            return inserted

    def insert_system_info(
        self, record: Union[SystemInfoRecord, dict[str, Any]], host_id: str | None = None
    ) -> bool:
        """Appends system metadata record via insert_verified."""
        if isinstance(record, SystemInfoRecord):
            rec_dict = record.to_dict()
            h_id = host_id or record.hostname
            collected_ts = record.timestamp_utc
        else:
            rec_dict = dict(record)
            h_id = host_id or rec_dict.get("host_id") or rec_dict.get("hostname") or "unknown_host"
            collected_ts = rec_dict.get("collected_at_utc") or rec_dict.get("timestamp_utc") or datetime.now(timezone.utc).isoformat()

        payload_hash = rec_dict.get("payload_sha256") or compute_payload_sha256(rec_dict)
        rec_id = rec_dict.get("record_id") or f"syst_{payload_hash[:16]}"

        row = {
            "record_id": str(rec_id),
            "host_id": str(h_id),
            "hostname": str(rec_dict.get("hostname", h_id)),
            "os_name": str(rec_dict.get("os_name", "")),
            "os_version": str(rec_dict.get("os_version", "")),
            "os_build": str(rec_dict.get("os_build", "") or ""),
            "architecture": str(rec_dict.get("architecture", "") or ""),
            "cpu_brand": str(rec_dict.get("cpu_brand", "")),
            "memory_total_bytes": int(rec_dict.get("memory_bytes") or rec_dict.get("memory_total_bytes") or 0),
            "uptime_seconds": int(rec_dict.get("uptime") or rec_dict.get("uptime_seconds") or 0),
            "collected_at_utc": str(collected_ts),
            "payload_sha256": str(payload_hash),
        }

        with self._get_write_connection() as conn:
            inserted = insert_verified(
                conn,
                "endpoint_system_info",
                row,
                keys=("record_id",),
                replay_metadata=("collected_at_utc",),
            )
            conn.commit()
            return inserted

    def insert_triage_audit(self, audit_record: dict[str, Any]) -> bool:
        """Appends first responder triage audit event via insert_verified."""
        triage_id = audit_record.get("triage_id")
        if not triage_id:
            raise ValueError("triage_id is mandatory for triage_audit_log")

        target_params = audit_record.get("target_params_json")
        if isinstance(target_params, (dict, list)):
            params_str = json.dumps(target_params, sort_keys=True)
        else:
            params_str = str(target_params or "{}")

        details = audit_record.get("details_json")
        if isinstance(details, (dict, list)):
            details_str = json.dumps(details, sort_keys=True)
        else:
            details_str = str(details or "{}")

        row = {
            "triage_id": str(triage_id),
            "action_name": str(audit_record.get("action_name", "")),
            "operator_or_agent": str(audit_record.get("operator_or_agent", "AIFirstResponder")),
            "case_id": str(audit_record.get("case_id", "default_case")),
            "target_params_json": params_str,
            "started_at_utc": str(audit_record.get("started_at_utc", datetime.now(timezone.utc).isoformat())),
            "completed_at_utc": str(audit_record.get("completed_at_utc", datetime.now(timezone.utc).isoformat())),
            "status": str(audit_record.get("status", "SUCCESS")),
            "records_count": int(audit_record.get("records_count", 0)),
            "result_digest_sha256": str(audit_record.get("result_digest_sha256", "")),
            "findings_summary": str(audit_record.get("findings_summary", "")),
            "details_json": details_str,
        }

        with self._get_write_connection() as conn:
            inserted = insert_verified(
                conn,
                "triage_audit_log",
                row,
                keys=("triage_id",),
                replay_metadata=("completed_at_utc",),
                json_fields=("target_params_json", "details_json"),
            )
            conn.commit()
            return inserted
