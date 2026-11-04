"""Canonical Endpoint Schemas for P7 Endpoint Ingestion and First Responder.

Standardizes telemetry records collected from endpoint daemons (osquery / Velociraptor)
and native Windows CIM/WMI fallbacks with deterministic ISO-8601 UTC timestamps,
canonical JSON serialization, and cryptographic SHA-256 payload invariance.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Sequence, Union


def canonical_json(data: dict[str, Any]) -> str:
    """Serializes a dictionary to canonical JSON (sorted keys, no extraneous whitespace)."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_payload_sha256(
    payload: dict[str, Any],
    excluded_keys: Sequence[str] = (
        "payload_sha256",
        "recorded_at_utc",
        "record_id",
        "source_id",
        "timestamp_utc",
        "record_type",
    ),
) -> str:
    """Computes SHA-256 hex digest of canonical JSON payload, ignoring envelope metadata."""
    clean = {k: v for k, v in payload.items() if k not in excluded_keys}
    return hashlib.sha256(canonical_json(clean).encode("utf-8")).hexdigest()


def generate_record_id(record_type: str, payload_sha256: str) -> str:
    """Generates deterministic record_id prefixing the 4-char record type."""
    prefix = record_type[:4].lower()
    return f"{prefix}_{payload_sha256[:16]}"


@dataclass(frozen=True)
class BaseEndpointRecord:
    """Base class for all standardized endpoint telemetry records."""

    record_id: str
    source_id: str
    timestamp_utc: str
    payload_sha256: str
    record_type: Literal["processes", "sockets", "events", "system_info"]

    def to_dict(self) -> dict[str, Any]:
        """Converts record to Python dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Serializes record to canonical JSON string."""
        return canonical_json(self.to_dict())


@dataclass(frozen=True)
class ProcessRecord(BaseEndpointRecord):
    """Canonical process execution telemetry record."""

    pid: int
    name: str
    path: str
    cmdline: str
    parent_pid: int
    sha256: str  # Hash of executable binary on disk or empty string if unreadable
    start_time: str  # ISO-8601 UTC process start timestamp or empty string


@dataclass(frozen=True)
class SocketRecord(BaseEndpointRecord):
    """Canonical network socket telemetry record."""

    pid: int
    protocol: Literal["tcp", "udp"]
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str  # e.g. 'Listen', 'Established', 'TimeWait', 'Closed'


@dataclass(frozen=True)
class EventRecord(BaseEndpointRecord):
    """Canonical Windows event log telemetry record."""

    event_id: int
    source: str  # Provider / Source name, e.g. 'Service Control Manager'
    channel: str  # Event channel, e.g. 'System', 'Application', 'Security'
    description: str  # Event payload description
    level: str  # e.g. 'Information', 'Warning', 'Error', 'Critical'


@dataclass(frozen=True)
class SystemInfoRecord(BaseEndpointRecord):
    """Canonical endpoint system metadata record."""

    hostname: str
    os_name: str
    os_version: str
    uptime: int  # Uptime in seconds
    cpu_brand: str
    memory_bytes: int  # Total physical RAM in bytes


def create_endpoint_record(
    record_type: Literal["processes", "sockets", "events", "system_info"],
    source_id: str,
    payload: dict[str, Any],
    timestamp_utc: str | None = None,
) -> Union[ProcessRecord, SocketRecord, EventRecord, SystemInfoRecord]:
    """Constructs a validated canonical endpoint record enforcing all envelope invariants."""
    ts = timestamp_utc or datetime.now(timezone.utc).isoformat()
    if ts.endswith("+00:00"):
        ts = f"{ts[:-6]}Z"
    elif not ts.endswith("Z"):
        ts = f"{ts}Z"

    payload_hash = compute_payload_sha256(payload)
    rec_id = payload.get("record_id") or generate_record_id(record_type, payload_hash)

    base_kwargs: dict[str, Any] = {
        "record_id": str(rec_id),
        "source_id": str(source_id),
        "timestamp_utc": str(ts),
        "payload_sha256": payload_hash,
        "record_type": record_type,
    }

    if record_type == "processes":
        return ProcessRecord(
            **base_kwargs,
            pid=int(payload.get("pid", 0)),
            name=str(payload.get("name", "")),
            path=str(payload.get("path", "") or ""),
            cmdline=str(payload.get("cmdline", "") or ""),
            parent_pid=int(payload.get("parent_pid", 0)),
            sha256=str(payload.get("sha256", "") or ""),
            start_time=str(payload.get("start_time", "") or ""),
        )
    elif record_type == "sockets":
        proto = str(payload.get("protocol", "tcp")).strip().lower()
        if proto not in ("tcp", "udp"):
            proto = "tcp"
        return SocketRecord(
            **base_kwargs,
            pid=int(payload.get("pid", 0)),
            protocol=proto,  # type: ignore[arg-type]
            local_address=str(payload.get("local_address", "") or ""),
            local_port=int(payload.get("local_port", 0)),
            remote_address=str(payload.get("remote_address", "") or ""),
            remote_port=int(payload.get("remote_port", 0)),
            state=str(payload.get("state", "Unknown") or "Unknown"),
        )
    elif record_type == "events":
        return EventRecord(
            **base_kwargs,
            event_id=int(payload.get("event_id", 0)),
            source=str(payload.get("source", "") or ""),
            channel=str(payload.get("channel", "System") or "System"),
            description=str(payload.get("description", "") or ""),
            level=str(payload.get("level", "Information") or "Information"),
        )
    elif record_type == "system_info":
        return SystemInfoRecord(
            **base_kwargs,
            hostname=str(payload.get("hostname", "") or ""),
            os_name=str(payload.get("os_name", "") or ""),
            os_version=str(payload.get("os_version", "") or ""),
            uptime=int(payload.get("uptime", 0)),
            cpu_brand=str(payload.get("cpu_brand", "") or ""),
            memory_bytes=int(payload.get("memory_bytes", 0)),
        )
    else:
        raise ValueError(f"Unknown endpoint record_type: '{record_type}'")
