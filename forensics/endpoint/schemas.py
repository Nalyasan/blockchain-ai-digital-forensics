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

from pydantic import BaseModel, ConfigDict, Field


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
    description: str
    level: str  # e.g. 'Information', 'Warning', 'Error', 'Critical'
    user_account: str = ""  # Extracted account/subject name (e.g. SYSTEM, DOMAIN\\user)
    process_hash: str = ""  # SHA-256 process hash if present in telemetry event
    process_id: int = 0  # Target process PID
    raw_payload_json: str = ""  # Verbatim JSON payload preserving unmapped fields


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
            user_account=str(payload.get("user_account", "") or ""),
            process_hash=str(payload.get("process_hash", "") or ""),
            process_id=int(payload.get("process_id", 0) or 0),
            raw_payload_json=str(payload.get("raw_payload_json", "") or ""),
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


class AcquisitionResult(BaseModel):
    """Immutable result envelope returned by all EvidenceSourceAdapter implementations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    acquisition_id: str = Field(..., description="Unique deterministic acquisition identifier, e.g. acq_<uuid16>")
    source_type: Literal["EVM", "HOST_LOG_JSONL", "HOST_LOG_EVTX", "OSQUERY_LIVE", "WMI_LIVE"]
    source_id: str = Field(..., description="Logical or host identifier of source, e.g. HOST-01:sysmon.jsonl")
    consent_scope: str = Field(..., description="Explicit authorized scope parameter, e.g. 'security_events_only'")
    original_sha256: str = Field(..., description="SHA-256 hex digest of original source artifact before ingestion")
    copy_sha256: str = Field(..., description="SHA-256 hex digest of bit-stream preserved artifact in evidence vault")
    record_count: int = Field(..., ge=0, description="Total number of valid parsed records extracted")
    timestamp_utc: str = Field(..., description="ISO-8601 UTC timestamp marking acquisition completion")
    destination_path: str = Field(..., description="Path to preserved raw evidence file in vault")
    manifest_path: str = Field(..., description="Path to ISO/IEC 27037 acquisition_manifest.json")
    operator_or_agent_did: str = Field(..., description="W3C DID or identifier of investigator/agent")
    case_id: str = Field(..., description="Forensic case or incident identifier")
    status: Literal["VERIFIED", "INTEGRITY_MISMATCH", "CONSENT_VIOLATION", "PARTIAL_RECOVERY"] = "VERIFIED"
    records: list[dict[str, Any]] = Field(default_factory=list, description="Extracted normalized record dictionaries")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Extended acquisition and environment metadata")


class CaseMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: str
    investigator_id: str
    operator_did: str
    consent_scope: str
    organization: str = "Digital Forensics Unit"


class EnvironmentState(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hostname: str = ""
    os_name: str = ""
    os_version: str = ""
    architecture: str = ""


class EvidenceSourceInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_type: str
    source_id: str
    original_path: str
    size_bytes: int = Field(..., ge=0)
    environment_state: EnvironmentState = Field(default_factory=EnvironmentState)


class AcquisitionProcessInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    acquisition_method: Literal["BITWISE_STREAM_COPY", "LIVE_API_SNAPSHOT", "EVM_RPC_EXTRACT"]
    tool_name: str
    tool_version: str
    python_version: str
    git_commit: str = ""
    start_time_utc: str
    completion_time_utc: str
    records_ingested: int = Field(..., ge=0)


class CryptographicVerificationInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hash_algorithm: Literal["SHA-256"] = "SHA-256"
    original_sha256: str
    copy_sha256: str
    bitwise_match: bool
    verification_status: Literal["VERIFIED_IDENTICAL", "INTEGRITY_MISMATCH"]


class PreservationInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vault_file_path: str
    destination_db: str
    destination_table: str
    read_only_enforced: bool = True


class AuditTrailEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stage: Literal["IDENTIFICATION", "COLLECTION", "ACQUISITION", "PRESERVATION"]
    timestamp_utc: str
    description: str
    status: Literal["OK", "WARN", "FAIL"] = "OK"


class AcquisitionManifest(BaseModel):
    """ISO/IEC 27037:2012 Digital Evidence Acquisition Manifest."""

    model_config = ConfigDict(extra="forbid")

    standard: Literal["ISO/IEC 27037:2012"] = "ISO/IEC 27037:2012"
    manifest_version: Literal["1.0.0"] = "1.0.0"
    acquisition_id: str
    case_metadata: CaseMetadata
    evidence_source: EvidenceSourceInfo
    acquisition_process: AcquisitionProcessInfo
    cryptographic_verification: CryptographicVerificationInfo
    preservation: PreservationInfo
    audit_trail: list[AuditTrailEntry] = Field(default_factory=list)

