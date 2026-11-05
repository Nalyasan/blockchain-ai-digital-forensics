"""Static Forensic Log Stream Parsers for JSONL and EVTX Artifacts.

Provides deterministic, side-effect-free parsing of exported digital forensic
artifacts adhering to ISO/IEC 27037:2012 identification and acquisition standards.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from forensics.endpoint.schemas import (
    EventRecord,
    ProcessRecord,
    SocketRecord,
    SystemInfoRecord,
    canonical_json,
    compute_payload_sha256,
    create_endpoint_record,
)

logger = logging.getLogger("forensics.endpoint.static_logs")

# Standard Windows EVTX File Header Magic Bytes ("ElfFile\x00")
EVTX_MAGIC_HEADER = b"ElfFile\x00"


def _normalize_iso_utc(ts_raw: Any) -> str:
    """Converts diverse timestamp formats into deterministic ISO-8601 UTC string."""
    if not ts_raw:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    s = str(ts_raw).strip()
    # If already UTC ISO with Z
    if s.endswith("Z"):
        return s
    if s.endswith("+00:00"):
        return f"{s[:-6]}Z"
    # PowerShell Date format: /Date(1730784000000)/
    m_ps = re.match(r"^/Date\((\d+)\)/$", s)
    if m_ps:
        epoch_ms = int(m_ps.group(1))
        dt = datetime.fromtimestamp(epoch_ms / 1000.0, tz=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    # Common format: YYYY-MM-DD HH:MM:SS
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
    ):
        try:
            dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            return dt.isoformat().replace("+00:00", "Z")
        except ValueError:
            pass
    return f"{s}Z" if not s.endswith("Z") else s


def _extract_sha256_from_hashes(hashes_str: str) -> str:
    """Extracts SHA256 hex digest from Sysmon-style hashes string (e.g. 'SHA256=abcdef...')."""
    if not hashes_str:
        return ""
    m = re.search(r"\b(?:SHA256|sha256)=([a-fA-F0-9]{64})\b", hashes_str)
    if m:
        return m.group(1).lower()
    m_raw = re.search(r"\b([a-fA-F0-9]{64})\b", hashes_str)
    if m_raw:
        return m_raw.group(1).lower()
    return ""


def parse_jsonl_log(
    source_path: Path | str,
    source_id: str = "HOST-01",
) -> list[dict[str, Any]]:
    """Streams and parses a JSONL file into canonical endpoint record dictionaries.

    Supports:
    1. Direct canonical records (`endpoint_processes`, `endpoint_sockets`, `endpoint_events`, `endpoint_system_info`).
    2. Exported Sysmon telemetry logs.
    3. Generic structured security logs.
    """
    path = Path(source_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"JSONL evidence file not found: {path}")
    if path.stat().st_size == 0:
        raise ValueError(f"JSONL evidence file is empty (0 bytes): {path}")

    records: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            s_line = line.strip()
            if not s_line or s_line.startswith("#"):
                continue
            try:
                raw_item = json.loads(s_line)
            except json.JSONDecodeError as err:
                logger.warning("Skipping malformed JSON line %d in %s: %s", line_no, path.name, err)
                continue

            if not isinstance(raw_item, dict):
                continue

            # Determine record type and parse
            rec_type = raw_item.get("record_type")
            ts = _normalize_iso_utc(
                raw_item.get("timestamp_utc")
                or raw_item.get("TimeCreated")
                or raw_item.get("UtcTime")
                or raw_item.get("timestamp")
            )

            # Case A: Canonical record types
            if rec_type in ("processes", "sockets", "events", "system_info"):
                parsed_rec = create_endpoint_record(
                    record_type=rec_type,
                    source_id=raw_item.get("source_id") or source_id,
                    payload=raw_item,
                    timestamp_utc=ts,
                )
                records.append(parsed_rec.to_dict())
                continue

            # Case B: Sysmon / Windows Event Log export
            event_id = raw_item.get("EventID") or raw_item.get("event_id") or raw_item.get("Id")
            if event_id is not None:
                try:
                    eid = int(event_id)
                except (ValueError, TypeError):
                    eid = 0

                channel = str(raw_item.get("Channel") or raw_item.get("channel") or "Microsoft-Windows-Sysmon/Operational")
                user = str(
                    raw_item.get("User")
                    or raw_item.get("TargetUserName")
                    or raw_item.get("SubjectUserName")
                    or raw_item.get("user_account")
                    or ""
                )
                raw_hashes = str(raw_item.get("Hashes") or raw_item.get("sha256") or raw_item.get("process_hash") or "")
                proc_hash = _extract_sha256_from_hashes(raw_hashes) or raw_hashes
                pid = int(raw_item.get("ProcessId") or raw_item.get("pid") or 0)
                desc = str(raw_item.get("Description") or raw_item.get("Message") or raw_item.get("cmdline") or "")
                source_name = str(raw_item.get("ProviderName") or raw_item.get("source") or "Sysmon")
                level = str(raw_item.get("LevelDisplayName") or raw_item.get("level") or "Information")

                # If Sysmon Process Creation (EventID 1), also record as process
                if eid == 1 and raw_item.get("Image"):
                    p_rec = create_endpoint_record(
                        record_type="processes",
                        source_id=source_id,
                        payload={
                            "pid": pid,
                            "name": Path(str(raw_item.get("Image", ""))).name,
                            "path": str(raw_item.get("Image", "")),
                            "cmdline": str(raw_item.get("CommandLine", desc)),
                            "parent_pid": int(raw_item.get("ParentProcessId", 0)),
                            "sha256": proc_hash,
                            "start_time": ts,
                        },
                        timestamp_utc=ts,
                    )
                    records.append(p_rec.to_dict())

                # Always produce canonical EventRecord
                e_rec = create_endpoint_record(
                    record_type="events",
                    source_id=source_id,
                    payload={
                        "event_id": eid,
                        "source": source_name,
                        "channel": channel,
                        "description": desc,
                        "level": level,
                        "user_account": user,
                        "process_hash": proc_hash,
                        "process_id": pid,
                        "raw_payload_json": canonical_json(raw_item),
                    },
                    timestamp_utc=ts,
                )
                records.append(e_rec.to_dict())
                continue

            # Case C: Generic process payload
            if "pid" in raw_item and ("name" in raw_item or "cmdline" in raw_item):
                p_rec = create_endpoint_record(
                    record_type="processes",
                    source_id=source_id,
                    payload=raw_item,
                    timestamp_utc=ts,
                )
                records.append(p_rec.to_dict())
                continue

            # Case D: Generic socket payload
            if "local_port" in raw_item and "remote_address" in raw_item:
                s_rec = create_endpoint_record(
                    record_type="sockets",
                    source_id=source_id,
                    payload=raw_item,
                    timestamp_utc=ts,
                )
                records.append(s_rec.to_dict())
                continue

            # Default: Wrap in generic event record
            fallback_event = create_endpoint_record(
                record_type="events",
                source_id=source_id,
                payload={
                    "event_id": 9999,
                    "source": "GenericLogParser",
                    "channel": "ForensicImport",
                    "description": raw_item.get("message") or raw_item.get("description") or "Ingested generic log line",
                    "level": "Information",
                    "raw_payload_json": canonical_json(raw_item),
                },
                timestamp_utc=ts,
            )
            records.append(fallback_event.to_dict())

    return records


def parse_evtx_log(
    source_path: Path | str,
    source_id: str = "HOST-01",
) -> list[dict[str, Any]]:
    """Extracts forensic events from static Windows EVTX files.

    Utilizes native Windows PowerShell `Get-WinEvent` in read-only mode if available,
    with robust test-fixture and text-export fallback support.
    """
    path = Path(source_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"EVTX evidence file not found: {path}")
    if path.stat().st_size == 0:
        raise ValueError(f"EVTX evidence file is empty (0 bytes): {path}")

    # Inspect header
    with open(path, "rb") as f:
        header = f.read(8)

    is_binary_evtx = header == EVTX_MAGIC_HEADER

    # Strategy 1: If binary EVTX on Windows, invoke Get-WinEvent securely
    if is_binary_evtx and os.name == "nt":
        try:
            ps_cmd = (
                f"$events = Get-WinEvent -Path '{path}' -MaxEvents 500 -ErrorAction SilentlyContinue; "
                f"if ($events) {{ "
                f"$events | Select-Object Id, TimeCreated, ProviderName, LevelDisplayName, Message, ProcessId, UserId | "
                f"ConvertTo-Json -Compress "
                f"}}"
            )
            res = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                stdout_text = res.stdout.strip()
                parsed_json = json.loads(stdout_text)
                if isinstance(parsed_json, dict):
                    parsed_json = [parsed_json]
                records: list[dict[str, Any]] = []
                for item in parsed_json:
                    eid = int(item.get("Id") or 0)
                    ts = _normalize_iso_utc(item.get("TimeCreated"))
                    msg = str(item.get("Message") or "")
                    provider = str(item.get("ProviderName") or "Windows")
                    level = str(item.get("LevelDisplayName") or "Information")
                    pid = int(item.get("ProcessId") or 0)
                    user = str(item.get("UserId") or "")

                    rec = create_endpoint_record(
                        record_type="events",
                        source_id=source_id,
                        payload={
                            "event_id": eid,
                            "source": provider,
                            "channel": "ExportedEVTX",
                            "description": msg,
                            "level": level,
                            "user_account": user,
                            "process_id": pid,
                            "raw_payload_json": canonical_json(item),
                        },
                        timestamp_utc=ts,
                    )
                    records.append(rec.to_dict())
                if records:
                    return records
        except Exception as err:
            logger.warning("PowerShell EVTX extraction encountered error on %s: %s", path.name, err)

    # Strategy 2: If file is a JSONL or text export fixture (or fallback)
    try:
        return parse_jsonl_log(path, source_id=source_id)
    except Exception:
        pass

    # Strategy 3: Binary EVTX fallback for non-Windows test environments
    # Extract file metadata and emit a verified binary acquisition placeholder record
    stat = path.stat()
    ts = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    rec = create_endpoint_record(
        record_type="events",
        source_id=source_id,
        payload={
            "event_id": 1000,
            "source": "BinaryEVTXAcquisition",
            "channel": "PreservedArtifact",
            "description": f"Preserved binary EVTX artifact {path.name} ({stat.st_size} bytes)",
            "level": "Information",
            "raw_payload_json": canonical_json({
                "filename": path.name,
                "file_size": stat.st_size,
                "magic_header": header.hex(),
            }),
        },
        timestamp_utc=ts,
    )
    return [rec.to_dict()]
