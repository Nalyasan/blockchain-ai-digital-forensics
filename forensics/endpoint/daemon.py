"""Dual-mode Endpoint Telemetry Ingestion Daemon for P7.

Architecture:
1. Primary: OsqueryProvider via osquery CLI JSON (`osqueryi --json "<query>"`) and pipe health checks.
2. Fallback: WMIPowerShellFallbackProvider via Windows CIM (Win32_Process, Get-NetTCPConnection,
   Get-WinEvent) and native ctypes/winreg system queries (<100ms).
3. Mock: MockTelemetryProvider providing deterministic offline fixtures for unit tests and CI/CD.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import logging
import os
import platform
import shutil
import socket
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Literal

from forensics.endpoint.schemas import (
    BaseEndpointRecord,
    EventRecord,
    ProcessRecord,
    SocketRecord,
    SystemInfoRecord,
    create_endpoint_record,
)

logger = logging.getLogger("forensics.endpoint.daemon")

TCP_STATE_MAP: dict[int, str] = {
    1: "Closed",
    2: "Listen",
    3: "SynSent",
    4: "SynReceived",
    5: "Established",
    6: "FinWait1",
    7: "FinWait2",
    8: "CloseWait",
    9: "Closing",
    10: "LastAck",
    11: "TimeWait",
    12: "DeleteTCB",
}


class TelemetryProvider(ABC):
    """Abstract base interface for endpoint telemetry providers."""

    @abstractmethod
    def is_available(self) -> bool:
        """Returns True if this provider can execute in the current host environment."""
        pass

    @abstractmethod
    def get_provider_name(self) -> str:
        """Returns short identifier for the provider."""
        pass

    @abstractmethod
    def query_processes(self, limit: int | None = None) -> list[ProcessRecord]:
        """Queries running processes."""
        pass

    @abstractmethod
    def query_sockets(self, limit: int | None = None) -> list[SocketRecord]:
        """Queries active network sockets."""
        pass

    @abstractmethod
    def query_events(
        self, channel: str = "System", max_events: int = 50
    ) -> list[EventRecord]:
        """Queries recent Windows operating system event logs."""
        pass

    @abstractmethod
    def query_system_info(self) -> SystemInfoRecord:
        """Queries host hardware and operating system metadata."""
        pass


class OsqueryProvider(TelemetryProvider):
    """Osquery telemetry provider via CLI JSON execution and extension named pipe check."""

    def __init__(self, binary_path: str | None = None, timeout: float = 15.0):
        self.timeout = timeout
        self.binary_path = binary_path or self._find_osqueryi()
        self.pipe_path = r"\\.\pipe\osquery.em"

    def _find_osqueryi(self) -> str | None:
        env_bin = os.environ.get("OSQUERY_BIN")
        if env_bin and os.path.isfile(env_bin):
            return env_bin
        which_bin = shutil.which("osqueryi")
        if which_bin:
            return which_bin
        candidates = [
            r"C:\Program Files\osquery\osqueryi.exe",
            r"C:\ProgramData\osquery\osqueryi.exe",
            str(Path(__file__).resolve().parents[2] / "tools" / "osquery" / "osqueryi.exe"),
        ]
        for c in candidates:
            if os.path.isfile(c):
                return c
        return None

    def is_available(self) -> bool:
        return self.binary_path is not None and os.path.isfile(self.binary_path)

    def is_daemon_pipe_active(self) -> bool:
        """Checks if osquery extension named pipe is active on Windows."""
        try:
            return os.path.exists(self.pipe_path)
        except Exception:
            return False

    def get_provider_name(self) -> str:
        return "osquery"

    def _run_query(self, sql: str) -> list[dict[str, Any]]:
        if not self.is_available():
            raise RuntimeError("Osquery executable not found on host system.")
        cmd = [str(self.binary_path), "--json", sql]
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=self.timeout, check=True
        )
        raw = proc.stdout.decode("utf-8", errors="replace").strip()
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, list) else [parsed]
        except Exception:
            return []

    def query_processes(self, limit: int | None = None) -> list[ProcessRecord]:
        lim = f" LIMIT {int(limit)}" if limit else ""
        sql = f"SELECT pid, name, path, cmdline, parent AS parent_pid, start_time FROM processes{lim};"
        rows = self._run_query(sql)
        records: list[ProcessRecord] = []
        source_id = f"{socket.gethostname()}:{self.get_provider_name()}"
        for r in rows:
            p_path = r.get("path", "") or ""
            f_hash = ""
            if p_path and os.path.isfile(p_path):
                try:
                    with open(p_path, "rb") as fp:
                        f_hash = hashlib.sha256(fp.read()).hexdigest()
                except (PermissionError, OSError):
                    f_hash = ""
            payload = {
                "pid": int(r.get("pid", 0)),
                "name": r.get("name", ""),
                "path": p_path,
                "cmdline": r.get("cmdline", ""),
                "parent_pid": int(r.get("parent_pid", 0)),
                "sha256": f_hash,
                "start_time": str(r.get("start_time", "") or ""),
            }
            rec = create_endpoint_record("processes", source_id, payload)
            if isinstance(rec, ProcessRecord):
                records.append(rec)
        return records

    def query_sockets(self, limit: int | None = None) -> list[SocketRecord]:
        lim = f" LIMIT {int(limit)}" if limit else ""
        sql = (
            "SELECT pid, protocol, local_address, local_port, remote_address, "
            f"remote_port, state FROM process_open_sockets{lim};"
        )
        rows = self._run_query(sql)
        records: list[SocketRecord] = []
        source_id = f"{socket.gethostname()}:{self.get_provider_name()}"
        for r in rows:
            proto_raw = int(r.get("protocol", 6))
            payload = {
                "pid": int(r.get("pid", 0)),
                "protocol": "tcp" if proto_raw == 6 else "udp",
                "local_address": r.get("local_address", "") or "",
                "local_port": int(r.get("local_port", 0)),
                "remote_address": r.get("remote_address", "") or "",
                "remote_port": int(r.get("remote_port", 0)),
                "state": r.get("state", "Unknown") or "Unknown",
            }
            rec = create_endpoint_record("sockets", source_id, payload)
            if isinstance(rec, SocketRecord):
                records.append(rec)
        return records

    def query_events(
        self, channel: str = "System", max_events: int = 50
    ) -> list[EventRecord]:
        sql = (
            "SELECT event_id, provider_name AS source, 'System' AS channel, "
            f"data AS description, level FROM windows_events LIMIT {int(max_events)};"
        )
        rows = self._run_query(sql)
        records: list[EventRecord] = []
        source_id = f"{socket.gethostname()}:{self.get_provider_name()}"
        for r in rows:
            payload = {
                "event_id": int(r.get("event_id", 0)),
                "source": r.get("source", "") or "",
                "channel": channel,
                "description": r.get("description", "") or "",
                "level": r.get("level", "Information") or "Information",
            }
            rec = create_endpoint_record("events", source_id, payload)
            if isinstance(rec, EventRecord):
                records.append(rec)
        return records

    def query_system_info(self) -> SystemInfoRecord:
        sql = (
            "SELECT si.hostname AS hostname, ov.name AS os_name, ov.version AS os_version, "
            "si.uptime AS uptime, si.cpu_brand AS cpu_brand, si.physical_memory AS memory_bytes "
            "FROM system_info si CROSS JOIN os_version ov LIMIT 1;"
        )
        rows = self._run_query(sql)
        source_id = f"{socket.gethostname()}:{self.get_provider_name()}"
        row = rows[0] if rows else {}
        payload = {
            "hostname": row.get("hostname", socket.gethostname()),
            "os_name": row.get("os_name", platform.system()),
            "os_version": row.get("os_version", platform.version()),
            "uptime": int(row.get("uptime", 0)),
            "cpu_brand": row.get("cpu_brand", "Unknown"),
            "memory_bytes": int(row.get("memory_bytes", 0)),
        }
        rec = create_endpoint_record("system_info", source_id, payload)
        if isinstance(rec, SystemInfoRecord):
            return rec
        raise RuntimeError("Failed to build SystemInfoRecord from osquery")


class WMIPowerShellFallbackProvider(TelemetryProvider):
    """Native Windows fallback provider utilizing CIM/PowerShell and ctypes."""

    def __init__(self, compute_hashes: bool = True, timeout: float = 15.0):
        self.compute_hashes = compute_hashes
        self.timeout = timeout

    def is_available(self) -> bool:
        return platform.system() == "Windows"

    def get_provider_name(self) -> str:
        return "wmi_fallback"

    def _run_ps(self, ps_script: str) -> Any:
        cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script]
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=self.timeout
        )
        if proc.returncode != 0:
            err_msg = proc.stderr.decode("utf-8", errors="replace").strip() if proc.stderr else ""
            logger.warning("PowerShell command warning: %s", err_msg)
            return []
        out = proc.stdout.decode("utf-8", errors="replace").strip() if proc.stdout else ""
        if not out:
            return []
        try:
            return json.loads(out)
        except Exception:
            return []

    def query_processes(self, limit: int | None = None) -> list[ProcessRecord]:
        lim_str = f" | Select-Object -First {int(limit)}" if limit else ""
        script = (
            "Get-CimInstance Win32_Process"
            + lim_str
            + " | Select-Object ProcessId, Name, ExecutablePath, CommandLine, "
            "ParentProcessId, @{Name='start_time'; Expression={ if ($_.CreationDate) { "
            "$_.CreationDate.ToUniversalTime().ToString('o') } else { $null } }} | ConvertTo-Json -Compress"
        )
        res = self._run_ps(script)
        if isinstance(res, dict):
            items = [res]
        elif isinstance(res, list):
            items = res
        else:
            items = []

        records: list[ProcessRecord] = []
        source_id = f"{socket.gethostname()}:{self.get_provider_name()}"
        for item in items:
            exe_path = item.get("ExecutablePath") or ""
            f_hash = ""
            if self.compute_hashes and exe_path and os.path.isfile(exe_path):
                try:
                    with open(exe_path, "rb") as fp:
                        f_hash = hashlib.sha256(fp.read()).hexdigest()
                except (PermissionError, OSError):
                    f_hash = ""

            payload = {
                "pid": int(item.get("ProcessId", 0)),
                "name": item.get("Name") or "",
                "path": exe_path,
                "cmdline": item.get("CommandLine") or "",
                "parent_pid": int(item.get("ParentProcessId", 0)),
                "sha256": f_hash,
                "start_time": item.get("start_time") or "",
            }
            rec = create_endpoint_record("processes", source_id, payload)
            if isinstance(rec, ProcessRecord):
                records.append(rec)
        return records

    def query_sockets(self, limit: int | None = None) -> list[SocketRecord]:
        lim_str = f" | Select-Object -First {int(limit)}" if limit else ""
        script = (
            "Get-NetTCPConnection"
            + lim_str
            + " | Select-Object OwningProcess, LocalAddress, LocalPort, "
            "RemoteAddress, RemotePort, State | ConvertTo-Json -Compress"
        )
        res = self._run_ps(script)
        if isinstance(res, dict):
            items = [res]
        elif isinstance(res, list):
            items = res
        else:
            items = []

        records: list[SocketRecord] = []
        source_id = f"{socket.gethostname()}:{self.get_provider_name()}"
        for item in items:
            raw_state = item.get("State", 0)
            if isinstance(raw_state, int):
                state_str = TCP_STATE_MAP.get(raw_state, f"State_{raw_state}")
            else:
                state_str = str(raw_state)

            payload = {
                "pid": int(item.get("OwningProcess", 0)),
                "protocol": "tcp",
                "local_address": item.get("LocalAddress") or "",
                "local_port": int(item.get("LocalPort", 0)),
                "remote_address": item.get("RemoteAddress") or "",
                "remote_port": int(item.get("RemotePort", 0)),
                "state": state_str,
            }
            rec = create_endpoint_record("sockets", source_id, payload)
            if isinstance(rec, SocketRecord):
                records.append(rec)
        return records

    def query_events(
        self, channel: str = "System", max_events: int = 50
    ) -> list[EventRecord]:
        script = (
            f"Get-WinEvent -LogName {channel} -MaxEvents {int(max_events)} "
            "-ErrorAction SilentlyContinue | Select-Object Id, ProviderName, "
            "LogName, @{Name='TimeCreated'; Expression={$_.TimeCreated.ToUniversalTime().ToString('o')}}, "
            "Message, LevelDisplayName | ConvertTo-Json -Compress"
        )
        res = self._run_ps(script)
        if isinstance(res, dict):
            items = [res]
        elif isinstance(res, list):
            items = res
        else:
            items = []

        records: list[EventRecord] = []
        source_id = f"{socket.gethostname()}:{self.get_provider_name()}"
        for item in items:
            msg = item.get("Message") or ""
            payload = {
                "event_id": int(item.get("Id", 0)),
                "source": item.get("ProviderName") or "",
                "channel": item.get("LogName") or channel,
                "description": msg.strip(),
                "level": item.get("LevelDisplayName") or "Information",
            }
            rec = create_endpoint_record("events", source_id, payload)
            if isinstance(rec, EventRecord):
                records.append(rec)
        return records

    def query_system_info(self) -> SystemInfoRecord:
        hostname = socket.gethostname()
        os_name = f"{platform.system()} {platform.release()}"
        os_version = platform.version()

        uptime_sec = 0
        try:
            uptime_sec = int(ctypes.windll.kernel32.GetTickCount64() // 1000)
        except Exception:
            uptime_sec = 0

        cpu_brand = "Unknown"
        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            )
            cpu_val, _ = winreg.QueryValueEx(key, "ProcessorNameString")
            cpu_brand = str(cpu_val).strip()
        except Exception:
            cpu_brand = platform.processor() or "Unknown"

        memory_bytes = 0
        try:
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
            memory_bytes = stat.ullTotalPhys
        except Exception:
            memory_bytes = 0

        source_id = f"{hostname}:{self.get_provider_name()}"
        payload = {
            "hostname": hostname,
            "os_name": os_name,
            "os_version": os_version,
            "uptime": uptime_sec,
            "cpu_brand": cpu_brand,
            "memory_bytes": memory_bytes,
        }
        rec = create_endpoint_record("system_info", source_id, payload)
        if isinstance(rec, SystemInfoRecord):
            return rec
        raise RuntimeError("Failed to build SystemInfoRecord from WMI fallback")


class MockTelemetryProvider(TelemetryProvider):
    """Deterministic mock provider populated with realistic endpoint artifacts for tests and CI."""

    def is_available(self) -> bool:
        return True

    def get_provider_name(self) -> str:
        return "mock"

    def query_processes(self, limit: int | None = None) -> list[ProcessRecord]:
        source_id = "MOCK-HOST:mock"
        sample = [
            {
                "pid": 4,
                "name": "System",
                "path": "",
                "cmdline": "",
                "parent_pid": 0,
                "sha256": "",
                "start_time": "2026-11-04T00:00:00Z",
            },
            {
                "pid": 940,
                "name": "services.exe",
                "path": r"C:\Windows\System32\services.exe",
                "cmdline": r"C:\Windows\system32\services.exe",
                "parent_pid": 800,
                "sha256": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
                "start_time": "2026-11-04T00:00:05Z",
            },
            {
                "pid": 1250,
                "name": "svchost.exe",
                "path": r"C:\Windows\System32\svchost.exe",
                "cmdline": r"C:\Windows\system32\svchost.exe -k DcomLaunch -p",
                "parent_pid": 940,
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "start_time": "2026-11-04T00:00:10Z",
            },
            {
                "pid": 4444,
                "name": "nc.exe",
                "path": r"C:\Users\Public\nc.exe",
                "cmdline": r"C:\Users\Public\nc.exe -lvp 4444 -e cmd.exe",
                "parent_pid": 1250,
                "sha256": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                "start_time": "2026-11-04T07:00:00Z",
            },
        ]
        if limit:
            sample = sample[:limit]
        records: list[ProcessRecord] = []
        for p in sample:
            rec = create_endpoint_record("processes", source_id, p)
            if isinstance(rec, ProcessRecord):
                records.append(rec)
        return records

    def query_sockets(self, limit: int | None = None) -> list[SocketRecord]:
        source_id = "MOCK-HOST:mock"
        sample = [
            {
                "pid": 1250,
                "protocol": "tcp",
                "local_address": "0.0.0.0",
                "local_port": 135,
                "remote_address": "0.0.0.0",
                "remote_port": 0,
                "state": "Listen",
            },
            {
                "pid": 4444,
                "protocol": "tcp",
                "local_address": "0.0.0.0",
                "local_port": 4444,
                "remote_address": "0.0.0.0",
                "remote_port": 0,
                "state": "Listen",
            },
            {
                "pid": 4444,
                "protocol": "tcp",
                "local_address": "192.168.1.100",
                "local_port": 4444,
                "remote_address": "198.51.100.23",
                "remote_port": 51234,
                "state": "Established",
            },
        ]
        if limit:
            sample = sample[:limit]
        records: list[SocketRecord] = []
        for s in sample:
            rec = create_endpoint_record("sockets", source_id, s)
            if isinstance(rec, SocketRecord):
                records.append(rec)
        return records

    def query_events(
        self, channel: str = "System", max_events: int = 50
    ) -> list[EventRecord]:
        source_id = "MOCK-HOST:mock"
        sample = [
            {
                "event_id": 7045,
                "source": "Service Control Manager",
                "channel": "System",
                "description": "A service was installed in the system: Name: MaliciousSvc",
                "level": "Information",
            },
            {
                "event_id": 4688,
                "source": "Microsoft-Windows-Security-Auditing",
                "channel": "Security",
                "description": r"A new process has been created: New Process Name: C:\Users\Public\nc.exe",
                "level": "Information",
            },
        ]
        records: list[EventRecord] = []
        for e in sample[:max_events]:
            rec = create_endpoint_record("events", source_id, e)
            if isinstance(rec, EventRecord):
                records.append(rec)
        return records

    def query_system_info(self) -> SystemInfoRecord:
        source_id = "MOCK-HOST:mock"
        payload = {
            "hostname": "MOCK-HOST",
            "os_name": "Microsoft Windows 11 Enterprise",
            "os_version": "10.0.26100",
            "uptime": 86400,
            "cpu_brand": "Intel(R) Core(TM) i9-14900K",
            "memory_bytes": 34359738368,
        }
        rec = create_endpoint_record("system_info", source_id, payload)
        if isinstance(rec, SystemInfoRecord):
            return rec
        raise RuntimeError("Failed to build SystemInfoRecord from mock")


def get_default_provider(force_mock: bool = False) -> TelemetryProvider:
    """Resolves the best available telemetry provider according to runtime environment."""
    if force_mock or os.environ.get("TELEMETRY_BACKEND") == "mock":
        return MockTelemetryProvider()

    osquery_provider = OsqueryProvider()
    if osquery_provider.is_available():
        return osquery_provider

    wmi_provider = WMIPowerShellFallbackProvider()
    if wmi_provider.is_available():
        return wmi_provider

    return MockTelemetryProvider()


def query_endpoint(
    query_type: Literal["processes", "sockets", "events", "system_info"],
    provider: TelemetryProvider | None = None,
    **kwargs: Any,
) -> list[BaseEndpointRecord]:
    """Public P7 Interface Contract function.

    Queries endpoint telemetry and returns a list of canonical dataclass records.
    Guarantees envelope invariants (record_id, source_id, timestamp_utc, payload_sha256).
    """
    force_mock = kwargs.get("force_mock", False)
    prov = provider or get_default_provider(force_mock=force_mock)

    if query_type == "processes":
        limit = kwargs.get("limit")
        return list(prov.query_processes(limit=limit))
    elif query_type == "sockets":
        limit = kwargs.get("limit")
        return list(prov.query_sockets(limit=limit))
    elif query_type == "events":
        channel = kwargs.get("channel", "System")
        max_events = kwargs.get("max_events", 50)
        return list(prov.query_events(channel=channel, max_events=max_events))
    elif query_type == "system_info":
        return [prov.query_system_info()]
    else:
        raise ValueError(f"Unsupported query_type '{query_type}'")
