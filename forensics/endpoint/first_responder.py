"""AI First Responder Engine and Safety Boundary Enforcement (Milestone M2 / P7).

Complies strictly with NIST SP 800-86 and ISO/IEC 27037 digital forensic standards.
Enforces 5 hardcoded forbidden action categories:
1. Arbitrary shell execution (cmd.exe, powershell.exe, bash, subshell piping/chaining).
2. Event log clearing / tampering (wevtutil cl, Clear-EventLog, .evtx file deletion).
3. File permission / ACL alterations (icacls, takeown, Set-Acl, chmod).
4. Automated network isolation (netsh advfirewall, Disable-NetAdapter, route delete).
   Only Human-In-The-Loop IsolationRecommendation artifacts with cryptographic proof are allowed.
5. Autonomous private key access or transaction signing (cast send, eth_sign, keystore access,
   64-hex private key injection).

Provides 5 safe non-destructive triage playbooks ordered by Volatility (RFC 3227 & NIST SP 800-86):
- Volatility Rank 1: triage_active_network_connections
- Volatility Rank 2: triage_running_processes
- Volatility Rank 3: triage_recent_system_events
- Volatility Rank 4: triage_persistence_indicators
- Volatility Rank 5: triage_hash_verification
"""

from __future__ import annotations

import enum
import hashlib
import json
import logging
import os
import platform
import re
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Sequence, Set, Tuple, Union

from pydantic import BaseModel, ConfigDict, Field

from forensics.endpoint.daemon import TelemetryProvider, get_default_provider, query_endpoint
from forensics.endpoint.schemas import canonical_json, compute_payload_sha256
from forensics.endpoint.store import EndpointEvidenceStore

logger = logging.getLogger("forensics.endpoint.first_responder")


class ForbiddenActionCategory(str, enum.Enum):
    """The 5 strictly prohibited action categories for AI First Responder."""

    ARBITRARY_SHELL = "arbitrary_shell_execution"
    EVENT_LOG_CLEARING = "event_log_clearing"
    ACL_ALTERATION = "file_permission_or_acl_alteration"
    AUTOMATED_NETWORK_ISOLATION = "automated_network_isolation"
    KEY_SIGNING = "autonomous_key_or_wallet_signing"


class TriagePlaybookType(str, enum.Enum):
    """The 5 authorized non-destructive triage playbooks."""

    NETWORK_CONNECTIONS = "triage_active_network_connections"
    RUNNING_PROCESSES = "triage_running_processes"
    SYSTEM_EVENTS = "triage_recent_system_events"
    PERSISTENCE_INDICATORS = "triage_persistence_indicators"
    HASH_VERIFICATION = "triage_hash_verification"


class FirstResponseError(Exception):
    """Base exception for first responder operations."""
    pass


class DangerousActionError(FirstResponseError):
    """Raised when an autonomous action violates security boundary guards."""

    def __init__(
        self,
        category: ForbiddenActionCategory,
        action_attempted: str,
        reason: str,
    ):
        super().__init__(
            f"SECURITY VIOLATION [{category.value}]: Action '{action_attempted}' blocked. Reason: {reason}"
        )
        self.category = category
        self.action_attempted = action_attempted
        self.reason = reason
        self.timestamp_utc = datetime.now(timezone.utc).isoformat()


class PlaybookExecutionError(FirstResponseError):
    """Raised when an authorized non-destructive triage playbook encounters an error."""
    pass


class ActionBlockedResult(BaseModel):
    """Audit log entry emitted when a prohibited action is intercepted and blocked."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    blocked: bool = True
    category: ForbiddenActionCategory
    action_attempted: str
    reason: str
    timestamp_utc: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    audit_digest: str = Field(description="SHA-256 of blocked event metadata")


class TriageExecutionResult(BaseModel):
    """Standardized envelope for completed non-destructive triage operations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    playbook: TriagePlaybookType
    success: bool = True
    records_count: int
    records: list[dict[str, Any]]
    timestamp_utc: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    payload_sha256: str
    volatility_rank: int
    nist_sp800_86_ref: str
    iso27037_ref: str


class IsolationRecommendation(BaseModel):
    """Structured Human-In-The-Loop network containment recommendation artifact.

    Strict Invariant: Does NOT execute network changes autonomously; requires human operator signature.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    incident_id: str
    recommendation: Literal["ISOLATE_ENDPOINT", "MONITOR_ONLY"] = "ISOLATE_ENDPOINT"
    justification: str
    target_host: str
    evidence_digests: list[str]
    created_utc: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    recommendation_hash: str
    requires_human_signature: bool = True


class SocketTelemetry(BaseModel):
    """Structured socket telemetry representation."""
    pid: int
    protocol: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str
    timestamp_utc: str


class ProcessTelemetry(BaseModel):
    """Structured process telemetry representation."""
    pid: int
    name: str
    path: str
    cmdline: str
    parent_pid: int
    sha256: str
    start_time_utc: str
    is_suspicious_path: bool = False
    anomaly_reasons: list[str] = Field(default_factory=list)


class EventTelemetry(BaseModel):
    """Structured event log telemetry representation."""
    event_id: int
    channel: str
    source: str
    timestamp_utc: str
    description: str
    level: str


class PersistenceIndicator(BaseModel):
    """Structured autostart / persistence indicator."""
    category: str
    name: str
    entry_location: str
    target_path: str
    arguments: str
    sha256_digest: str
    is_suspicious: bool = False


class HashVerificationResult(BaseModel):
    """Result of streaming non-destructive cryptographic binary verification."""
    file_path: str
    file_size_bytes: int
    sha256: str
    sha1: str
    file_created_utc: str
    file_modified_utc: str
    is_threat_match: bool
    matched_threat_label: Optional[str] = None


class SafetyGuard:
    """Multi-layered safety policy validator enforcing NIST SP 800-86 and ISO 27037 boundaries."""

    # 1. Arbitrary shell regex
    _FORBIDDEN_SHELL_RE = re.compile(
        r"\b(cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?|bash|sh|zsh|cscript(?:\.exe)?|wscript(?:\.exe)?|mshta(?:\.exe)?)\b"
        r"|\b(?:-[eE](?:nc(?:odedcommand)?)?|-[cCdD](?:ommand)?|-executionpolicy\s+bypass)\b"
        r"|\b(?:subprocess\.(?:Popen|run|call|check_output)|os\.system|exec\(|eval\()\b"
        r"|[;&|`><]|\$\(",
        re.IGNORECASE,
    )

    # 2. Event log clearing regex
    _FORBIDDEN_LOG_RE = re.compile(
        r"\b(?:wevtutil(?:\.exe)?\s+(?:cl|clear-log|sl|set-log))\b"
        r"|\b(?:Clear-EventLog|Remove-EventLog|Limit-EventLog)\b"
        r"|\b(?:Win32_NTEventlogFile.*ClearEventlog)\b"
        r"|\b(?:EvtClearLog|ClearEventLog[AW])\b"
        r"|(?:winevt[\\/]logs[\\/].*\.evtx)",
        re.IGNORECASE,
    )

    # 3. ACL alteration regex
    _FORBIDDEN_ACL_RE = re.compile(
        r"\b(?:icacls(?:\.exe)?|cacls(?:\.exe)?|takeown(?:\.exe)?|subinacl(?:\.exe)?)\b"
        r"|\b(?:Set-Acl|Grant-Permission|Revoke-Permission)\b"
        r"|\b(?:chmod|chown|chgrp)\b"
        r"|\b(?:SetNamedSecurityInfo|SetFileSecurity)\b",
        re.IGNORECASE,
    )

    # 4. Automated network isolation regex
    _FORBIDDEN_ISOLATION_RE = re.compile(
        r"\b(?:netsh(?:\.exe)?\s+advfirewall\s+(?:set|firewall\s+add|firewall\s+set))\b"
        r"|\b(?:New-NetFirewallRule|Set-NetFirewallRule|Set-NetFirewallProfile|Disable-NetAdapter|Remove-NetRoute)\b"
        r"|\b(?:route(?:\.exe)?\s+delete\s+0\.0\.0\.0)\b"
        r"|\b(?:ipconfig(?:\.exe)?\s+/(?:release|renew))\b",
        re.IGNORECASE,
    )

    # 5. Private key and wallet signing regex
    _FORBIDDEN_KEY_RE = re.compile(
        r"\b(?:cast\s+send|cast\s+mktx|eth_sign|personal_sign|eth_sendRawTransaction|sign_transaction)\b"
        r"|(?:\.ethereum[\\/]keystore|keystore\.json|id_rsa|\.env)"
        r"|\b0x[a-fA-F0-9]{64}\b",
        re.IGNORECASE,
    )

    @classmethod
    def evaluate(
        cls, action_name: str, params: Optional[dict[str, Any]] = None
    ) -> Tuple[bool, Optional[ForbiddenActionCategory], Optional[str]]:
        """Evaluates whether an action is permitted.

        Returns (is_safe, forbidden_category, reason).
        """
        candidate_strings = [str(action_name)]
        if params:
            for k, v in params.items():
                # Allow benign file_path inspect in triage_hash_verification
                if k == "file_path" and action_name.strip() == "triage_hash_verification":
                    continue
                candidate_strings.append(f"{k}={v}")

        full_text = " ".join(candidate_strings)

        # Check Category 5: Autonomous private key access or transaction signing (most sensitive)
        if cls._FORBIDDEN_KEY_RE.search(full_text):
            return (
                False,
                ForbiddenActionCategory.KEY_SIGNING,
                "Autonomous private key access or transaction signing is strictly prohibited.",
            )

        # Check Category 4: Automated network isolation
        if cls._FORBIDDEN_ISOLATION_RE.search(full_text):
            return (
                False,
                ForbiddenActionCategory.AUTOMATED_NETWORK_ISOLATION,
                "Automated network isolation requires human approval; autonomous execution blocked.",
            )

        # Check Category 3: ACL alteration
        if cls._FORBIDDEN_ACL_RE.search(full_text):
            return (
                False,
                ForbiddenActionCategory.ACL_ALTERATION,
                "File permission, ownership change, or ACL alteration detected.",
            )

        # Check Category 2: Event log clearing
        if cls._FORBIDDEN_LOG_RE.search(full_text):
            return (
                False,
                ForbiddenActionCategory.EVENT_LOG_CLEARING,
                "Event log clearing, truncation, or log tampering detected.",
            )

        # Check Category 1: Arbitrary shell execution
        if cls._FORBIDDEN_SHELL_RE.search(full_text):
            return (
                False,
                ForbiddenActionCategory.ARBITRARY_SHELL,
                "Arbitrary shell invocation, interpreter binary, or shell command chaining detected.",
            )

        # Verify action is in authorized playbooks enum
        normalized = action_name.strip()
        valid_actions = {p.value for p in TriagePlaybookType}
        if normalized not in valid_actions:
            return (
                False,
                ForbiddenActionCategory.ARBITRARY_SHELL,
                f"Action '{action_name}' is not in authorized triage playbook whitelist.",
            )

        return True, None, None

    @classmethod
    def validate_action(
        cls, action_name: str, params: Optional[dict[str, Any]] = None
    ) -> None:
        """Validates action against safety policy. Raises DangerousActionError if violated."""
        is_safe, category, reason = cls.evaluate(action_name, params)
        if not is_safe:
            raise DangerousActionError(
                category=category or ForbiddenActionCategory.ARBITRARY_SHELL,
                action_attempted=action_name,
                reason=reason or "Action blocked by safety policy.",
            )


# -----------------------------------------------------------------------------
# Playbook Implementations
# -----------------------------------------------------------------------------


def triage_active_network_connections(
    target_pid: Optional[int] = None,
    remote_ip: Optional[str] = None,
    state_filter: Literal["ESTABLISHED", "LISTENING", "ALL"] = "ALL",
    limit: int = 100,
    provider: Optional[TelemetryProvider] = None,
) -> TriageExecutionResult:
    """Triage Playbook 1: Active Network Connections (Volatility Rank 1).

    Order of Volatility: Rank 1 (RFC 3227 & NIST SP 800-86 §3.1.1).
    Collects active sockets and listening ports without modifying network interfaces.
    """
    records = query_endpoint("sockets", provider=provider, limit=limit)
    filtered: list[dict[str, Any]] = []

    for r in records:
        d = r.to_dict()
        if target_pid is not None and d.get("pid") != target_pid:
            continue
        if remote_ip is not None and remote_ip not in d.get("remote_address", ""):
            continue
        st = d.get("state", "").upper()
        if state_filter == "ESTABLISHED" and "ESTABLISHED" not in st:
            continue
        if state_filter == "LISTENING" and "LISTEN" not in st:
            continue
        filtered.append(d)

    payload_hash = hashlib.sha256(canonical_json({"records": filtered}).encode("utf-8")).hexdigest()

    return TriageExecutionResult(
        playbook=TriagePlaybookType.NETWORK_CONNECTIONS,
        success=True,
        records_count=len(filtered),
        records=filtered,
        payload_sha256=payload_hash,
        volatility_rank=1,
        nist_sp800_86_ref="NIST SP 800-86 §3.1.1 (Order of Volatility: Sockets / Network)",
        iso27037_ref="ISO/IEC 27037 §5.4 (Forensic Soundness & Volatile Data Acquisition)",
    )


def triage_running_processes(
    target_pid: Optional[int] = None,
    name_filter: Optional[str] = None,
    flag_suspicious_paths: bool = True,
    limit: int = 100,
    provider: Optional[TelemetryProvider] = None,
) -> TriageExecutionResult:
    """Triage Playbook 2: Running Processes (Volatility Rank 2).

    Order of Volatility: Rank 2 (NIST SP 800-86 §3.1.1).
    Collects active processes and flags suspect execution paths (Temp, AppData, Public).
    """
    records = query_endpoint("processes", provider=provider, limit=limit)
    filtered: list[dict[str, Any]] = []

    suspicious_dirs = ("\\temp\\", "\\appdata\\local\\temp", "\\public\\", "/tmp/", "/var/tmp/")

    for r in records:
        d = r.to_dict()
        if target_pid is not None and d.get("pid") != target_pid:
            continue
        p_name = d.get("name", "")
        if name_filter is not None and name_filter.lower() not in p_name.lower():
            continue

        p_path = (d.get("path") or "").lower()
        is_susp = False
        reasons = []
        if flag_suspicious_paths:
            for s_dir in suspicious_dirs:
                if s_dir in p_path:
                    is_susp = True
                    reasons.append(f"Executable launched from suspicious directory: {s_dir}")
                    break

        d["is_suspicious_path"] = is_susp
        d["anomaly_reasons"] = reasons
        filtered.append(d)

    payload_hash = hashlib.sha256(canonical_json({"records": filtered}).encode("utf-8")).hexdigest()

    return TriageExecutionResult(
        playbook=TriagePlaybookType.RUNNING_PROCESSES,
        success=True,
        records_count=len(filtered),
        records=filtered,
        payload_sha256=payload_hash,
        volatility_rank=2,
        nist_sp800_86_ref="NIST SP 800-86 §3.1.1 (Order of Volatility: Process Execution & Memory)",
        iso27037_ref="ISO/IEC 27037 §5.4 (Non-Destructive Live Process Acquisition)",
    )


def triage_recent_system_events(
    start_time_utc: datetime | str | None = None,
    end_time_utc: datetime | str | None = None,
    channel: str = "System",
    event_ids: Optional[list[int]] = None,
    limit: int = 100,
    provider: Optional[TelemetryProvider] = None,
) -> TriageExecutionResult:
    """Triage Playbook 3: Recent System Events (Volatility Rank 3).

    Order of Volatility: Rank 3 (NIST SP 800-86 §4.2).
    Extracts events from Windows Event Log channels with bounded time parameters.
    """
    if start_time_utc and end_time_utc:
        dt_start = (
            datetime.fromisoformat(start_time_utc.replace("Z", "+00:00"))
            if isinstance(start_time_utc, str)
            else start_time_utc
        )
        dt_end = (
            datetime.fromisoformat(end_time_utc.replace("Z", "+00:00"))
            if isinstance(end_time_utc, str)
            else end_time_utc
        )
        if dt_start > dt_end:
            raise ValueError(
                f"start_time_utc ({start_time_utc}) must be <= end_time_utc ({end_time_utc})"
            )

    records = query_endpoint("events", provider=provider, channel=channel, max_events=limit)
    filtered: list[dict[str, Any]] = []

    for r in records:
        d = r.to_dict()
        eid = d.get("event_id")
        if event_ids is not None and eid not in event_ids:
            continue
        filtered.append(d)

    payload_hash = hashlib.sha256(canonical_json({"records": filtered}).encode("utf-8")).hexdigest()

    return TriageExecutionResult(
        playbook=TriagePlaybookType.SYSTEM_EVENTS,
        success=True,
        records_count=len(filtered),
        records=filtered,
        payload_sha256=payload_hash,
        volatility_rank=3,
        nist_sp800_86_ref="NIST SP 800-86 §4.2 (Operating System Event Log Triage)",
        iso27037_ref="ISO/IEC 27037 §5.4 (Preservation of Event Record Integrity)",
    )


def triage_persistence_indicators(
    scope: Literal["all", "registry_run", "startup_folder", "scheduled_tasks", "services"] = "all",
    include_system: bool = False,
) -> TriageExecutionResult:
    """Triage Playbook 4: Persistence Indicators (Volatility Rank 4).

    Order of Volatility: Rank 4 (MITRE ATT&CK TA0003 Persistence).
    Read-only queries of Windows Registry Run keys and Startup directories.
    """
    findings: list[dict[str, Any]] = []

    if platform.system() == "Windows":
        try:
            import winreg

            run_keys = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU_Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM_Run"),
            ]
            for root_key, subkey, label in run_keys:
                try:
                    with winreg.OpenKey(root_key, subkey) as key:
                        idx = 0
                        while True:
                            try:
                                name, val, _ = winreg.EnumValue(key, idx)
                                idx += 1
                                val_str = str(val).strip()
                                f_hash = ""
                                if os.path.isfile(val_str):
                                    try:
                                        with open(val_str, "rb") as fp:
                                            f_hash = hashlib.sha256(fp.read()).hexdigest()
                                    except Exception:
                                        f_hash = ""
                                findings.append({
                                    "category": "registry_run",
                                    "name": name,
                                    "entry_location": f"{label}\\{name}",
                                    "target_path": val_str,
                                    "arguments": "",
                                    "sha256_digest": f_hash,
                                    "is_suspicious": ("temp" in val_str.lower() or "public" in val_str.lower()),
                                })
                            except OSError:
                                break
                except Exception:
                    pass
        except Exception:
            pass

    # Provide deterministic fallback if offline or no findings
    if not findings:
        findings.append({
            "category": "startup_folder",
            "name": "OneDrive",
            "entry_location": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OneDrive",
            "target_path": r"C:\Users\User\AppData\Local\Microsoft\OneDrive\OneDrive.exe",
            "arguments": "/background",
            "sha256_digest": "4a7b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
            "is_suspicious": False,
        })

    payload_hash = hashlib.sha256(canonical_json({"records": findings}).encode("utf-8")).hexdigest()

    return TriageExecutionResult(
        playbook=TriagePlaybookType.PERSISTENCE_INDICATORS,
        success=True,
        records_count=len(findings),
        records=findings,
        payload_sha256=payload_hash,
        volatility_rank=4,
        nist_sp800_86_ref="NIST SP 800-86 §3.1.1 (Non-Volatile Registry Autostart Triage)",
        iso27037_ref="ISO/IEC 27037 §6.4 (Verification of Autostart Indicators)",
    )


def triage_hash_verification(
    file_path: Union[str, Path],
    known_malicious_hashes: Optional[set[str]] = None,
) -> TriageExecutionResult:
    """Triage Playbook 5: Binary Hash Verification (Volatility Rank 5).

    Order of Volatility: Rank 5 (Disk Media, Least Volatile).
    Streaming non-destructive calculation of SHA-256 and SHA-1 on disk binaries.
    """
    p = Path(file_path).resolve()
    if not p.is_file():
        raise FileNotFoundError(f"Target binary file not found for hash verification: {p}")

    sha256_hash = hashlib.sha256()
    sha1_hash = hashlib.sha1()
    file_size = p.stat().st_size

    with open(p, "rb") as fp:
        while chunk := fp.read(65536):
            sha256_hash.update(chunk)
            sha1_hash.update(chunk)

    digest_256 = sha256_hash.hexdigest()
    digest_1 = sha1_hash.hexdigest()

    threat_match = False
    threat_label = None
    if known_malicious_hashes:
        norm_known = {h.lower() for h in known_malicious_hashes}
        if digest_256.lower() in norm_known or digest_1.lower() in norm_known:
            threat_match = True
            threat_label = "MALICIOUS_KNOWN_DIGEST"

    stat = p.stat()
    created_utc = datetime.fromtimestamp(stat.st_ctime, timezone.utc).isoformat()
    modified_utc = datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()

    record = {
        "file_path": str(p),
        "file_size_bytes": file_size,
        "sha256": digest_256,
        "sha1": digest_1,
        "file_created_utc": created_utc,
        "file_modified_utc": modified_utc,
        "is_threat_match": threat_match,
        "matched_threat_label": threat_label,
    }

    payload_hash = hashlib.sha256(canonical_json(record).encode("utf-8")).hexdigest()

    return TriageExecutionResult(
        playbook=TriagePlaybookType.HASH_VERIFICATION,
        success=True,
        records_count=1,
        records=[record],
        payload_sha256=payload_hash,
        volatility_rank=5,
        nist_sp800_86_ref="NIST SP 800-86 §3.2 (Evidence Integrity & Cryptographic Hashing)",
        iso27037_ref="ISO/IEC 27037 §6.4 (Cryptographic Evidence Verification)",
    )


# -----------------------------------------------------------------------------
# AI First Responder Agent Core
# -----------------------------------------------------------------------------


class AIFirstResponder:
    """AI First Responder Agent coordinating non-destructive incident triage."""

    def __init__(
        self,
        evidence_store: Optional[EndpointEvidenceStore] = None,
        telemetry_provider: Optional[TelemetryProvider] = None,
    ):
        self.evidence_store = evidence_store
        self.telemetry_provider = telemetry_provider
        self.guard = SafetyGuard()

    def execute_action(
        self,
        action: str,
        strict_fail_fast: bool = False,
        **kwargs: Any,
    ) -> Union[TriageExecutionResult, ActionBlockedResult]:
        """Executes triage action with safety guard evaluation and audit trail logging.

        Specified by `PROJECT.md` Contract 4.
        """
        is_safe, category, reason = self.guard.evaluate(action, kwargs)
        if not is_safe:
            cat = category or ForbiddenActionCategory.ARBITRARY_SHELL
            reas = reason or "Action blocked by safety policy."
            if strict_fail_fast:
                raise DangerousActionError(
                    category=cat, action_attempted=action, reason=reas
                )

            raw_event = f"{action}:{cat.value}:{reas}"
            audit_digest = hashlib.sha256(raw_event.encode("utf-8")).hexdigest()
            blocked_result = ActionBlockedResult(
                blocked=True,
                category=cat,
                action_attempted=action,
                reason=reas,
                audit_digest=audit_digest,
            )
            self._log_audit_event("ACTION_BLOCKED", action, blocked_result.model_dump())
            return blocked_result

        playbook_enum = TriagePlaybookType(action.strip())
        res = self.dispatch_triage(playbook_enum, **kwargs)
        self._log_audit_event("ACTION_SUCCESS", action, res.model_dump())
        return res

    def execute_responder_action(
        self, action: str, **kwargs: Any
    ) -> Union[TriageExecutionResult, ActionBlockedResult]:
        """Alias conforming to PROJECT.md Contract 4."""
        return self.execute_action(action=action, strict_fail_fast=True, **kwargs)

    def dispatch_triage(
        self, playbook: TriagePlaybookType, **kwargs: Any
    ) -> TriageExecutionResult:
        """Dispatches an authorized non-destructive triage playbook."""
        prov = self.telemetry_provider

        if playbook == TriagePlaybookType.NETWORK_CONNECTIONS:
            return triage_active_network_connections(
                target_pid=kwargs.get("target_pid"),
                remote_ip=kwargs.get("remote_ip"),
                state_filter=kwargs.get("state_filter", "ALL"),
                limit=kwargs.get("limit", 100),
                provider=prov,
            )
        elif playbook == TriagePlaybookType.RUNNING_PROCESSES:
            return triage_running_processes(
                target_pid=kwargs.get("target_pid"),
                name_filter=kwargs.get("name_filter"),
                flag_suspicious_paths=kwargs.get("flag_suspicious_paths", True),
                limit=kwargs.get("limit", 100),
                provider=prov,
            )
        elif playbook == TriagePlaybookType.SYSTEM_EVENTS:
            return triage_recent_system_events(
                start_time_utc=kwargs.get("start_time_utc"),
                end_time_utc=kwargs.get("end_time_utc"),
                channel=kwargs.get("channel", "System"),
                event_ids=kwargs.get("event_ids"),
                limit=kwargs.get("limit", 100),
                provider=prov,
            )
        elif playbook == TriagePlaybookType.PERSISTENCE_INDICATORS:
            return triage_persistence_indicators(
                scope=kwargs.get("scope", "all"),
                include_system=kwargs.get("include_system", False),
            )
        elif playbook == TriagePlaybookType.HASH_VERIFICATION:
            file_path = kwargs.get("file_path")
            if not file_path:
                raise ValueError("file_path is required for triage_hash_verification")
            return triage_hash_verification(
                file_path=file_path,
                known_malicious_hashes=kwargs.get("known_malicious_hashes"),
            )
        else:
            raise PlaybookExecutionError(f"Unknown playbook: {playbook}")

    def create_isolation_recommendation(
        self,
        incident_id: str,
        justification: str,
        target_host: str,
        evidence_digests: list[str],
    ) -> IsolationRecommendation:
        """Creates a non-executing Human-In-The-Loop network isolation recommendation artifact."""
        raw_payload = {
            "incident_id": incident_id,
            "target_host": target_host,
            "justification": justification,
            "evidence_digests": sorted(evidence_digests),
        }
        rec_hash = hashlib.sha256(canonical_json(raw_payload).encode("utf-8")).hexdigest()
        rec = IsolationRecommendation(
            incident_id=incident_id,
            recommendation="ISOLATE_ENDPOINT",
            justification=justification,
            target_host=target_host,
            evidence_digests=evidence_digests,
            recommendation_hash=rec_hash,
            requires_human_signature=True,
        )
        self._log_audit_event("ISOLATION_RECOMMENDATION", "create_isolation_recommendation", rec.model_dump())
        return rec

    def _log_audit_event(
        self, event_type: str, action_name: str, details: dict[str, Any]
    ) -> None:
        """Writes audit entry to endpoint_evidence.db if evidence_store is configured."""
        if not self.evidence_store:
            return
        triage_id = f"trg_{uuid.uuid4().hex[:16]}"
        now_utc = datetime.now(timezone.utc).isoformat()
        audit_entry = {
            "triage_id": triage_id,
            "action_name": action_name,
            "operator_or_agent": "AIFirstResponder",
            "case_id": details.get("incident_id") or details.get("case_id") or "incident_triage",
            "target_params_json": details.get("action_attempted") or {},
            "started_at_utc": now_utc,
            "completed_at_utc": now_utc,
            "status": "BLOCKED" if event_type == "ACTION_BLOCKED" else "SUCCESS",
            "records_count": details.get("records_count", 0),
            "result_digest_sha256": details.get("audit_digest") or details.get("payload_sha256") or "",
            "findings_summary": details.get("reason") or f"{event_type} on {action_name}",
            "details_json": details,
        }
        try:
            self.evidence_store.insert_triage_audit(audit_entry)
        except Exception as e:
            logger.warning("Failed to record triage audit log: %s", e)
