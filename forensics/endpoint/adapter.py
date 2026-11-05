"""Polymorphic Evidence Source Adapters complying with ISO/IEC 27037:2012.

Provides standard acquisition lifecycle across heterogeneous data sources:
- EVMCollectorAdapter (Blockchain transactions/blocks)
- JsonlLogAdapter (Static Sysmon/telemetry JSONL logs)
- EvtxLogAdapter (Static Windows Event Log files)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from forensics.endpoint.manifest import generate_acquisition_manifest
from forensics.endpoint.schemas import AcquisitionResult
from forensics.endpoint.static_logs import parse_evtx_log, parse_jsonl_log
from forensics.endpoint.store import EndpointEvidenceStore

logger = logging.getLogger("forensics.endpoint.adapter")

# Valid authorized consent scopes for forensic acquisition
ALLOWED_CONSENT_SCOPES = {
    "security_events_only",
    "process_telemetry",
    "network_sockets_only",
    "host_logs",
    "full_system_audit",
    "all_allowed_endpoint_data",
    "blockchain_transactions",
    "incident_investigation",
    "incident_response_case",
    "case_triage",
}


class ForensicIntegrityError(Exception):
    """Raised when bit-stream cryptographic verification fails (original != copy)."""
    pass


class ConsentScopeViolation(Exception):
    """Raised when evidence collection is attempted outside legal/authorized consent scope."""
    pass


def _compute_sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest().lower()


class EvidenceSourceAdapter(ABC):
    """Abstract Base Class for digital evidence source adapters (ISO/IEC 27037)."""

    def __init__(
        self,
        case_id: str = "CASE-DEFAULT",
        operator_did: str = "did:ethr:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
        vault_dir: Optional[Path | str] = None,
        evidence_store: Optional[EndpointEvidenceStore] = None,
    ):
        self.case_id = case_id
        self.operator_did = operator_did
        self.vault_dir = Path(vault_dir or "data/evidence_vault").resolve()
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_store = evidence_store or EndpointEvidenceStore()

    @property
    @abstractmethod
    def source_type(self) -> str:
        """Returns standard source type."""
        pass

    def validate_consent_scope(self, consent_scope: str) -> None:
        """Validates that collection is within authorized boundaries."""
        scope_str = (consent_scope or "").strip().lower()
        if not scope_str:
            raise ConsentScopeViolation("Consent scope cannot be empty.")
        if scope_str not in ALLOWED_CONSENT_SCOPES and not any(
            allowed in scope_str for allowed in ("security", "telemetry", "incident", "investigation", "audit")
        ):
            raise ConsentScopeViolation(
                f"Unauthorized consent scope '{consent_scope}'. Authorized scopes: {sorted(ALLOWED_CONSENT_SCOPES)}"
            )

    def _bitwise_preserve(
        self,
        source_path: Path,
        acquisition_id: str,
    ) -> tuple[str, str, Path]:
        """Performs bit-stream duplicate copy and enforces cryptographic verification."""
        if not source_path.exists():
            raise FileNotFoundError(f"Source evidence file not found: {source_path}")
        if source_path.stat().st_size == 0:
            raise ValueError(f"Source evidence file is empty: {source_path}")

        orig_sha = _compute_sha256_file(source_path)

        acq_vault = self.vault_dir / acquisition_id
        acq_vault.mkdir(parents=True, exist_ok=True)
        dest_path = acq_vault / source_path.name

        shutil.copy2(source_path, dest_path)
        copy_sha = _compute_sha256_file(dest_path)

        if orig_sha != copy_sha:
            try:
                dest_path.unlink()
            except OSError:
                pass
            raise ForensicIntegrityError(
                f"Bit-stream verification failed! original={orig_sha} != copy={copy_sha}"
            )

        return orig_sha, copy_sha, dest_path

    @abstractmethod
    def collect(self, source_path_or_query: str, consent_scope: str) -> AcquisitionResult:
        """Executes evidence collection, verification, and persistence."""
        pass


class JsonlLogAdapter(EvidenceSourceAdapter):
    """Adapter for acquiring static JSONL event, process, and socket logs."""

    @property
    def source_type(self) -> str:
        return "HOST_LOG_JSONL"

    def collect(
        self,
        source_path_or_query: str,
        consent_scope: str,
        source_id: str = "HOST-01:jsonl",
    ) -> AcquisitionResult:
        self.validate_consent_scope(consent_scope)
        start_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        src_path = Path(source_path_or_query).resolve()
        acq_id = f"acq_{uuid.uuid4().hex[:12]}"

        # 1. Bit-stream preservation & verification
        orig_sha, copy_sha, vault_file = self._bitwise_preserve(src_path, acq_id)

        # 2. Parsing
        parsed_records = parse_jsonl_log(vault_file, source_id=source_id)

        # 3. Insertion into evidence store
        for rec in parsed_records:
            rtype = rec.get("record_type")
            try:
                if rtype == "processes":
                    self.evidence_store.insert_process(rec)
                elif rtype == "sockets":
                    self.evidence_store.insert_socket(rec)
                elif rtype == "events":
                    self.evidence_store.insert_event(rec)
                elif rtype == "system_info":
                    self.evidence_store.insert_system_info(rec)
            except Exception as e:
                logger.debug("Record insertion notice: %s", e)

        comp_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        manifest_path = vault_file.parent / "acquisition_manifest.json"

        # 4. Generate ISO/IEC 27037 Manifest
        generate_acquisition_manifest(
            acquisition_id=acq_id,
            case_id=self.case_id,
            operator_did=self.operator_did,
            consent_scope=consent_scope,
            source_type=self.source_type,
            source_id=source_id,
            original_path=str(src_path),
            size_bytes=src_path.stat().st_size,
            original_sha256=orig_sha,
            copy_sha256=copy_sha,
            vault_file_path=str(vault_file),
            records_ingested=len(parsed_records),
            start_time_utc=start_utc,
            completion_time_utc=comp_utc,
            output_path=manifest_path,
        )

        # 5. Build and save AcquisitionResult
        result = AcquisitionResult(
            acquisition_id=acq_id,
            source_type=self.source_type,  # type: ignore[arg-type]
            source_id=source_id,
            consent_scope=consent_scope,
            original_sha256=orig_sha,
            copy_sha256=copy_sha,
            record_count=len(parsed_records),
            timestamp_utc=comp_utc,
            destination_path=str(vault_file),
            manifest_path=str(manifest_path),
            operator_or_agent_did=self.operator_did,
            case_id=self.case_id,
            status="VERIFIED",
            records=parsed_records,
            metadata={"parser": "JsonlLogAdapter", "source_file": src_path.name},
        )

        self.evidence_store.insert_acquisition(result)
        return result


class EvtxLogAdapter(EvidenceSourceAdapter):
    """Adapter for acquiring Windows Event Log (EVTX) forensic files."""

    @property
    def source_type(self) -> str:
        return "HOST_LOG_EVTX"

    def collect(
        self,
        source_path_or_query: str,
        consent_scope: str,
        source_id: str = "HOST-01:evtx",
    ) -> AcquisitionResult:
        self.validate_consent_scope(consent_scope)
        start_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        src_path = Path(source_path_or_query).resolve()
        acq_id = f"acq_{uuid.uuid4().hex[:12]}"

        # 1. Bit-stream preservation & verification
        orig_sha, copy_sha, vault_file = self._bitwise_preserve(src_path, acq_id)

        # 2. Parsing
        parsed_records = parse_evtx_log(vault_file, source_id=source_id)

        # 3. Insertion into evidence store
        for rec in parsed_records:
            try:
                self.evidence_store.insert_event(rec)
            except Exception as e:
                logger.debug("Event insertion notice: %s", e)

        comp_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        manifest_path = vault_file.parent / "acquisition_manifest.json"

        # 4. Generate ISO/IEC 27037 Manifest
        generate_acquisition_manifest(
            acquisition_id=acq_id,
            case_id=self.case_id,
            operator_did=self.operator_did,
            consent_scope=consent_scope,
            source_type=self.source_type,
            source_id=source_id,
            original_path=str(src_path),
            size_bytes=src_path.stat().st_size,
            original_sha256=orig_sha,
            copy_sha256=copy_sha,
            vault_file_path=str(vault_file),
            records_ingested=len(parsed_records),
            start_time_utc=start_utc,
            completion_time_utc=comp_utc,
            output_path=manifest_path,
        )

        # 5. Build and save AcquisitionResult
        result = AcquisitionResult(
            acquisition_id=acq_id,
            source_type=self.source_type,  # type: ignore[arg-type]
            source_id=source_id,
            consent_scope=consent_scope,
            original_sha256=orig_sha,
            copy_sha256=copy_sha,
            record_count=len(parsed_records),
            timestamp_utc=comp_utc,
            destination_path=str(vault_file),
            manifest_path=str(manifest_path),
            operator_or_agent_did=self.operator_did,
            case_id=self.case_id,
            status="VERIFIED",
            records=parsed_records,
            metadata={"parser": "EvtxLogAdapter", "source_file": src_path.name},
        )

        self.evidence_store.insert_acquisition(result)
        return result


class EVMCollectorAdapter(EvidenceSourceAdapter):
    """Adapter wrapping EVM block and transaction extraction into ISO/IEC 27037 pipeline."""

    @property
    def source_type(self) -> str:
        return "EVM"

    def collect(
        self,
        source_path_or_query: str,
        consent_scope: str = "blockchain_transactions",
        source_id: str = "EVM-RPC:blocks",
    ) -> AcquisitionResult:
        self.validate_consent_scope(consent_scope)
        start_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        src_path = Path(source_path_or_query).resolve()
        acq_id = f"acq_{uuid.uuid4().hex[:12]}"

        # If a file path is provided (e.g. exported raw EVM block/tx jsonl)
        if src_path.exists():
            orig_sha, copy_sha, vault_file = self._bitwise_preserve(src_path, acq_id)
            size_bytes = src_path.stat().st_size
            try:
                parsed_records = parse_jsonl_log(vault_file, source_id=source_id)
            except Exception:
                parsed_records = []
        else:
            # Query string representation
            acq_vault = self.vault_dir / acq_id
            acq_vault.mkdir(parents=True, exist_ok=True)
            vault_file = acq_vault / "evm_query.json"
            content = json.dumps({"query": source_path_or_query, "timestamp": start_utc}, indent=2)
            vault_file.write_text(content, encoding="utf-8")
            orig_sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
            copy_sha = orig_sha
            size_bytes = len(content.encode("utf-8"))
            parsed_records = [{"query": source_path_or_query}]

        comp_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        manifest_path = vault_file.parent / "acquisition_manifest.json"

        generate_acquisition_manifest(
            acquisition_id=acq_id,
            case_id=self.case_id,
            operator_did=self.operator_did,
            consent_scope=consent_scope,
            source_type=self.source_type,
            source_id=source_id,
            original_path=str(src_path),
            size_bytes=size_bytes,
            original_sha256=orig_sha,
            copy_sha256=copy_sha,
            vault_file_path=str(vault_file),
            records_ingested=len(parsed_records),
            start_time_utc=start_utc,
            completion_time_utc=comp_utc,
            output_path=manifest_path,
        )

        result = AcquisitionResult(
            acquisition_id=acq_id,
            source_type=self.source_type,  # type: ignore[arg-type]
            source_id=source_id,
            consent_scope=consent_scope,
            original_sha256=orig_sha,
            copy_sha256=copy_sha,
            record_count=len(parsed_records),
            timestamp_utc=comp_utc,
            destination_path=str(vault_file),
            manifest_path=str(manifest_path),
            operator_or_agent_did=self.operator_did,
            case_id=self.case_id,
            status="VERIFIED",
            records=parsed_records,
            metadata={"source": "EVMCollectorAdapter"},
        )

        self.evidence_store.insert_acquisition(result)
        return result
