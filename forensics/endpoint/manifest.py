"""ISO/IEC 27037:2012 Digital Evidence Acquisition Manifest Generator & Verifier.

Implements the four standardized forensic lifecycle phases:
1. Identification
2. Collection
3. Acquisition (bit-stream verification: original_sha256 == copy_sha256)
4. Preservation (tamper-evident immutable storage)
"""

from __future__ import annotations

import hashlib
import json
import logging
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from forensics.endpoint.schemas import (
    AcquisitionManifest,
    AcquisitionProcessInfo,
    AuditTrailEntry,
    CaseMetadata,
    CryptographicVerificationInfo,
    EnvironmentState,
    EvidenceSourceInfo,
    PreservationInfo,
    canonical_json,
)
from forensics.paths import get_endpoint_evidence_db

logger = logging.getLogger("forensics.endpoint.manifest")


def _get_git_commit() -> str:
    """Attempts to retrieve the current git commit hash."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception:
        pass
    return "unknown"


def _compute_file_sha256(file_path: Path | str) -> str:
    """Computes SHA-256 hex digest of a file in 64KB blocks."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def generate_acquisition_manifest(
    acquisition_id: str,
    case_id: str,
    operator_did: str,
    consent_scope: str,
    source_type: str,
    source_id: str,
    original_path: str,
    size_bytes: int,
    original_sha256: str,
    copy_sha256: str,
    vault_file_path: str,
    destination_db: str | None = None,
    destination_table: str = "endpoint_evidence",
    records_ingested: int = 0,
    acquisition_method: str = "BITWISE_STREAM_COPY",
    start_time_utc: str | None = None,
    completion_time_utc: str | None = None,
    investigator_id: str | None = None,
    organization: str = "Digital Forensics Unit",
    audit_trail: list[dict[str, Any]] | None = None,
    output_path: Path | str | None = None,
) -> dict[str, Any]:
    """Builds and serializes an ISO/IEC 27037:2012 compliant digital evidence manifest."""
    destination_db = destination_db or str(get_endpoint_evidence_db())
    now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    start_ts = start_time_utc or now_utc
    comp_ts = completion_time_utc or now_utc

    orig_hash = original_sha256.lower().strip()
    copy_hash = copy_sha256.lower().strip()
    bitwise_match = orig_hash == copy_hash
    verif_status = "VERIFIED_IDENTICAL" if bitwise_match else "INTEGRITY_MISMATCH"

    env_state = EnvironmentState(
        hostname=platform.node(),
        os_name=platform.system(),
        os_version=platform.version(),
        architecture=platform.machine(),
    )

    ev_source = EvidenceSourceInfo(
        source_type=source_type,
        source_id=source_id,
        original_path=str(original_path),
        size_bytes=int(size_bytes),
        environment_state=env_state,
    )

    proc_info = AcquisitionProcessInfo(
        acquisition_method=acquisition_method,  # type: ignore[arg-type]
        tool_name="Blockchain-Forensics-EndpointAcquisition",
        tool_version="6.0.0",
        python_version=platform.python_version(),
        git_commit=_get_git_commit(),
        start_time_utc=start_ts,
        completion_time_utc=comp_ts,
        records_ingested=int(records_ingested),
    )

    crypto_verif = CryptographicVerificationInfo(
        hash_algorithm="SHA-256",
        original_sha256=orig_hash,
        copy_sha256=copy_hash,
        bitwise_match=bitwise_match,
        verification_status=verif_status,  # type: ignore[arg-type]
    )

    preserv_info = PreservationInfo(
        vault_file_path=str(vault_file_path),
        destination_db=str(destination_db),
        destination_table=str(destination_table),
        read_only_enforced=True,
    )

    case_meta = CaseMetadata(
        case_id=case_id,
        investigator_id=investigator_id or operator_did,
        operator_did=operator_did,
        consent_scope=consent_scope,
        organization=organization,
    )

    default_trail: list[AuditTrailEntry] = []
    if audit_trail:
        for item in audit_trail:
            default_trail.append(
                AuditTrailEntry(
                    stage=item.get("stage", "ACQUISITION"),
                    timestamp_utc=item.get("timestamp_utc", now_utc),
                    description=item.get("description", ""),
                    status=item.get("status", "OK"),
                )
            )
    else:
        default_trail = [
            AuditTrailEntry(
                stage="IDENTIFICATION",
                timestamp_utc=start_ts,
                description=f"Identified evidence source {source_id} at {original_path}",
                status="OK",
            ),
            AuditTrailEntry(
                stage="COLLECTION",
                timestamp_utc=start_ts,
                description=f"Computed original SHA-256 {orig_hash} under consent scope '{consent_scope}'",
                status="OK",
            ),
            AuditTrailEntry(
                stage="ACQUISITION",
                timestamp_utc=comp_ts,
                description=f"Bit-stream duplicate created with SHA-256 {copy_hash}; match={bitwise_match}",
                status="OK" if bitwise_match else "FAIL",
            ),
            AuditTrailEntry(
                stage="PRESERVATION",
                timestamp_utc=comp_ts,
                description=f"Persisted artifact to vault {vault_file_path} and indexed {records_ingested} records",
                status="OK",
            ),
        ]

    manifest = AcquisitionManifest(
        standard="ISO/IEC 27037:2012",
        manifest_version="1.0.0",
        acquisition_id=acquisition_id,
        case_metadata=case_meta,
        evidence_source=ev_source,
        acquisition_process=proc_info,
        cryptographic_verification=crypto_verif,
        preservation=preserv_info,
        audit_trail=default_trail,
    )

    manifest_dict = manifest.model_dump()

    if output_path:
        out_p = Path(output_path).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            f.write(json.dumps(manifest_dict, indent=2, sort_keys=True))

    return manifest_dict


def verify_acquisition_manifest(
    manifest_path_or_dict: Path | str | dict[str, Any],
    vault_file_path: Path | str | None = None,
) -> tuple[bool, str]:
    """Validates an acquisition manifest against ISO/IEC 27037 requirements and bitwise files.

    Returns (is_valid, reason).
    """
    if isinstance(manifest_path_or_dict, (Path, str)):
        p = Path(manifest_path_or_dict).resolve()
        if not p.exists():
            return False, f"Manifest file not found: {p}"
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as err:
            return False, f"Malformed manifest JSON: {err}"
    elif isinstance(manifest_path_or_dict, dict):
        data = manifest_path_or_dict
    else:
        return False, f"Invalid manifest input type: {type(manifest_path_or_dict)}"

    try:
        manifest = AcquisitionManifest.model_validate(data)
    except Exception as err:
        return False, f"Manifest schema validation failed: {err}"

    crypto = manifest.cryptographic_verification
    if crypto.original_sha256 != crypto.copy_sha256:
        return (
            False,
            f"Bitwise mismatch in manifest: original={crypto.original_sha256} != copy={crypto.copy_sha256}",
        )

    if not crypto.bitwise_match:
        return False, "Manifest bitwise_match flag is False"

    target_vault_file = vault_file_path or manifest.preservation.vault_file_path
    if target_vault_file:
        v_path = Path(target_vault_file).resolve()
        if not v_path.exists():
            return False, f"Preserved vault file not found on disk: {v_path}"
        actual_copy_sha256 = _compute_file_sha256(v_path)
        if actual_copy_sha256 != crypto.copy_sha256.lower():
            return (
                False,
                f"Disk vault file tampered: actual={actual_copy_sha256} != expected={crypto.copy_sha256}",
            )

    return True, "VALID_ISO_27037_MANIFEST"
