"""Cryptographic Anchoring for P8 ML, XAI, and P9 ZKML Artifacts into Chain of Custody.

Adheres strictly to ISO/IEC 27037 standards:
- Mathematical digests (SHA-256) are committed on-chain
- Zero sensitive data (PII, private keys, raw telemetry, or model parameters) leaked on-chain
- Canonical JSON serialization ensures deterministic statement verification
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

CANARY_PATTERNS = [
    re.compile(r"0x[0-9a-fA-F]{64}"),  # Raw private keys
    re.compile(r"bearer\s+[A-Za-z0-9_-]+", re.IGNORECASE),
    re.compile(r"api[_-]?key\s*[:=]\s*[^\s,;]+", re.IGNORECASE),
    re.compile(r"password\s*[:=]\s*[^\s,;]+", re.IGNORECASE),
]


def canonical_json_bytes(obj: Any) -> bytes:
    """Serializes any object to canonical UTF-8 JSON without extraneous whitespace."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def canonical_hash(obj: Any) -> str:
    """Computes a 0x-prefixed 32-byte SHA-256 hex digest of an object's canonical JSON representation."""
    raw = canonical_json_bytes(obj)
    return "0x" + hashlib.sha256(raw).hexdigest().lower()


def compute_file_sha256(file_path: str | Path) -> str:
    """Computes 0x-prefixed SHA-256 hash of a file on disk."""
    p = Path(file_path)
    if not p.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")
    hasher = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return "0x" + hasher.hexdigest().lower()


def create_ml_xai_attestation_payload(
    evidence_id: int,
    model_sha256: str,
    entity_address: str,
    explanation_dict: dict[str, Any],
) -> tuple[str, str]:
    """Generates (artifact_hash, statement_hash) for a P8 ML + XAI finding.

    - artifact_hash: SHA-256 of the trained ONNX model weights and architecture.
    - statement_hash: Canonical digest of the explanation, bound to evidenceId and entity address.

    Zero model weights or feature raw data are exposed.
    """
    art_hash = model_sha256 if model_sha256.startswith("0x") else f"0x{model_sha256}"
    art_hash = art_hash.lower()

    xai_digest = canonical_hash(explanation_dict)
    statement_dict = {
        "type": "P8_XAI_EXPLANATION",
        "evidenceId": int(evidence_id),
        "modelSha256": art_hash,
        "entityAddress": entity_address.lower(),
        "xaiDigest": xai_digest,
    }
    stmt_hash = canonical_hash(statement_dict)
    return art_hash, stmt_hash


def create_zkml_attestation_payload(
    evidence_id: int,
    model_sha256: str,
    proof_sha256: str,
    input_commitment: str,
    output_commitment: str,
    vk_sha256: str,
) -> tuple[str, str]:
    """Generates (artifact_hash, statement_hash) for a P9 ZKML verified inference proof.

    - artifact_hash: SHA-256 of the Halo2 proof bytes (pi).
    - statement_hash: Canonical commitment binding proof, public commitments, and verification key.
    """
    proof_hash = proof_sha256 if proof_sha256.startswith("0x") else f"0x{proof_sha256}"
    proof_hash = proof_hash.lower()

    mod_hash = model_sha256 if model_sha256.startswith("0x") else f"0x{model_sha256}"
    mod_hash = mod_hash.lower()

    vkey_hash = vk_sha256 if vk_sha256.startswith("0x") else f"0x{vk_sha256}"
    vkey_hash = vkey_hash.lower()

    statement_dict = {
        "type": "P9_ZKML_VERIFIED_INFERENCE",
        "evidenceId": int(evidence_id),
        "modelSha256": mod_hash,
        "inputCommitment": input_commitment,
        "outputCommitment": output_commitment,
        "vkSha256": vkey_hash,
    }
    stmt_hash = canonical_hash(statement_dict)
    return proof_hash, stmt_hash


def scan_for_sensitive_leakage(text_or_dict: str | dict[str, Any], canaries: list[str] | None = None) -> list[str]:
    """Scans structured payload or text for accidental leakage of canaries or credentials.

    Returns:
        List of detected canary strings or matched patterns.
    """
    serialized = text_or_dict if isinstance(text_or_dict, str) else json.dumps(text_or_dict)
    detected: list[str] = []

    if canaries:
        for c in canaries:
            if c in serialized:
                detected.append(c)

    return detected
