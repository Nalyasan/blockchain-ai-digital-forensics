"""Evidence Identity & Privacy Module (Milestone 1 — Requirement R2).

Provides cryptographic hashing, canonical URI generation, legacy verification identity,
and privacy sanitization for digital forensics evidence and custody records.

Key Invariants:
1. Zero-leakage: Raw case_id and note values are never reflected in error messages or logs.
2. No file probing: note_hash_bytes32 operates strictly in-memory on strings without touching filesystem.
3. Canonical URI: strictly 161 ASCII characters, conforming to MAX_URI_BYTES <= 256.
4. Hash cycle prevention: manifest hash is derived from manifest bytes without self-referential cycles.
5. Legacy compatibility: legacy unhashed case IDs and URIs are supported via explicit opt-in only.
"""
from __future__ import annotations

import hashlib
import re
from typing import Sequence

# Maximum URI length matching EvidenceRegistry.sol MAX_URI_BYTES
MAX_URI_BYTES = 256

# Canonical URI exact character/byte length:
# len("evidence://sha256/") [18] + case_digest [64] + len("/") [1] + manifest_digest [64] + len("/manifest.json") [14] = 161
CANONICAL_URI_LENGTH = 161

# case_id: ASCII alphanumeric plus '_', '-', '.', length 1 to 64 chars
CASE_ID_REGEX = re.compile(r"\A[A-Za-z0-9_.-]{1,64}\Z")

# 64-character lowercase hex string
HEX64_REGEX = re.compile(r"\A[0-9a-f]{64}\Z")


def sha256_utf8(text: str) -> str:
    """Compute 64-char lowercase hex SHA-256 digest of UTF-8 encoded string.

    Args:
        text: Input string to hash.

    Returns:
        64-character lowercase hexadecimal SHA-256 digest.

    Raises:
        ValueError: If text is not a string.
    """
    if not isinstance(text, str):
        raise ValueError("Invalid input: text must be a string")
    return hashlib.sha256(text.encode("utf-8")).hexdigest().lower()


def case_id_digest(case_id: str) -> str:
    """Validate case_id format and return its 64-char lowercase hex SHA-256 digest.

    Zero-leakage requirement: If validation fails, raises ValueError with a generic
    message without echoing the raw case_id value.

    Args:
        case_id: Case identifier (ASCII alphanumeric, '_', '-', '.', 1-64 chars).

    Returns:
        64-character lowercase hexadecimal SHA-256 digest.

    Raises:
        ValueError: If case_id format is invalid (generic message, zero leakage).
    """
    if not isinstance(case_id, str) or not CASE_ID_REGEX.match(case_id):
        raise ValueError("Invalid case_id format")
    return sha256_utf8(case_id)


def case_id_hash_bytes32(case_id: str) -> str:
    """Return '0x' prefixed 64-char hex SHA-256 digest of validated case_id.

    Args:
        case_id: Case identifier.

    Returns:
        '0x' followed by 64 hex characters.

    Raises:
        ValueError: If case_id format is invalid (generic message, zero leakage).
    """
    return "0x" + case_id_digest(case_id)


def note_hash_bytes32(note: str) -> str:
    """Validate note is non-empty string, strip whitespace, and return '0x' + SHA-256 digest.

    Strictly NO filesystem probing: Operates purely in-memory and does not check
    whether the note matches an existing file path (no os.path.exists or stat calls).
    Zero-leakage: Raw note text is never included in error messages.

    Args:
        note: Custody note string.

    Returns:
        '0x' followed by 64-character lowercase hex digest of stripped note.

    Raises:
        ValueError: If note is not a string, or is empty/whitespace-only.
    """
    if not isinstance(note, str):
        raise ValueError("Invalid note: must be a string")
    clean_note = note.strip()
    if not clean_note:
        raise ValueError("Invalid note: cannot be empty or whitespace-only")
    return "0x" + sha256_utf8(clean_note)


def canonical_storage_uri(case_digest: str, manifest_digest: str) -> str:
    """Generate canonical storage URI for evidence manifest.

    Format:
        evidence://sha256/<case_digest>/<manifest_digest>/manifest.json
        (exactly 161 characters).

    Validates:
        - case_digest and manifest_digest are 64-character hex strings.
        - Resulting URI is printable ASCII.
        - Resulting URI length is exactly 161 bytes and <= 256 bytes (MAX_URI_BYTES).

    Args:
        case_digest: 64-character hex digest of case ID (optional '0x' prefix accepted).
        manifest_digest: 64-character hex digest of manifest (optional '0x' prefix accepted).

    Returns:
        Canonical storage URI string of exactly 161 characters.

    Raises:
        ValueError: If digests are invalid hex or resulting URI violates constraints.
    """
    if not isinstance(case_digest, str) or not isinstance(manifest_digest, str):
        raise ValueError("Invalid digest: case_digest and manifest_digest must be strings")

    case_h = case_digest.lower()
    if case_h.startswith("0x"):
        case_h = case_h[2:]

    man_h = manifest_digest.lower()
    if man_h.startswith("0x"):
        man_h = man_h[2:]

    if not HEX64_REGEX.match(case_h):
        raise ValueError("Invalid case_digest: must be a 64-character hex string")
    if not HEX64_REGEX.match(man_h):
        raise ValueError("Invalid manifest_digest: must be a 64-character hex string")

    uri = f"evidence://sha256/{case_h}/{man_h}/manifest.json"

    try:
        encoded = uri.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("URI contains non-ASCII characters")

    if len(encoded) > MAX_URI_BYTES:
        raise ValueError(f"URI exceeds maximum byte length of {MAX_URI_BYTES}")

    if len(uri) != CANONICAL_URI_LENGTH:
        raise ValueError(f"Canonical URI must be exactly {CANONICAL_URI_LENGTH} characters")

    return uri


def validate_manifest_hash_cycle(manifest_bytes: bytes, manifest_digest: str) -> bool:
    """Ensure manifest hash is derived from manifest bytes without self-referential hash cycles.

    Verifies that:
    1. manifest_digest matches SHA-256 of manifest_bytes.
    2. manifest_bytes does not embed manifest_digest within itself (preventing self-referential cycle).

    Args:
        manifest_bytes: Raw bytes of the manifest file.
        manifest_digest: Expected SHA-256 hex digest.

    Returns:
        True if valid and non-cyclic; False otherwise.
    """
    if not isinstance(manifest_bytes, (bytes, bytearray)):
        return False
    if not isinstance(manifest_digest, str):
        return False

    clean_digest = manifest_digest.lower()
    if clean_digest.startswith("0x"):
        clean_digest = clean_digest[2:]

    if not HEX64_REGEX.match(clean_digest):
        return False

    computed = hashlib.sha256(manifest_bytes).hexdigest().lower()
    if computed != clean_digest:
        return False

    # Check for self-referential hash cycle: the digest must not appear inside the manifest content
    digest_ascii = clean_digest.encode("ascii")
    if digest_ascii in bytes(manifest_bytes).lower():
        return False

    return True


def string_to_bytes32_hex(text: str) -> str:
    """Legacy helper: Convert UTF-8 string to '0x' prefixed 32-byte hex with trailing zero padding.

    Args:
        text: Input string (UTF-8 encoded size must be <= 32 bytes).

    Returns:
        '0x' followed by 64 hex characters (32 bytes).

    Raises:
        ValueError: If text is not a string or exceeds 32 bytes.
    """
    if not isinstance(text, str):
        raise ValueError("Invalid input: text must be a string")
    encoded = text.encode("utf-8")
    if len(encoded) > 32:
        raise ValueError(f"String exceeds 32 bytes limit ({len(encoded)} bytes)")
    return "0x" + encoded.ljust(32, b"\x00").hex()


def identity_for_verify(
    case_id: str,
    manifest_sha256: str,
    legacy_case_encoding: bool = False,
    legacy_uri: bool | None = None,
) -> tuple[str, str]:
    """Provide identity tuple (case_id_b32, storage_uri) for verification.

    If legacy_case_encoding is False (default):
        Returns (case_id_hash_bytes32(case_id), canonical_storage_uri(case_id_digest(case_id), manifest_sha256)).
    If legacy_case_encoding is True:
        Returns legacy identity (string_to_bytes32_hex(case_id), f"evidence://{case_id}/manifest.json").

    Args:
        case_id: Case identifier.
        manifest_sha256: Manifest SHA-256 digest.
        legacy_case_encoding: If True, uses legacy unhashed encoding.
        legacy_uri: Alias for legacy_case_encoding for backwards compatibility.

    Returns:
        Tuple of (case_id_bytes32_hex, storage_uri).
    """
    is_legacy = legacy_case_encoding if legacy_uri is None else bool(legacy_uri)
    if is_legacy:
        if not isinstance(case_id, str) or not CASE_ID_REGEX.match(case_id):
            raise ValueError("Invalid case_id format")
        return string_to_bytes32_hex(case_id), f"evidence://{case_id}/manifest.json"

    digest = case_id_digest(case_id)
    return "0x" + digest, canonical_storage_uri(digest, manifest_sha256)


def sanitize_log_text(text: str, forbidden_strings: Sequence[str] | None) -> str:
    """Replace occurrences of any forbidden raw string with [REDACTED].

    Replaces longer matching strings first to prevent partial redaction leaks.

    Args:
        text: Text to sanitize.
        forbidden_strings: Sequence of strings that must be redacted.

    Returns:
        Sanitized text with forbidden strings replaced by '[REDACTED]'.
    """
    if not isinstance(text, str):
        text = str(text)
    if not forbidden_strings:
        return text

    valid_strings = [s for s in forbidden_strings if isinstance(s, str) and len(s) > 0]
    valid_strings.sort(key=len, reverse=True)

    for s in valid_strings:
        text = text.replace(s, "[REDACTED]")

    return text
