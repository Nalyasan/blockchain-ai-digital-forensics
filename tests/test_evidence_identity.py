"""Acceptance Unit Tests for Evidence Identity & Privacy (Milestone 1 — Requirement R2).

Validates Acceptance Gates:
- G3-05: Note SHA-256 Hashing & No File Probing
- G3-06: Case ID SHA-256 Hashing & Zero Leakage
- G3-07: Legacy Read-Only Compatibility
- G3-12: Canary Privacy & Secret Guardrails
- G3-15: Canonical URI Format & Byte Limits
"""
from __future__ import annotations

import builtins
import hashlib
import os
import pathlib
from unittest.mock import patch

import pytest

from forensics.evidence_identity import (
    CANONICAL_URI_LENGTH,
    MAX_URI_BYTES,
    canonical_storage_uri,
    case_id_digest,
    case_id_hash_bytes32,
    identity_for_verify,
    note_hash_bytes32,
    sanitize_log_text,
    sha256_utf8,
    string_to_bytes32_hex,
    validate_manifest_hash_cycle,
)
from forensics.onchain import (
    TOPIC_EVIDENCE_REGISTERED,
    check_registered_state,
    extract_evidence_id_from_receipt,
)


# ==============================================================================
# Gate G3-05: Note SHA-256 Hashing & No File Probing
# ==============================================================================
class TestGate3_05_NoteHashAndNoProbing:
    """Gate G3-05: Note hash is 0x + 64 hex chars with zero filesystem probing."""

    def test_note_hash_format_and_hex(self):
        """Note hash must produce '0x' + 64 lowercase hex characters matching SHA-256."""
        note = "Investigator collected sample item 42 from workstation"
        expected_digest = hashlib.sha256(note.encode("utf-8")).hexdigest()
        result = note_hash_bytes32(note)

        assert result.startswith("0x")
        assert len(result) == 66  # "0x" + 64 hex characters
        assert result[2:] == expected_digest
        assert result[2:].islower()

    def test_note_hash_whitespace_verbatim_preservation(self):
        """Leading and trailing whitespace must be preserved verbatim in hash computation."""
        base_note = "Custody transfer to secure storage vault"
        padded_note = f"   \t\n  {base_note}  \r\n\t  "

        hash_base = note_hash_bytes32(base_note)
        hash_padded = note_hash_bytes32(padded_note)

        # Hashes must differ because raw UTF-8 bytes differ
        assert hash_base != hash_padded
        assert hash_base == "0x" + hashlib.sha256(base_note.encode("utf-8")).hexdigest()
        assert hash_padded == "0x" + hashlib.sha256(padded_note.encode("utf-8")).hexdigest()

    def test_note_hash_unicode_multibyte(self):
        """Multi-byte Unicode characters must be hashed verbatim without loss or conversion."""
        unicode_notes = [
            "Thu thập ổ cứng NVMe tại hiện trường phòng lab #4 - niêm phong số 892",
            "証拠物件の押収およびハッシュ値検証記録",
            "Evidence collected 🔒📦 #case-99 with accents: é, à, ç, ñ, ö, ü",
            "Complex symbols: ∑∏∆∇∈∉⊆⊇ ⨁⨂ 0xDEADBEEF",
        ]
        for u_note in unicode_notes:
            result = note_hash_bytes32(u_note)
            expected = "0x" + hashlib.sha256(u_note.encode("utf-8")).hexdigest()
            assert result == expected
            assert len(result) == 66
            assert result[2:].islower()

    def test_note_hash_long_content(self):
        """Long custody notes must hash accurately according to SHA-256 over verbatim bytes."""
        for length in [512, 1024, 2048, 8192]:
            long_note = "A" * (length - 10) + " - END_NOTE"
            result = note_hash_bytes32(long_note)
            expected = "0x" + hashlib.sha256(long_note.encode("utf-8")).hexdigest()
            assert result == expected

    def test_note_hash_same_prefix_different_suffix(self):
        """Notes sharing identical prefixes but differing in suffixes or whitespace must yield distinct hashes."""
        n1 = "Custody transfer operation: Node Alpha"
        n2 = "Custody transfer operation: Node Alpha Prime"
        n3 = "Custody transfer operation: Node Alpha "  # Trailing space
        n4 = " Custody transfer operation: Node Alpha"  # Leading space

        h1 = note_hash_bytes32(n1)
        h2 = note_hash_bytes32(n2)
        h3 = note_hash_bytes32(n3)
        h4 = note_hash_bytes32(n4)

        assert len({h1, h2, h3, h4}) == 4  # All 4 hashes must be strictly distinct

    def test_note_hash_zero_leakage_in_exceptions(self):
        """Plaintext note content must NEVER leak into exceptions or logs."""
        secret_canary = "SUPER_SECRET_CANARY_NOTE_CONTENT_12345"
        # Whitespace-only notes that trigger validation errors
        with pytest.raises(ValueError) as excinfo:
            note_hash_bytes32("   \t\n  ")
        assert "cannot be empty or whitespace-only" in str(excinfo.value)
        assert secret_canary not in str(excinfo.value)

    def test_note_hash_no_filesystem_probing(self):
        """Note hash must NEVER attempt to probe or read the filesystem.

        Even if the note looks like a file path (absolute, relative, Windows, or Unix),
        it must be treated strictly as an in-memory literal string.
        """
        path_like_notes = [
            r"C:\secret.txt",
            r"C:\Windows\System32\drivers\etc\hosts",
            str(pathlib.Path(__file__).resolve()),
            "/etc/shadow",
            "/tmp/confidential_evidence.bin",
            "./relative/nonexistent/path/note.log",
            r"\\network_share\evidence\file.raw",
        ]

        def forbidden_fs_call(*args, **kwargs):
            raise AssertionError(f"Filesystem probed with args={args}, kwargs={kwargs}")

        # Patch all filesystem probing functions to ensure none are called
        with patch("os.path.exists", side_effect=forbidden_fs_call), \
             patch("os.stat", side_effect=forbidden_fs_call), \
             patch.object(pathlib.Path, "exists", side_effect=forbidden_fs_call), \
             patch.object(pathlib.Path, "stat", side_effect=forbidden_fs_call), \
             patch.object(builtins, "open", side_effect=forbidden_fs_call):

            for note_str in path_like_notes:
                result = note_hash_bytes32(note_str)
                expected_sha = hashlib.sha256(note_str.encode("utf-8")).hexdigest()
                assert result == f"0x{expected_sha}"

    def test_note_hash_empty_or_whitespace_rejected(self):
        """Empty or whitespace-only notes must be rejected with ValueError."""
        invalid_notes = ["", " ", "   ", "\t", "\n", "\r\n", "   \t\n\r  "]
        for empty_note in invalid_notes:
            with pytest.raises(ValueError, match="cannot be empty or whitespace-only"):
                note_hash_bytes32(empty_note)

    def test_note_hash_non_string_rejected(self):
        """Non-string inputs must be rejected with ValueError."""
        for non_str in [None, 12345, True, ["note"], {"note": "text"}, b"bytes_note"]:
            with pytest.raises(ValueError, match="must be a string"):
                note_hash_bytes32(non_str)  # type: ignore[arg-type]


# ==============================================================================
# Gate G3-06: Case ID SHA-256 Hashing & Zero Leakage
# ==============================================================================
class TestGate3_06_CaseIdHashAndZeroLeakage:
    """Gate G3-06: Case ID SHA-256 hashing into bytes32 with zero privacy leakage."""

    def test_case_id_digest_and_bytes32_valid(self):
        """Valid case IDs must correctly produce 64-hex digest and 0x-prefixed bytes32."""
        valid_cases = [
            "CASE-2026-001",
            "case_alpha_99",
            "C",
            "c.123-x_y",
            "X" * 64,  # max length 64
            "evidence.item-01_v2",
        ]
        for case_id in valid_cases:
            expected_hex = hashlib.sha256(case_id.encode("utf-8")).hexdigest()

            digest = case_id_digest(case_id)
            assert digest == expected_hex
            assert len(digest) == 64

            b32 = case_id_hash_bytes32(case_id)
            assert b32 == f"0x{expected_hex}"
            assert len(b32) == 66

    def test_case_id_invalid_inputs_zero_leakage(self):
        """Crucial Privacy: Invalid case_id inputs must raise ValueError WITHOUT echoing raw value."""
        sensitive_canary = "SECRET_CANARY_CASE_TOKEN_987654"
        invalid_cases = [
            "",                                  # empty
            " ",                                 # whitespace
            f"{sensitive_canary} with space",    # invalid character: space
            f"{sensitive_canary}/slash",         # invalid character: slash
            f"{sensitive_canary}:colon",         # invalid character: colon
            f"{sensitive_canary}@at",            # invalid character: @
            f"{sensitive_canary}#hash",          # invalid character: #
            f"{sensitive_canary}$money",         # invalid character: $
            f"{sensitive_canary}!bang",          # invalid character: !
            f"{sensitive_canary}*" * 3,          # invalid character: *
            "X" * 65,                            # length 65 exceeds max 64
            f"{sensitive_canary}" + ("A" * 40),  # length exceeds max 64
            f"{sensitive_canary}_emoji_\U0001F525",  # non-ASCII unicode
        ]

        for invalid_case in invalid_cases:
            with pytest.raises(ValueError) as exc_info:
                case_id_digest(invalid_case)

            exc_msg = str(exc_info.value)
            # Zero leakage check: generic error message exactly matches constant
            assert exc_msg == "Invalid case_id format"
            # Crucial assertion: sensitive raw input must NOT be reflected
            assert sensitive_canary not in exc_msg

            # Same zero-leakage check on case_id_hash_bytes32
            with pytest.raises(ValueError) as exc_info_b32:
                case_id_hash_bytes32(invalid_case)
            assert str(exc_info_b32.value) == "Invalid case_id format"
            assert sensitive_canary not in str(exc_info_b32.value)

    def test_case_id_non_string_rejected_zero_leakage(self):
        """Non-string inputs to case_id_digest must be rejected without leaking values."""
        for non_str in [None, 999999, False, ["case_id"], {"case": "1"}]:
            with pytest.raises(ValueError) as exc_info:
                case_id_digest(non_str)  # type: ignore[arg-type]
            assert str(exc_info.value) == "Invalid case_id format"

    def test_case_id_trailing_newline_rejected_zero_leakage(self):
        """Regex anchoring: case_id ending with \n, \r, or containing newlines must raise ValueError without leaking."""
        sensitive_canary = "SECRET_CANARY_NEWLINE_CASE_123"
        newline_cases = [
            "case-01\n",
            "case-01\r",
            "case-01\r\n",
            "\ncase-01",
            "case\n01",
            "A" * 64 + "\n",  # length 65 with trailing newline
            "A" * 64 + "\r",
            f"{sensitive_canary}\n",
            f"{sensitive_canary}\r\n",
            f"\n{sensitive_canary}",
        ]
        for bad_case in newline_cases:
            with pytest.raises(ValueError) as exc_info:
                case_id_digest(bad_case)
            assert str(exc_info.value) == "Invalid case_id format"
            assert sensitive_canary not in str(exc_info.value)

            with pytest.raises(ValueError) as exc_info_b32:
                case_id_hash_bytes32(bad_case)
            assert str(exc_info_b32.value) == "Invalid case_id format"
            assert sensitive_canary not in str(exc_info_b32.value)



# ==============================================================================
# Gate G3-07: Legacy Read-Only Compatibility
# ==============================================================================
class TestGate3_07_LegacyReadOnlyCompatibility:
    """Gate G3-07: Legacy verification mode produces unhashed case ID and legacy URI."""

    def test_identity_for_verify_default_canonical(self):
        """Default identity_for_verify must produce hashed bytes32 and canonical URI."""
        case_id = "CASE-2026-001"
        manifest_hash = "33" * 32

        b32, uri = identity_for_verify(case_id, manifest_hash)

        expected_case_digest = hashlib.sha256(case_id.encode("utf-8")).hexdigest()
        assert b32 == f"0x{expected_case_digest}"
        assert uri == f"evidence://sha256/{expected_case_digest}/{manifest_hash}/manifest.json"
        assert len(uri) == CANONICAL_URI_LENGTH

    def test_identity_for_verify_legacy_mode_explicit(self):
        """Explicit legacy_case_encoding=True produces legacy bytes32 and legacy URI."""
        case_id = "CASE-2026-001"
        manifest_hash = "33" * 32

        b32, uri = identity_for_verify(case_id, manifest_hash, legacy_case_encoding=True)

        expected_legacy_b32 = "0x" + case_id.encode("utf-8").ljust(32, b"\x00").hex()
        assert b32 == expected_legacy_b32
        assert uri == f"evidence://{case_id}/manifest.json"

    def test_identity_for_verify_legacy_uri_alias(self):
        """legacy_uri keyword argument acts as alias for legacy_case_encoding."""
        case_id = "CASE-LEGACY-02"
        manifest_hash = "44" * 32

        b32, uri = identity_for_verify(case_id, manifest_hash, legacy_uri=True)

        expected_legacy_b32 = "0x" + case_id.encode("utf-8").ljust(32, b"\x00").hex()
        assert b32 == expected_legacy_b32
        assert uri == f"evidence://{case_id}/manifest.json"

    def test_string_to_bytes32_hex_exact_padding(self):
        """string_to_bytes32_hex pads UTF-8 bytes to 32 bytes with null bytes."""
        text = "short_str"
        raw_bytes = text.encode("utf-8")
        expected_hex = "0x" + raw_bytes.ljust(32, b"\x00").hex()

        result = string_to_bytes32_hex(text)
        assert result == expected_hex
        assert len(result) == 66  # "0x" + 64 hex chars

        # Exact 32-byte string
        text_32 = "A" * 32
        result_32 = string_to_bytes32_hex(text_32)
        assert result_32 == "0x" + ("41" * 32)
        assert len(result_32) == 66

    def test_string_to_bytes32_hex_overflow_rejected(self):
        """Strings exceeding 32 UTF-8 bytes must be rejected."""
        overflow_text = "A" * 33
        with pytest.raises(ValueError, match="exceeds 32 bytes limit"):
            string_to_bytes32_hex(overflow_text)

        # 33 UTF-8 bytes with multi-byte characters
        multi_byte_overflow = "€" * 11  # 11 * 3 = 33 bytes
        with pytest.raises(ValueError, match="exceeds 32 bytes limit"):
            string_to_bytes32_hex(multi_byte_overflow)

    def test_identity_for_verify_rejects_newlines_in_legacy_and_canonical(self):
        """identity_for_verify must strictly reject newlines in both legacy and canonical modes."""
        bad_cases = ["case-01\n", "case-01\r", "A" * 64 + "\n"]
        manifest_hash = "33" * 32

        for bad in bad_cases:
            with pytest.raises(ValueError, match="Invalid case_id format"):
                identity_for_verify(bad, manifest_hash, legacy_case_encoding=False)

            with pytest.raises(ValueError, match="Invalid case_id format"):
                identity_for_verify(bad, manifest_hash, legacy_case_encoding=True)

    def test_check_registered_state_no_silent_downgrade(self):
        """check_registered_state must fail when checking legacy state with canonical parameters."""
        case_id = "CASE-LEGACY-01"
        manifest_hash = "ab" * 32
        submitter = "0x" + "1" * 40
        legacy_case = string_to_bytes32_hex(case_id).lower()
        legacy_uri = f"evidence://{case_id}/manifest.json"

        legacy_state = {
            "exists": True,
            "id": 1,
            "case": legacy_case,
            "hash": "0x" + manifest_hash,
            "submitter": submitter,
            "uri": legacy_uri,
            "registered_at": 1700000000,
        }

        # Canonical parameters
        can_case_hash = case_id_hash_bytes32(case_id).lower()
        can_uri = canonical_storage_uri(case_id_digest(case_id), manifest_hash)

        # Checking legacy state with canonical parameters MUST fail with REGISTRY_MISMATCH
        with pytest.raises((ValueError, RuntimeError), match="REGISTRY_MISMATCH"):
            check_registered_state(legacy_state, 1, can_case_hash, "0x" + manifest_hash, submitter, can_uri)

        # Checking legacy state with explicit legacy parameters MUST pass
        check_registered_state(legacy_state, 1, legacy_case, "0x" + manifest_hash, submitter, legacy_uri)

    def test_mixed_profile_strictly_rejected(self):
        """Mixed profiles (legacy case + canonical URI or canonical case + legacy URI) are strictly rejected."""
        case_id = "CASE-MIXED-01"
        manifest_hash = "cd" * 32
        submitter = "0x" + "2" * 40
        legacy_case = string_to_bytes32_hex(case_id).lower()
        legacy_uri = f"evidence://{case_id}/manifest.json"
        can_case_hash = case_id_hash_bytes32(case_id).lower()
        can_uri = canonical_storage_uri(case_id_digest(case_id), manifest_hash)

        # Mixed 1: Legacy case, Canonical URI
        mixed_state_1 = {
            "exists": True, "id": 2, "case": legacy_case,
            "hash": "0x" + manifest_hash, "submitter": submitter, "uri": can_uri,
        }
        with pytest.raises((ValueError, RuntimeError), match="REGISTRY_MISMATCH"):
            check_registered_state(mixed_state_1, 2, can_case_hash, "0x" + manifest_hash, submitter, can_uri)
        with pytest.raises((ValueError, RuntimeError), match="REGISTRY_MISMATCH"):
            check_registered_state(mixed_state_1, 2, legacy_case, "0x" + manifest_hash, submitter, legacy_uri)

        # Mixed 2: Canonical case, Legacy URI
        mixed_state_2 = {
            "exists": True, "id": 3, "case": can_case_hash,
            "hash": "0x" + manifest_hash, "submitter": submitter, "uri": legacy_uri,
        }
        with pytest.raises((ValueError, RuntimeError), match="REGISTRY_MISMATCH"):
            check_registered_state(mixed_state_2, 3, can_case_hash, "0x" + manifest_hash, submitter, can_uri)
        with pytest.raises((ValueError, RuntimeError), match="REGISTRY_MISMATCH"):
            check_registered_state(mixed_state_2, 3, legacy_case, "0x" + manifest_hash, submitter, legacy_uri)

    def test_extract_evidence_id_no_silent_downgrade(self):
        """extract_evidence_id_from_receipt must strictly enforce matching profile."""
        case_id = "CASE-LEGACY-02"
        manifest_hash = "ef" * 32
        submitter = "0x" + "3" * 40
        leg_case = string_to_bytes32_hex(case_id).lower()
        can_case = case_id_hash_bytes32(case_id).lower()
        leg_uri = f"evidence://{case_id}/manifest.json"
        can_uri = canonical_storage_uri(case_id_digest(case_id), manifest_hash)

        def make_receipt(topic2, uri_val):
            raw_uri = uri_val.encode()
            abi_data = (
                "0x" + "0" * 24 + submitter[2:] + f"{64:064x}" +
                f"{len(raw_uri):064x}" + raw_uri.hex() + ("00" * ((-len(raw_uri)) % 32))
            )
            return {
                "status": "0x1",
                "logs": [{
                    "address": "0x5fbdb2315678afecb367f032d93f642f64180aa3",
                    "topics": [TOPIC_EVIDENCE_REGISTERED, f"0x{1:064x}", topic2, "0x" + manifest_hash],
                    "data": abi_data,
                }]
            }

        leg_receipt = make_receipt(leg_case, leg_uri)
        can_receipt = make_receipt(can_case, can_uri)

        # Default (legacy_case_encoding=False): legacy receipt MUST fail
        with pytest.raises(ValueError, match="Event caseId mismatch"):
            extract_evidence_id_from_receipt(
                leg_receipt, expected_case_id=case_id, expected_manifest_sha256=manifest_hash,
                expected_uri=can_uri, legacy_case_encoding=False
            )

        # Canonical receipt succeeds with legacy_case_encoding=False
        assert extract_evidence_id_from_receipt(
            can_receipt, expected_case_id=case_id, expected_manifest_sha256=manifest_hash,
            expected_uri=can_uri, legacy_case_encoding=False
        ) == 1

        # Explicit legacy mode (legacy_case_encoding=True): canonical receipt MUST fail
        with pytest.raises(ValueError, match="Event caseId mismatch"):
            extract_evidence_id_from_receipt(
                can_receipt, expected_case_id=case_id, expected_manifest_sha256=manifest_hash,
                expected_uri=leg_uri, legacy_case_encoding=True
            )

        # Legacy receipt succeeds with legacy_case_encoding=True
        assert extract_evidence_id_from_receipt(
            leg_receipt, expected_case_id=case_id, expected_manifest_sha256=manifest_hash,
            expected_uri=leg_uri, legacy_case_encoding=True
        ) == 1



# ==============================================================================
# Gate G3-12: Canary Privacy & Secret Guardrails
# ==============================================================================
class TestGate3_12_CanaryPrivacyAndSecretGuardrails:
    """Gate G3-12: Zero raw secrets/canaries exposed in URIs, hashes, or logs."""

    CANARY_CASE = "CANARY_CASE_XYZ_SECRET"
    CANARY_NOTE = "CANARY_NOTE_CONFIDENTIAL_ABC"

    def test_canary_case_never_in_canonical_uri_or_hash(self):
        """Raw canary case ID must never appear in canonical URI or hashed bytes32."""
        manifest_digest = "55" * 32
        b32, uri = identity_for_verify(self.CANARY_CASE, manifest_digest)

        assert self.CANARY_CASE not in uri
        assert "XYZ_SECRET" not in uri
        assert self.CANARY_CASE not in b32
        assert "XYZ_SECRET" not in b32

    def test_canary_note_never_in_note_hash(self):
        """Raw canary note must never appear in note hash output."""
        n_hash = note_hash_bytes32(self.CANARY_NOTE)

        assert self.CANARY_NOTE not in n_hash
        assert "CONFIDENTIAL_ABC" not in n_hash

    def test_sanitize_log_text_redacts_single_and_multiple_canaries(self):
        """sanitize_log_text must replace all forbidden strings with [REDACTED]."""
        forbidden = [self.CANARY_CASE, self.CANARY_NOTE]
        raw_log = f"Processing case {self.CANARY_CASE} with note {self.CANARY_NOTE} on line 42."

        sanitized = sanitize_log_text(raw_log, forbidden)

        assert self.CANARY_CASE not in sanitized
        assert self.CANARY_NOTE not in sanitized
        assert sanitized == "Processing case [REDACTED] with note [REDACTED] on line 42."

    def test_sanitize_log_text_longer_substring_first(self):
        """Longer forbidden strings must be redacted first to avoid partial leak."""
        forbidden = ["CANARY_CASE", "CANARY_CASE_EXTENDED_SECRET"]
        raw_log = "Detected CANARY_CASE_EXTENDED_SECRET in execution trail."

        sanitized = sanitize_log_text(raw_log, forbidden)

        assert "CANARY_CASE" not in sanitized
        assert "EXTENDED_SECRET" not in sanitized
        assert sanitized == "Detected [REDACTED] in execution trail."

    def test_sanitize_log_text_edge_cases(self):
        """sanitize_log_text handles empty/None lists and non-string inputs safely."""
        text = "Normal log message without secrets."
        assert sanitize_log_text(text, None) == text
        assert sanitize_log_text(text, []) == text
        assert sanitize_log_text(text, [""]) == text

        # Non-string text converted to string and sanitized
        number_text = 123456
        assert sanitize_log_text(number_text, ["234"]) == "1[REDACTED]56"  # type: ignore[arg-type]


# ==============================================================================
# Gate G3-15: Canonical URI Format & Byte Limits
# ==============================================================================
class TestGate3_15_CanonicalUriFormatAndByteLimits:
    """Gate G3-15: Canonical storage URI schema, length, and hash cycle validation."""

    def test_canonical_uri_exact_length_and_limits(self):
        """Canonical storage URI must be exactly 161 characters and <= 256 bytes."""
        case_digest = "aa" * 32
        manifest_digest = "bb" * 32

        uri = canonical_storage_uri(case_digest, manifest_digest)

        assert len(uri) == CANONICAL_URI_LENGTH
        assert len(uri) == 161
        assert len(uri.encode("ascii")) <= MAX_URI_BYTES
        assert MAX_URI_BYTES == 256
        assert uri == f"evidence://sha256/{case_digest}/{manifest_digest}/manifest.json"

    def test_canonical_uri_accepts_0x_prefix_and_normalizes_lowercase(self):
        """canonical_storage_uri handles '0x' prefixes and uppercase hex seamlessly."""
        case_digest = "AA" * 32
        manifest_digest = "0x" + ("BB" * 32)

        uri = canonical_storage_uri(case_digest, manifest_digest)

        expected_case = ("aa" * 32)
        expected_man = ("bb" * 32)
        assert uri == f"evidence://sha256/{expected_case}/{expected_man}/manifest.json"
        assert len(uri) == 161

    def test_canonical_uri_rejection_of_non_hex_or_malformed_digests(self):
        """canonical_storage_uri rejects non-hex characters, invalid lengths, or non-strings."""
        valid_digest = "11" * 32

        malformed_digests = [
            "not_a_hex_string",
            "gg" * 32,             # 'g' is not hex
            "11" * 31,             # 62 chars (too short)
            "11" * 33,             # 66 chars without 0x (too long)
            "",                    # empty
            "   ",                 # whitespace
            None,                  # non-string
            123456,                # non-string
        ]

        for bad in malformed_digests:
            with pytest.raises(ValueError):
                canonical_storage_uri(bad, valid_digest)  # type: ignore[arg-type]
            with pytest.raises(ValueError):
                canonical_storage_uri(valid_digest, bad)  # type: ignore[arg-type]

    def test_canonical_storage_uri_rejects_trailing_newlines_and_whitespace(self):
        """canonical_storage_uri must strictly reject digests with trailing newlines, carriage returns, or whitespace."""
        valid_digest = "aa" * 32

        newline_digests = [
            ("bb" * 32) + "\n",
            ("bb" * 32) + "\r",
            ("bb" * 32) + "\r\n",
            "\n" + ("bb" * 32),
            ("bb" * 16) + "\n" + ("bb" * 16),
            "0x" + ("bb" * 32) + "\n",
            ("bb" * 32) + " ",
            " " + ("bb" * 32),
            "   ",
            "\t" + ("bb" * 32),
        ]

        for bad in newline_digests:
            with pytest.raises(ValueError, match="Invalid case_digest"):
                canonical_storage_uri(bad, valid_digest)
            with pytest.raises(ValueError, match="Invalid manifest_digest"):
                canonical_storage_uri(valid_digest, bad)


    def test_manifest_hash_cycle_validation_success(self):
        """validate_manifest_hash_cycle succeeds when hash is genuinely derived and not self-referential."""
        manifest_data = b'{"version": "1.1.0", "files": [{"path": "audit.log", "sha256": "cc"}]}'
        correct_digest = hashlib.sha256(manifest_data).hexdigest()

        # Both bare hex and 0x-prefixed hex must validate
        assert validate_manifest_hash_cycle(manifest_data, correct_digest) is True
        assert validate_manifest_hash_cycle(manifest_data, f"0x{correct_digest}") is True
        assert validate_manifest_hash_cycle(manifest_data, correct_digest.upper()) is True

    def test_manifest_hash_cycle_mismatched_digest_fails(self):
        """validate_manifest_hash_cycle fails if digest is not derived from manifest bytes."""
        manifest_data = b'{"files": []}'
        wrong_digest = "99" * 32

        assert validate_manifest_hash_cycle(manifest_data, wrong_digest) is False

    def test_manifest_hash_cycle_self_referential_cycle_rejected(self):
        """validate_manifest_hash_cycle must reject self-referential manifest embedding its own digest."""
        # Suppose a manifest file attempts to embed the target digest inside its own content:
        fake_target_digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        cyclic_manifest_bytes = f'{{"self_hash": "{fake_target_digest}"}}'.encode("utf-8")

        # Because the digest is embedded inside cyclic_manifest_bytes, it must be rejected
        assert validate_manifest_hash_cycle(cyclic_manifest_bytes, fake_target_digest) is False

    def test_manifest_hash_cycle_invalid_inputs(self):
        """validate_manifest_hash_cycle returns False on invalid argument types."""
        valid_digest = "11" * 32
        assert validate_manifest_hash_cycle("not_bytes", valid_digest) is False  # type: ignore[arg-type]
        assert validate_manifest_hash_cycle(b"bytes", None) is False  # type: ignore[arg-type]
        assert validate_manifest_hash_cycle(b"bytes", "not_hex") is False


# ==============================================================================
# Helper Verification: sha256_utf8
# ==============================================================================
def test_sha256_utf8_valid_and_errors():
    """sha256_utf8 produces exact 64 lowercase hex SHA-256 for strings, rejects non-strings."""
    assert sha256_utf8("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert sha256_utf8("hello") == hashlib.sha256(b"hello").hexdigest()
    assert sha256_utf8("tiếng việt") == hashlib.sha256("tiếng việt".encode("utf-8")).hexdigest()

    with pytest.raises(ValueError, match="text must be a string"):
        sha256_utf8(None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="text must be a string"):
        sha256_utf8(123)  # type: ignore[arg-type]
