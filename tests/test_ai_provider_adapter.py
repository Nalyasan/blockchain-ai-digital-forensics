"""Unit Test Suite for Multi-Model AI Provider Adapter & Security Guardrails (Milestone 3 / R4).

Verifies:
1. Polymorphic model instantiation for Ollama, OpenAI, Anthropic, Google Gemini, Custom, Deterministic Fallback.
2. Dynamic provider and model switching per session without code modification.
3. Air-gap security: default local Ollama, strictly NO automatic cloud fallback.
4. Credential gating: explicit user credentials and session consent (cloud_consent=True) required.
5. Credential masking: logs and metadata show only first 4 and last 4 characters (zero plain leaks).
6. Air-Gap Data Protection: blocks raw SQLite database binary streams, private keys, and secret tokens.
7. Zero-Permission Security Boundaries: prohibits shell execution, SQL mutations, tx signing, code editing.
8. Decoupling invariance: changing LLM provider never alters P8 ML model or P9 Halo2 ZKML circuit.
9. Deterministic Fallback Engine: clearly labeled as rule-based fallback, NEVER disguised as LLM inference.
10. Mock testing strategy: transparently documents mock testing when cloud credentials absent.
11. Two-stage RefChecker validation: existence_ref_ratio and content_match_ratio on AI-observed facts.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from pydantic_ai.models.anthropic import AnthropicModel
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.models.google import GoogleModel
from pydantic_ai.models.ollama import OllamaModel
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.models.test import TestModel

import forensics.ai.provider_adapter as adapter_module
from forensics.ai.provider_adapter import (
    CANONICAL_P8_META_SHA256,
    CANONICAL_P8_ONNX_SHA256,
    CANONICAL_P9_CIRCUIT_META_SHA256,
    CLOUD_PROVIDERS,
    CONFIG_VERSION,
    DEFAULT_ANTHROPIC_MODEL,
    DEFAULT_GEMINI_MODEL,
    DEFAULT_OLLAMA_MODEL,
    DEFAULT_OPENAI_MODEL,
    PROVIDER_ANTHROPIC,
    PROVIDER_CUSTOM,
    PROVIDER_DETERMINISTIC_FALLBACK,
    PROVIDER_GOOGLE,
    PROVIDER_OLLAMA,
    PROVIDER_OPENAI,
    AIAdapterError,
    AISecurityGuardrail,
    AirGapDataProtectionGuard,
    CloudConsentRequiredError,
    DataExfiltrationError,
    MissingCredentialsError,
    ModelDecouplingViolationError,
    MultiModelAIAdapter,
    OpenAIModel,
    ProviderUnavailableError,
    SessionAIConfig,
    UnauthorizedCapabilityError,
    mask_credential,
    normalize_provider_name,
    resolve_provider_credentials,
    verify_p8_p9_decoupling,
)
from forensics.ai.schemas import ForensicInvestigationOutput, ObservedFact, RuleDetection
from forensics.paths import get_project_root


# ------------------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------------------


@pytest.fixture
def clean_env(monkeypatch):
    """Ensures clean environment without leftover credentials."""
    for var in [
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
        "CUSTOM_AI_API_KEY",
        "OLLAMA_BASE_URL",
        "OLLAMA_HOST",
    ]:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def in_memory_forensic_db():
    """Provides a populated in-memory SQLite database matching canonical real_p4.db schema."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    with conn:
        conn.execute(
            """
            CREATE TABLE blocks(
                chain_id INT,
                number INT,
                hash TEXT,
                parent_hash TEXT,
                block_timestamp INT,
                block_time_utc TEXT,
                first_observed_at TEXT,
                collected_at TEXT,
                status TEXT DEFAULT 'canonical',
                raw_json TEXT,
                raw_sha256 TEXT,
                synthetic INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(chain_id, hash)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE transactions(
                chain_id INT,
                tx_hash TEXT,
                block_hash TEXT,
                block_number INT,
                tx_index INT,
                from_addr TEXT,
                to_addr TEXT,
                value_raw TEXT,
                nonce INT,
                input TEXT,
                raw_json TEXT,
                raw_sha256 TEXT,
                PRIMARY KEY(chain_id, tx_hash, block_hash)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE asset_transfers(
                transfer_id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain_id INT,
                block_number INT,
                block_hash TEXT,
                block_timestamp INT,
                tx_hash TEXT,
                log_index INT,
                asset_id TEXT,
                from_addr TEXT,
                to_addr TEXT,
                amount_raw TEXT,
                synthetic INTEGER NOT NULL DEFAULT 0,
                UNIQUE(chain_id, block_hash, tx_hash, log_index)
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE alerts(
                alert_id TEXT PRIMARY KEY,
                rule_id TEXT,
                rule_version TEXT,
                unit_type TEXT,
                unit_key TEXT,
                asset_id TEXT,
                severity TEXT,
                score REAL,
                reason TEXT,
                evidence_refs TEXT,
                window_start TEXT,
                window_end TEXT,
                created_at TEXT,
                status TEXT DEFAULT 'new',
                synthetic INTEGER NOT NULL DEFAULT 0
            );
            """
        )

        # Populate sample canonical ground truth records
        tx1 = "0x" + "a" * 64
        tx2 = "0x" + "b" * 64
        addr1 = "0x" + "1" * 40
        addr2 = "0x" + "2" * 40
        b_hash1 = "0x" + "c" * 64
        b_hash2 = "0x" + "d" * 64

        conn.execute(
            "INSERT INTO blocks VALUES (1, 100, ?, '0x0', 1680000000, '2023-03-28T00:00:00Z', '', '', 'canonical', '', '', 0)",
            (b_hash1,),
        )
        conn.execute(
            "INSERT INTO blocks VALUES (1, 101, ?, ?, 1680000012, '2023-03-28T00:00:12Z', '', '', 'canonical', '', '', 0)",
            (b_hash2, b_hash1),
        )

        conn.execute(
            "INSERT INTO transactions VALUES (1, ?, ?, 100, 0, ?, ?, '1000000000000000000', 0, '', '', '')",
            (tx1, b_hash1, addr1, addr2),
        )
        conn.execute(
            "INSERT INTO asset_transfers VALUES (1, 1, 100, ?, 1680000000, ?, 0, 'NATIVE', ?, ?, '1000000000000000000', 0)",
            (b_hash1, tx1, addr1, addr2),
        )

        conn.execute(
            "INSERT INTO transactions VALUES (1, ?, ?, 101, 0, ?, ?, '500000000000000000', 1, '', '', '')",
            (tx2, b_hash2, addr2, addr1),
        )
        conn.execute(
            "INSERT INTO asset_transfers VALUES (2, 1, 101, ?, 1680000012, ?, 0, '0x' || '3333333333333333333333333333333333333333', ?, ?, '500000000000000000', 0)",
            (b_hash2, tx2, addr2, addr1),
        )

        conn.execute(
            "INSERT INTO alerts VALUES ('alert-001', 'large_transfer', 'v1', 'tx', 'tx:' || ?, 'NATIVE', 'HIGH', 0.85, 'Transfer exceeded threshold', ?, '2023-03-28T00:00:00Z', '2023-03-28T00:00:12Z', '2023-03-28T00:00:15Z', 'new', 0)",
            (tx1, json.dumps([{"tx_hash": tx1, "block_number": 100, "from_addr": addr1, "to_addr": addr2, "asset_id": "NATIVE", "amount_raw": "1000000000000000000"}])),
        )
    return conn


# ------------------------------------------------------------------------------
# 1. Provider Normalization & Credential Masking Tests
# ------------------------------------------------------------------------------


class TestProviderNormalizationAndMasking:
    """Verifies provider name resolution and credential masking."""

    def test_normalize_provider_name_synonyms(self):
        assert normalize_provider_name("local") == PROVIDER_OLLAMA
        assert normalize_provider_name("ollama") == PROVIDER_OLLAMA
        assert normalize_provider_name("local_ollama") == PROVIDER_OLLAMA
        assert normalize_provider_name("openai") == PROVIDER_OPENAI
        assert normalize_provider_name("chatgpt") == PROVIDER_OPENAI
        assert normalize_provider_name("claude") == PROVIDER_ANTHROPIC
        assert normalize_provider_name("anthropic") == PROVIDER_ANTHROPIC
        assert normalize_provider_name("gemini") == PROVIDER_GOOGLE
        assert normalize_provider_name("google") == PROVIDER_GOOGLE
        assert normalize_provider_name("custom") == PROVIDER_CUSTOM
        assert normalize_provider_name("openai-compatible") == PROVIDER_CUSTOM
        assert normalize_provider_name("deterministic_fallback") == PROVIDER_DETERMINISTIC_FALLBACK
        assert normalize_provider_name("rule_fallback") == PROVIDER_DETERMINISTIC_FALLBACK
        assert normalize_provider_name("offline") == PROVIDER_DETERMINISTIC_FALLBACK

    def test_mask_credential_examples(self):
        assert mask_credential(None) == "[ABSENT]"
        assert mask_credential("") == "[ABSENT]"
        assert mask_credential("   ") == "[ABSENT]"
        assert mask_credential("12345") == "***"
        assert mask_credential("12345678") == "***"
        assert mask_credential("sk-ant-api03-abcdef1234567890") == "sk-a...7890"
        assert mask_credential("AIzaSySecretTestKey12345678") == "AIza...5678"

    def test_session_metadata_does_not_leak_raw_credential(self):
        raw_key = "sk-proj-SuperSecretKeyNeverLeakThisInLogs1234"
        adapter = MultiModelAIAdapter(
            provider="openai",
            api_key=raw_key,
            cloud_consent=True,
        )
        meta = adapter.get_session_metadata()
        meta_str = json.dumps(meta)
        assert raw_key not in meta_str
        assert meta["api_key_masked"] == "sk-p...1234"
        assert meta["provider"] == "openai"


# ------------------------------------------------------------------------------
# 2. Air-Gap Security & Credential Gating Tests
# ------------------------------------------------------------------------------


class TestAirGapAndCredentialGating:
    """Verifies air-gap security, consent requirements, and credentials gating."""

    def test_default_provider_is_ollama(self, clean_env):
        adapter = MultiModelAIAdapter()
        meta = adapter.get_session_metadata()
        assert meta["provider"] == PROVIDER_OLLAMA
        assert meta["model_id"] == DEFAULT_OLLAMA_MODEL
        assert meta["cloud_consent"] is False
        assert "11434" in meta["endpoint"]

    def test_no_automatic_cloud_fallback(self, clean_env):
        """Default adapter must NOT automatically fall back to cloud providers."""
        adapter = MultiModelAIAdapter(provider="ollama")
        meta = adapter.get_session_metadata()
        assert meta["provider"] == PROVIDER_OLLAMA
        # Cloud consent is False by default
        assert meta["cloud_consent"] is False

    def test_cloud_provider_requires_explicit_consent(self, clean_env):
        """Invoking cloud provider without cloud_consent=True must raise CloudConsentRequiredError."""
        adapter = MultiModelAIAdapter(
            provider="openai",
            api_key="sk-dummykey1234567890",
            cloud_consent=False,  # No consent
        )
        with pytest.raises(CloudConsentRequiredError) as exc_info:
            adapter.create_model()
        assert "explicit session consent" in str(exc_info.value)

    def test_cloud_provider_requires_credentials(self, clean_env):
        """Invoking cloud provider with consent but without credentials must raise MissingCredentialsError."""
        adapter = MultiModelAIAdapter(
            provider="anthropic",
            cloud_consent=True,
            api_key=None,
        )
        with pytest.raises(MissingCredentialsError) as exc_info:
            adapter.create_model()
        assert "Valid API key required" in str(exc_info.value)

    def test_cloud_credentials_from_env_gated_by_consent(self, monkeypatch):
        """Environment credentials are not used unless cloud_consent is explicitly True."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-env-secret-key-12345678")
        # Without consent -> should still fail with CloudConsentRequiredError
        adapter = MultiModelAIAdapter(provider="openai", cloud_consent=False)
        with pytest.raises(CloudConsentRequiredError):
            adapter.create_model()

        # With consent -> succeeds
        adapter_with_consent = MultiModelAIAdapter(provider="openai", cloud_consent=True)
        model = adapter_with_consent.create_model()
        assert isinstance(model, OpenAIChatModel)

    def test_non_local_custom_endpoint_requires_consent(self, clean_env):
        """Non-loopback custom endpoint requires cloud consent."""
        adapter = MultiModelAIAdapter(
            provider="custom",
            base_url="https://api.external-ai-host.com/v1",
            api_key="custom-key-123456",
            cloud_consent=False,
        )
        with pytest.raises(CloudConsentRequiredError) as exc_info:
            adapter.create_model()
        assert "Non-local custom endpoint" in str(exc_info.value)

    def test_local_custom_endpoint_allowed_without_cloud_consent(self, clean_env):
        """Loopback custom endpoint (e.g. vLLM or local proxy) is allowed offline."""
        adapter = MultiModelAIAdapter(
            provider="custom",
            base_url="http://127.0.0.1:8000/v1",
            api_key="local-key-123456",
            cloud_consent=False,
        )
        model = adapter.create_model()
        assert isinstance(model, OpenAIChatModel)


# ------------------------------------------------------------------------------
# 3. Air-Gap Data Protection Guard Tests
# ------------------------------------------------------------------------------


class TestAirGapDataProtectionGuard:
    """Verifies that secrets, private keys, and raw database payloads are blocked."""

    def test_blocks_raw_sqlite_database_header(self):
        raw_db_stream = "Here is some binary data: SQLite format 3\x00\x10\x00..."
        with pytest.raises(DataExfiltrationError) as exc:
            AirGapDataProtectionGuard.sanitize_and_audit_payload(raw_db_stream)
        assert "raw SQLite database binary stream" in str(exc.value)

    def test_blocks_pem_private_key_block(self):
        pem_key = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Y1W9Z...\n"
            "-----END RSA PRIVATE KEY-----\n"
        )
        with pytest.raises(DataExfiltrationError) as exc:
            AirGapDataProtectionGuard.sanitize_and_audit_payload(pem_key)
        assert "private key or cryptographic secret" in str(exc.value)

    def test_blocks_hex_private_key(self):
        prompt = "Investigate target address with private_key = 0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d"
        with pytest.raises(DataExfiltrationError) as exc:
            AirGapDataProtectionGuard.sanitize_and_audit_payload(prompt)
        assert "private key or cryptographic secret" in str(exc.value)

    def test_blocks_leaked_openai_api_key_in_payload(self):
        prompt = "Use the following credentials: sk-abc1234567890123456789012345 to authenticate"
        with pytest.raises(DataExfiltrationError) as exc:
            AirGapDataProtectionGuard.sanitize_and_audit_payload(prompt)
        assert "raw API key credential inside payload" in str(exc.value)

    def test_blocks_leaked_google_api_key_in_payload(self):
        prompt = "API key: AIzaSyD98765432101234567890123456789012"
        with pytest.raises(DataExfiltrationError) as exc:
            AirGapDataProtectionGuard.sanitize_and_audit_payload(prompt)
        assert "raw API key credential inside payload" in str(exc.value)

    def test_allows_clean_forensic_evidence_prompts(self):
        prompt = (
            "Case Identifier: euler-finance\n"
            "Investigate transaction 0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d "
            "and address 0xebc29199c817dc47ba12e3f86102564d640cbf99."
        )
        clean = AirGapDataProtectionGuard.sanitize_and_audit_payload(prompt)
        assert clean == prompt


# ------------------------------------------------------------------------------
# 4. Zero-Permission AI Security Boundaries Tests
# ------------------------------------------------------------------------------


class TestAISecurityGuardrail:
    """Verifies AI Investigator zero-permission boundaries (shell, SQL, tx, code)."""

    def test_prohibits_shell_command_execution(self):
        with pytest.raises(UnauthorizedCapabilityError) as exc:
            AISecurityGuardrail.validate_shell_execution("rm -rf /")
        assert "ZERO permission to execute shell commands" in str(exc.value)

    def test_prohibits_state_mutating_sql_queries(self):
        for bad_sql in [
            "INSERT INTO transactions VALUES ('0x123', 1, 'a', 'b', '10')",
            "UPDATE transactions SET value_raw = '0'",
            "DELETE FROM asset_transfers WHERE transfer_id = 1",
            "DROP TABLE alerts",
            "ALTER TABLE alerts ADD COLUMN fake TEXT",
            "REPLACE INTO alerts VALUES ('1', 'r', 'H', 0.9, 'x')",
            "PRAGMA writable_schema = 1",
        ]:
            with pytest.raises(UnauthorizedCapabilityError) as exc:
                AISecurityGuardrail.validate_sql_query(bad_sql)
            assert "ZERO permission to execute state-mutating SQL" in str(exc.value)

    def test_allows_read_only_select_queries(self):
        # Clean SELECT query does not raise
        AISecurityGuardrail.validate_sql_query(
            "SELECT tx_hash, block_number, from_addr, to_addr FROM asset_transfers WHERE block_number = 100"
        )

    def test_prohibits_blockchain_transactions(self):
        with pytest.raises(UnauthorizedCapabilityError) as exc:
            AISecurityGuardrail.validate_blockchain_transaction("eth_sendTransaction")
        assert "ZERO permission to sign or broadcast blockchain transactions" in str(exc.value)

    def test_prohibits_code_modification(self):
        with pytest.raises(UnauthorizedCapabilityError) as exc:
            AISecurityGuardrail.validate_code_modification("forensics/ai/investigator.py")
        assert "ZERO permission to edit source code" in str(exc.value)

    def test_enforces_tool_whitelist(self):
        # Whitelisted tools pass
        for t in ["get_alerts", "get_tx", "get_address_history", "get_counterparties", "get_timeline"]:
            AISecurityGuardrail.validate_tool_permission(t)

        # Unauthorized tool raises
        with pytest.raises(UnauthorizedCapabilityError) as exc:
            AISecurityGuardrail.validate_tool_permission("execute_bash_command")
        assert "ZERO permission to execute unauthorized tool" in str(exc.value)


# ------------------------------------------------------------------------------
# 5. Polymorphic Model Instantiation & Dynamic Switching Tests
# ------------------------------------------------------------------------------


class TestPolymorphicModelCreationAndSwitching:
    """Verifies model creation across providers and dynamic session switching."""

    def test_ollama_dynamic_model_not_locked_to_qwen(self, clean_env):
        adapter = MultiModelAIAdapter(
            provider="ollama",
            model_id="llama3.2:3b",
        )
        model = adapter.create_model()
        assert isinstance(model, OllamaModel)
        assert model.model_name == "llama3.2:3b"

    def test_openai_model_instantiation(self):
        adapter = MultiModelAIAdapter(
            provider="openai",
            model_id="gpt-4o-mini",
            api_key="sk-testkey1234567890abcdef",
            cloud_consent=True,
        )
        model = adapter.create_model()
        assert isinstance(model, OpenAIChatModel)
        # Naming compliance alias check
        assert isinstance(model, OpenAIModel)
        assert model.model_name == "gpt-4o-mini"

    def test_anthropic_model_instantiation(self):
        adapter = MultiModelAIAdapter(
            provider="anthropic",
            model_id="claude-3-5-sonnet-20241022",
            api_key="sk-ant-testkey1234567890abcdef",
            cloud_consent=True,
        )
        model = adapter.create_model()
        assert isinstance(model, AnthropicModel)
        assert model.model_name == "claude-3-5-sonnet-20241022"

    def test_google_gemini_model_instantiation(self):
        adapter = MultiModelAIAdapter(
            provider="google",
            model_id="gemini-2.0-flash",
            api_key="AIzaSyTestKey1234567890abcdef",
            cloud_consent=True,
        )
        model = adapter.create_model()
        assert isinstance(model, GoogleModel)
        assert model.model_name == "gemini-2.0-flash"

    def test_deterministic_fallback_labeling(self):
        """Rule engine / FunctionModel must be clearly labeled as rule fallback."""
        adapter = MultiModelAIAdapter(provider="deterministic_fallback")
        model = adapter.create_model()
        assert isinstance(model, FunctionModel)

        meta = adapter.get_session_metadata()
        assert meta["is_rule_based_fallback"] is True
        assert meta["inference_mode"] == "RULE_BASED_DETERMINISTIC_FALLBACK"
        assert "rule-based fallback engine" in meta["disclaimer"]

    def test_dynamic_session_switching_without_code_modification(self):
        """Adapter switches cleanly across sessions without recreating object or modifying code."""
        adapter = MultiModelAIAdapter(provider="ollama", model_id="qwen3:8b")
        meta1 = adapter.get_session_metadata()
        assert meta1["provider"] == "ollama"
        assert meta1["model_id"] == "qwen3:8b"

        # Switch to OpenAI
        adapter.switch_session(
            provider="openai",
            model_id="gpt-4o",
            api_key="sk-openai-key-12345678",
            cloud_consent=True,
        )
        meta2 = adapter.get_session_metadata()
        assert meta2["provider"] == "openai"
        assert meta2["model_id"] == "gpt-4o"
        assert meta2["api_key_masked"] == "sk-o...5678"
        assert meta2["cloud_consent"] is True

        # Switch to Anthropic
        adapter.switch_session(
            provider="anthropic",
            model_id="claude-3-5-sonnet-20241022",
            api_key="sk-ant-claude-key-998877",
            cloud_consent=True,
        )
        meta3 = adapter.get_session_metadata()
        assert meta3["provider"] == "anthropic"
        assert meta3["model_id"] == "claude-3-5-sonnet-20241022"

        # Switch to Deterministic Fallback
        adapter.switch_session(provider="deterministic_fallback")
        meta4 = adapter.get_session_metadata()
        assert meta4["provider"] == "deterministic_fallback"
        assert meta4["is_rule_based_fallback"] is True


# ------------------------------------------------------------------------------
# 6. Mock Testing Strategy Tests
# ------------------------------------------------------------------------------


class TestMockTestingStrategy:
    """Verifies transparent mock testing when cloud credentials are absent."""

    def test_mock_cloud_model_transparent_labeling(self):
        adapter = MultiModelAIAdapter(
            provider="openai",
            model_id="gpt-4o",
            is_mock=True,  # Mock mode
        )
        model = adapter.create_model()
        assert isinstance(model, FunctionModel)

        meta = adapter.get_session_metadata()
        assert meta["tested_via_mock"] is True
        assert "mock adapter" in meta["mock_testing_disclaimer"]
        assert "no live cloud verification claimed" in meta["mock_testing_disclaimer"]


# ------------------------------------------------------------------------------
# 7. Strict Decoupling Invariance (P5 LLM vs P8 ML & P9 Halo2 ZKML)
# ------------------------------------------------------------------------------


class TestDecouplingInvariance:
    """Verifies that changing the LLM provider in P5 has zero effect on P8 ML or P9 ZKML."""

    def test_p8_p9_artifacts_bitwise_invariance(self):
        """Asserts that onnx model, meta, and circuit files match canonical SHA-256 digests."""
        res = verify_p8_p9_decoupling()
        assert res["is_decoupled"] is True
        assert res["p8_onnx_verified"] is True
        assert res["p8_meta_verified"] is True
        assert res["p9_circuit_meta_verified"] is True

    def test_switching_llm_preserves_p8_p9_hashes(self):
        """Performs successive provider switches and verifies P8/P9 remain 100% byte-for-byte identical."""
        adapter = MultiModelAIAdapter(provider="ollama")

        # Provider Switch 1: OpenAI
        adapter.switch_session(
            provider="openai",
            api_key="sk-test-key-1234567890",
            cloud_consent=True,
        )
        verify_p8_p9_decoupling()

        # Provider Switch 2: Anthropic
        adapter.switch_session(
            provider="anthropic",
            api_key="sk-ant-test-key-12345678",
            cloud_consent=True,
        )
        verify_p8_p9_decoupling()

        # Provider Switch 3: Google
        adapter.switch_session(
            provider="google",
            api_key="AIzaSyTestKey12345678",
            cloud_consent=True,
        )
        verify_p8_p9_decoupling()

        # Provider Switch 4: Deterministic Fallback
        adapter.switch_session(provider="deterministic_fallback")
        verify_p8_p9_decoupling()

    def test_decoupling_raises_on_tampered_artifact(self, tmp_path, monkeypatch):
        """Simulates tampered P8 model and confirms ModelDecouplingViolationError is raised."""
        tampered_root = tmp_path / "tampered_repo"
        (tampered_root / "models").mkdir(parents=True)
        (tampered_root / "circuits" / "anomaly_detector_v1").mkdir(parents=True)

        # Write fake ONNX model
        fake_onnx = tampered_root / "models" / "anomaly_detector_v1.onnx"
        fake_onnx.write_text("corrupted_weights")

        with pytest.raises(ModelDecouplingViolationError) as exc:
            verify_p8_p9_decoupling(project_root=tampered_root)
        assert "Decoupling Invariant Violation" in str(exc.value)


# ------------------------------------------------------------------------------
# 8. Two-Stage RefChecker Validation Tests
# ------------------------------------------------------------------------------


class TestRefCheckerIntegration:
    """Verifies two-stage RefChecker validation (existence_ref_ratio and content_match_ratio)."""

    def test_ref_checker_passes_on_ground_truth_facts(self, in_memory_forensic_db):
        adapter = MultiModelAIAdapter()

        facts = [
            ObservedFact(
                statement="Verified transfer in block 100",
                tx_hash="0x" + "a" * 64,
                block_number=100,
                from_addr="0x" + "1" * 40,
                to_addr="0x" + "2" * 40,
                asset_id="NATIVE",
                amount_raw="1000000000000000000",
                evidence_refs=["tx:0x" + "a" * 64],
            )
        ]

        result = adapter.validate_observed_facts(facts, in_memory_forensic_db)
        assert result.is_valid is True
        assert result.status == "PASS"
        assert result.existence_ref_ratio == 1.0
        assert result.content_match_ratio == 1.0
        assert len(result.mismatches) == 0

    def test_ref_checker_flags_content_mismatch_on_tampered_amount(self, in_memory_forensic_db):
        adapter = MultiModelAIAdapter()

        facts = [
            ObservedFact(
                statement="Tampered transfer in block 100",
                tx_hash="0x" + "a" * 64,
                block_number=100,
                from_addr="0x" + "1" * 40,
                to_addr="0x" + "2" * 40,
                asset_id="NATIVE",
                amount_raw="9999999999999999999",  # Tampered amount!
                evidence_refs=["tx:0x" + "a" * 64],
            )
        ]

        result = adapter.validate_observed_facts(facts, in_memory_forensic_db)
        assert result.is_valid is False
        assert result.status == "CONTENT_MISMATCH"
        assert result.existence_ref_ratio == 1.0  # tx exists
        assert result.content_match_ratio < 1.0  # content field mismatch
        assert len(result.mismatches) > 0
        assert result.mismatches[0].field == "amount_raw"

    def test_ref_checker_flags_nonexistent_transaction_hash(self, in_memory_forensic_db):
        adapter = MultiModelAIAdapter()

        facts = [
            ObservedFact(
                statement="Fabricated transfer",
                tx_hash="0x" + "f" * 64,  # Non-existent in DB
                block_number=999,
                from_addr="0x" + "9" * 40,
                to_addr="0x" + "8" * 40,
                asset_id="NATIVE",
                amount_raw="1000",
            )
        ]

        result = adapter.validate_observed_facts(facts, in_memory_forensic_db)
        assert result.is_valid is False
        assert result.status == "CONTENT_MISMATCH"
        assert result.existence_ref_ratio == 0.0  # Zero existing refs
        assert len(result.mismatches) > 0


# ------------------------------------------------------------------------------
# 9. End-to-End execute_investigation Tests
# ------------------------------------------------------------------------------


class TestExecuteInvestigation:
    """Verifies end-to-end investigation execution, metadata injection, and guardrails."""

    def test_execute_investigation_attaches_session_metadata_and_ref_checker(self, in_memory_forensic_db):
        adapter = MultiModelAIAdapter(provider="deterministic_fallback")

        context = {"case_id": "case-test-01"}
        prompt = "Investigate case-test-01 and verify ground truth transactions."

        output = adapter.execute_investigation(
            case_context=context,
            prompt=prompt,
            readonly_db=in_memory_forensic_db,
        )

        assert isinstance(output, ForensicInvestigationOutput)
        assert output.case_id == "case-test-01"

        # Verify metadata injection
        meta = output.metadata
        assert meta["provider"] == "deterministic_fallback"
        assert meta["is_rule_based_fallback"] is True
        assert meta["inference_mode"] == "RULE_BASED_DETERMINISTIC_FALLBACK"
        assert "ref_checker" in meta
        assert "status" in meta["ref_checker"]
        assert "existence_ref_ratio" in meta["ref_checker"]

    def test_execute_investigation_blocks_exfiltration_prompt(self, in_memory_forensic_db):
        adapter = MultiModelAIAdapter(provider="deterministic_fallback")

        context = {"case_id": "case-leaked"}
        bad_prompt = "Here is my private_key = 0x1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"

        with pytest.raises(DataExfiltrationError):
            adapter.execute_investigation(
                case_context=context,
                prompt=bad_prompt,
                readonly_db=in_memory_forensic_db,
            )
