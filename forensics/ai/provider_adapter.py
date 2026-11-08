"""P5 Multi-Model AI Provider Adapter & Security Guardrails (Milestone 3 / R4).

This module implements a unified polymorphic AI adapter supporting:
1. Local Ollama (default, dynamic models, not locked to qwen3:8b)
2. OpenAI API (OpenAIModel / OpenAIChatModel)
3. Anthropic Claude API (AnthropicModel)
4. Google Gemini API (GoogleModel)
5. Custom Provider (OpenAI-compatible endpoints via OpenAICompatibleProvider)
6. Deterministic Fallback Engine (FunctionModel / TestModel) clearly labeled as rule-based fallback,
   NEVER disguised as LLM inference.

Security & Architecture Guarantees (R4):
- Dynamic provider and model switching per session without code modification.
- Session metadata recorded: provider, model_id, timestamp_utc, config_version, credential masking.
- Air-Gap Security & Credential Gating:
  * Default to local Ollama; strictly NO automatic cloud fallback.
  * Require explicit user credentials and session consent before initiating cloud API calls.
  * Credential masking in logs and session metadata (show only first 4 and last 4 characters).
  * Prohibit sending raw evidence databases, private keys, or secrets to external services.
  * Mock testing strategy: When cloud credentials are absent, test cleanly using mocks and state
    clearly that cloud service was tested via mock (zero false claims of live cloud verification).
- Strict Decoupling & Security Boundaries:
  * Changing the LLM provider/model in P5 MUST NEVER modify the P8 ML model (CompactAnomalyMLP)
    or P9 Halo2 ZKML circuit.
  * The AI Investigator has ZERO permissions to execute shell commands, SQL mutating statements,
    blockchain transactions, or edit code.
  * Two-stage RefChecker validation (existence_ref_ratio and content_match_ratio) on all AI-observed
    facts against underlying SQLite databases.
"""

from __future__ import annotations

import ast
import hashlib
import json
import logging
import os
import re
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Literal, Optional, Sequence, Set, Tuple, Union

os.environ.setdefault("PYDANTIC_AI_NO_BANNER", "1")

from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic_ai import Agent, RunContext, UsageLimits
from pydantic_ai.models import Model
from pydantic_ai.models.anthropic import AnthropicModel
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai.models.google import GoogleModel
from pydantic_ai.models.ollama import OllamaModel
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.models.test import TestModel

from pydantic_ai.providers.anthropic import AnthropicProvider
from pydantic_ai.providers.google import GoogleProvider
from pydantic_ai.providers.ollama import OllamaProvider
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic_ai.providers.openai_compatible import OpenAICompatibleProvider

# Naming compliance alias: OpenAIModel maps to OpenAIChatModel
OpenAIModel = OpenAIChatModel

from forensics.ai.investigator import (
    DEFAULT_PROMPT_VERSION,
    DEFAULT_SYSTEM_PROMPT,
    ForensicInvestigator,
    InvestigationDeps,
    create_offline_forensic_model,
)
from forensics.ai.provider import (
    DEFAULT_MAX_TOOL_STEPS,
    DEFAULT_REQUEST_LIMIT,
    mask_api_key,
    resolve_ollama_base_url,
)
from forensics.ai.ref_checker import (
    ReferenceCheckResult,
    RefMismatch,
    check_investigation_output,
    verify_observed_facts,
    verify_references_existence,
)
from forensics.ai.schemas import (
    AnalystInterpretation,
    ExternalLabel,
    ForensicInvestigationOutput,
    ObservedFact,
    RuleDetection,
)
from forensics.ai.tools import (
    AUTHORIZED_TOOLS,
    MAX_AI_TOOL_STEPS,
    ToolBudgetManager,
    execute_guarded_tool,
    get_address_history,
    get_alerts,
    get_counterparties,
    get_ml_anomaly_analysis,
    get_threat_intel,
    get_timeline,
    get_tx,
)
from forensics.paths import get_circuits_dir, get_models_dir, get_project_root

logger = logging.getLogger("forensics.ai.provider_adapter")

__all__ = [
    # Constants
    "CLOUD_PROVIDERS",
    "CONFIG_VERSION",
    "DEFAULT_ANTHROPIC_MODEL",
    "DEFAULT_CUSTOM_MODEL",
    "DEFAULT_GEMINI_MODEL",
    "DEFAULT_OLLAMA_MODEL",
    "DEFAULT_OPENAI_MODEL",
    "PROVIDER_ANTHROPIC",
    "PROVIDER_CUSTOM",
    "PROVIDER_DETERMINISTIC_FALLBACK",
    "PROVIDER_GOOGLE",
    "PROVIDER_OLLAMA",
    "PROVIDER_OPENAI",
    # Exceptions
    "AIAdapterError",
    "CloudConsentRequiredError",
    "DataExfiltrationError",
    "MissingCredentialsError",
    "ModelDecouplingViolationError",
    "ProviderUnavailableError",
    "UnauthorizedCapabilityError",
    # Core Classes & Functions
    "AISecurityGuardrail",
    "AirGapDataProtectionGuard",
    "MultiModelAIAdapter",
    "OpenAIModel",
    "SessionAIConfig",
    "mask_credential",
    "normalize_provider_name",
    "resolve_provider_credentials",
    "verify_p8_p9_decoupling",
]

# Supported Provider Constants
PROVIDER_OLLAMA: str = "ollama"
PROVIDER_OPENAI: str = "openai"
PROVIDER_ANTHROPIC: str = "anthropic"
PROVIDER_GOOGLE: str = "google"
PROVIDER_CUSTOM: str = "custom"
PROVIDER_DETERMINISTIC_FALLBACK: str = "deterministic_fallback"

CLOUD_PROVIDERS: Set[str] = {PROVIDER_OPENAI, PROVIDER_ANTHROPIC, PROVIDER_GOOGLE}

# Default Model Identifiers
DEFAULT_OLLAMA_MODEL: str = "qwen3:8b"
DEFAULT_OPENAI_MODEL: str = "gpt-4o"
DEFAULT_ANTHROPIC_MODEL: str = "claude-3-5-sonnet-20241022"
DEFAULT_GEMINI_MODEL: str = "gemini-2.0-flash"
DEFAULT_CUSTOM_MODEL: str = "custom-model"
CONFIG_VERSION: str = "v1.0"

# Canonical Checksums for P8 ML & P9 Halo2 ZKML Invariance Protection
CANONICAL_P8_ONNX_SHA256: str = "d1b9ce8247f8a188355454ef5158280ce7b0d46dfb3388581023e9e01806aeff"
CANONICAL_P8_META_SHA256: str = "60e313e71a7a1ed8ea2da7addcf62b27be18a69d5b1c3f01030e7785415f286f"
CANONICAL_P9_CIRCUIT_META_SHA256: str = "ef804675b821a3524bfcee3b525ef8fc58256dd312036c6d1f946a3dcd09eb8d"


# Custom Exceptions


class AIAdapterError(Exception):
    """Base exception for Multi-Model AI Adapter errors."""


class ProviderUnavailableError(AIAdapterError):
    """Raised when an AI provider is unreachable or misconfigured."""


class MissingCredentialsError(AIAdapterError):
    """Raised when explicit user credentials required for cloud provider are missing."""


class CloudConsentRequiredError(AIAdapterError):
    """Raised when cloud AI provider is invoked without explicit user session consent."""


class DataExfiltrationError(AIAdapterError):
    """Raised when sensitive data (private keys, secrets, raw databases) are detected in AI payload."""


class UnauthorizedCapabilityError(AIAdapterError):
    """Raised when an unauthorized capability (shell, mutating SQL, tx signing, code edit) is requested."""


class ModelDecouplingViolationError(AIAdapterError):
    """Raised when LLM configuration changes attempt or cause mutation of P8 ML or P9 ZKML models."""


# Provider Normalization & Credential Helpers


def normalize_provider_name(provider: str) -> str:
    """Normalizes various provider synonyms into canonical provider identifiers."""
    p = str(provider or "").strip().lower()
    if p in ("ollama", "local", "local_ollama", "ollama_local"):
        return PROVIDER_OLLAMA
    if p in ("openai", "chatgpt", "gpt"):
        return PROVIDER_OPENAI
    if p in ("anthropic", "claude"):
        return PROVIDER_ANTHROPIC
    if p in ("google", "gemini", "google_genai"):
        return PROVIDER_GOOGLE
    if p in ("custom", "openai_compatible", "openai-compatible", "compatible"):
        return PROVIDER_CUSTOM
    if p in ("deterministic_fallback", "deterministic", "fallback", "rule", "rule_fallback", "function", "test", "offline"):
        return PROVIDER_DETERMINISTIC_FALLBACK
    return p


def mask_credential(key: Optional[str]) -> str:
    """Safely masks an API key or credential string showing only first 4 and last 4 characters.

    Examples:
        - None or empty -> "[ABSENT]"
        - "12345" -> "***"
        - "sk-ant-api03-12345678" -> "sk-a...5678"
    """
    if not key or not str(key).strip():
        return "[ABSENT]"
    cleaned = str(key).strip()
    if len(cleaned) <= 8:
        return "***"
    return f"{cleaned[:4]}...{cleaned[-4:]}"


def resolve_provider_credentials(
    provider: str,
    override_key: Optional[str] = None,
    cloud_consent: bool = False,
) -> Tuple[Optional[str], str]:
    """Resolves provider API key with strict credential precedence.

    Precedence:
    1. override_key parameter (explicit per-session key).
    2. Environment variables ONLY IF cloud_consent is True:
       - OpenAI: OPENAI_API_KEY
       - Anthropic: ANTHROPIC_API_KEY
       - Google: GOOGLE_API_KEY, then GEMINI_API_KEY

    Returns:
        Tuple of (api_key, source_identifier).
    """
    canon_p = normalize_provider_name(provider)

    if override_key and str(override_key).strip():
        return str(override_key).strip(), "explicit_session_credential"

    # Cloud credentials from env are strictly gated behind cloud_consent
    if canon_p in CLOUD_PROVIDERS and not cloud_consent:
        return None, "consent_not_granted"

    if canon_p == PROVIDER_OPENAI:
        env_k = os.getenv("OPENAI_API_KEY")
        if env_k and env_k.strip():
            return env_k.strip(), "OPENAI_API_KEY"

    elif canon_p == PROVIDER_ANTHROPIC:
        env_k = os.getenv("ANTHROPIC_API_KEY")
        if env_k and env_k.strip():
            return env_k.strip(), "ANTHROPIC_API_KEY"

    elif canon_p == PROVIDER_GOOGLE:
        env_k = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
        if env_k and env_k.strip():
            source = "GOOGLE_API_KEY" if os.getenv("GOOGLE_API_KEY") else "GEMINI_API_KEY"
            return env_k.strip(), source

    elif canon_p == PROVIDER_CUSTOM:
        env_k = os.getenv("CUSTOM_AI_API_KEY") or os.getenv("OPENAI_API_KEY")
        if env_k and env_k.strip():
            return env_k.strip(), "CUSTOM_AI_API_KEY"

    return None, "none"


# Air-Gap Data Protection & Leak Prevention Guard


class AirGapDataProtectionGuard:
    """Security guard preventing raw evidence databases, private keys, and secrets leakage."""

    # Patterns indicating raw private keys
    PRIVATE_KEY_PATTERNS = [
        re.compile(r"-----BEGIN\s+(?:[A-Z0-9_\-]+\s+)?PRIVATE\s+KEY-----", re.IGNORECASE),
        re.compile(r"(?i)\b(?:private[_\s-]?key|secret[_\s-]?key|prv_key)\s*[:=]\s*['\"]?(?:0x)?([0-9a-fA-F]{64})['\"]?"),
        re.compile(r"(?i)\bmnemonic\s*[:=]\s*['\"]?([a-z\s]{24,120})['\"]?"),
    ]

    # Pattern detecting raw SQLite database header bytes in strings
    SQLITE_HEADER_PATTERN = re.compile(r"SQLite format 3\x00")

    # Patterns indicating raw API keys in payload
    API_KEY_LEAK_PATTERNS = [
        re.compile(r"\bAIzaSy[A-Za-z0-9_\-]{33}\b"),
        re.compile(r"\bsk-[a-zA-Z0-9]{20,}\b"),
        re.compile(r"\bsk-ant-[a-zA-Z0-9_\-]{20,}\b"),
    ]

    @classmethod
    def sanitize_and_audit_payload(
        cls,
        payload: Any,
        allow_cloud_transmission: bool = False,
    ) -> str:
        """Audits and sanitizes payload before sending to model inference.

        Raises:
            DataExfiltrationError: If private keys, raw database headers, or secret credentials
            are detected in the payload intended for an external service.
        """
        text = str(payload)

        # 1. Prohibit raw SQLite database headers
        if cls.SQLITE_HEADER_PATTERN.search(text):
            raise DataExfiltrationError(
                "Air-Gap Guardrail Violation: Detected raw SQLite database binary stream in payload. "
                "Transmission of raw evidence databases to external AI services is strictly prohibited."
            )

        # 2. Prohibit private keys and sensitive secrets
        for pat in cls.PRIVATE_KEY_PATTERNS:
            if pat.search(text):
                raise DataExfiltrationError(
                    "Air-Gap Guardrail Violation: Detected private key or cryptographic secret in AI payload. "
                    "Private keys and mnemonics must never be exposed or transmitted to AI services."
                )

        # 3. Prohibit leaked API credentials in payload
        for pat in cls.API_KEY_LEAK_PATTERNS:
            if pat.search(text):
                raise DataExfiltrationError(
                    "Air-Gap Guardrail Violation: Detected raw API key credential inside payload text. "
                    "Credentials must not be echoed in prompt contexts."
                )

        return text


# AI Security Boundaries & Zero-Permission Enforcement Guardrail


class AISecurityGuardrail:
    """Enforces zero-permission security boundaries for AI Investigator."""

    FORBIDDEN_SQL_KEYWORDS = re.compile(
        r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|REPLACE|ATTACH|DETACH|PRAGMA\s+writable_schema)\b",
        re.IGNORECASE,
    )

    AUTHORIZED_TOOLS = set(AUTHORIZED_TOOLS)

    @classmethod
    def validate_tool_permission(cls, tool_name: str) -> None:
        """Ensures tool execution is restricted strictly to authorized read-only tools."""
        clean_name = tool_name.replace("tool_", "").strip()
        if clean_name not in cls.AUTHORIZED_TOOLS:
            raise UnauthorizedCapabilityError(
                f"Security Boundary Violation: AI Investigator has ZERO permission to execute unauthorized tool '{tool_name}'. "
                f"Authorized tools: {sorted(cls.AUTHORIZED_TOOLS)}"
            )

    @classmethod
    def validate_sql_query(cls, query: str) -> None:
        """Ensures no state-mutating SQL statement is executed by AI Investigator."""
        q = str(query or "").strip()
        match = cls.FORBIDDEN_SQL_KEYWORDS.search(q)
        if match:
            raise UnauthorizedCapabilityError(
                f"Security Boundary Violation: AI Investigator has ZERO permission to execute state-mutating SQL "
                f"keyword '{match.group(1)}'. Database access is strictly read-only."
            )

    @classmethod
    def validate_shell_execution(cls, command: str) -> None:
        """Enforces absolute prohibition on shell / terminal command execution."""
        raise UnauthorizedCapabilityError(
            f"Security Boundary Violation: AI Investigator has ZERO permission to execute shell commands ('{command}'). "
            "Terminal execution is prohibited by security policy AGENT.md R4."
        )

    @classmethod
    def validate_blockchain_transaction(cls, tx_action: str) -> None:
        """Enforces absolute prohibition on AI blockchain transaction signing or broadcast."""
        raise UnauthorizedCapabilityError(
            f"Security Boundary Violation: AI Investigator has ZERO permission to sign or broadcast "
            f"blockchain transactions ('{tx_action}'). Autonomous on-chain mutation is prohibited."
        )

    @classmethod
    def validate_code_modification(cls, target_file: str) -> None:
        """Enforces absolute prohibition on AI source code modification."""
        raise UnauthorizedCapabilityError(
            f"Security Boundary Violation: AI Investigator has ZERO permission to edit source code ('{target_file}'). "
            "Autonomous code modification is prohibited by security policy AGENT.md R4."
        )


# Strict Decoupling Verification: LLM Provider Changes vs P8 ML & P9 Halo2 ZKML


def verify_p8_p9_decoupling(project_root: Optional[Path] = None) -> Dict[str, Any]:
    """Verifies that P8 ML model and P9 Halo2 ZKML circuit artifacts are intact and untouched.

    Guarantees: Changing the LLM provider/model in P5 MUST NEVER modify the P8 ML model
    (CompactAnomalyMLP) or P9 Halo2 ZKML circuit.
    """
    root = project_root or get_project_root()
    p8_onnx = root / "models" / "anomaly_detector_v1.onnx"
    p8_meta = root / "models" / "anomaly_detector_v1_meta.json"
    p9_circuit_meta = root / "circuits" / "anomaly_detector_v1" / "circuit_meta.json"

    results: Dict[str, Any] = {
        "p8_onnx_verified": False,
        "p8_meta_verified": False,
        "p9_circuit_meta_verified": False,
        "is_decoupled": True,
        "violations": [],
    }

    if p8_onnx.is_file():
        h = hashlib.sha256(p8_onnx.read_bytes()).hexdigest().lower()
        if h == CANONICAL_P8_ONNX_SHA256:
            results["p8_onnx_verified"] = True
        else:
            results["is_decoupled"] = False
            results["violations"].append(f"P8 ONNX digest mismatch: expected {CANONICAL_P8_ONNX_SHA256}, got {h}")
    else:
        results["violations"].append(f"P8 ONNX model missing at {p8_onnx}")

    if p8_meta.is_file():
        h = hashlib.sha256(p8_meta.read_bytes()).hexdigest().lower()
        if h == CANONICAL_P8_META_SHA256:
            results["p8_meta_verified"] = True
        else:
            results["is_decoupled"] = False
            results["violations"].append(f"P8 meta digest mismatch: expected {CANONICAL_P8_META_SHA256}, got {h}")

    if p9_circuit_meta.is_file():
        h = hashlib.sha256(p9_circuit_meta.read_bytes()).hexdigest().lower()
        if h == CANONICAL_P9_CIRCUIT_META_SHA256:
            results["p9_circuit_meta_verified"] = True
        else:
            results["is_decoupled"] = False
            results["violations"].append(f"P9 circuit meta digest mismatch: expected {CANONICAL_P9_CIRCUIT_META_SHA256}, got {h}")

    if not results["is_decoupled"]:
        raise ModelDecouplingViolationError(
            f"Decoupling Invariant Violation: P8 ML / P9 ZKML artifacts were altered! Violations: {results['violations']}"
        )

    return results


# Session Configuration Schema


class SessionAIConfig(BaseModel):
    """Dynamic session configuration for Multi-Model AI Provider Adapter."""

    model_config = ConfigDict(extra="forbid")

    provider: str = Field(
        default=PROVIDER_OLLAMA,
        description="Target AI provider ('ollama', 'openai', 'anthropic', 'google', 'custom', 'deterministic_fallback').",
    )
    model_id: str = Field(
        default=DEFAULT_OLLAMA_MODEL,
        description="Target model identifier (e.g. 'qwen3:8b', 'gpt-4o', 'claude-3-5-sonnet-20241022', 'gemini-2.0-flash').",
    )
    api_key: Optional[str] = Field(
        default=None,
        description="Explicit per-session API credential. Never persisted in plain text.",
    )
    base_url: Optional[str] = Field(
        default=None,
        description="Optional custom API endpoint URL.",
    )
    cloud_consent: bool = Field(
        default=False,
        description="Explicit user session consent for cloud API transmission. MANDATORY for cloud providers.",
    )
    allow_deterministic_fallback: bool = Field(
        default=True,
        description="Allow offline deterministic rule-based fallback when local Ollama is offline. Strictly NO cloud fallback.",
    )
    config_version: str = Field(
        default=CONFIG_VERSION,
        description="Configuration version string for session metadata tracking.",
    )
    request_limit: int = Field(
        default=DEFAULT_REQUEST_LIMIT,
        description="Maximum model inference requests per investigation.",
        ge=1,
    )
    max_tool_steps: int = Field(
        default=DEFAULT_MAX_TOOL_STEPS,
        description="Maximum authorized tool call steps (default: 5).",
        ge=1,
    )
    temperature: float = Field(
        default=0.0,
        description="Sampling temperature (0.0 for deterministic forensics).",
        ge=0.0,
        le=2.0,
    )
    is_mock: bool = Field(
        default=False,
        description="Explicit mock testing flag for clean testing without live external credentials.",
    )

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, v: str) -> str:
        canon = normalize_provider_name(v)
        supported = {
            PROVIDER_OLLAMA,
            PROVIDER_OPENAI,
            PROVIDER_ANTHROPIC,
            PROVIDER_GOOGLE,
            PROVIDER_CUSTOM,
            PROVIDER_DETERMINISTIC_FALLBACK,
        }
        if canon not in supported:
            raise ValueError(f"Unsupported AI provider: {v!r}. Supported providers: {sorted(supported)}")
        return canon


# Unified Polymorphic Multi-Model AI Adapter


class MultiModelAIAdapter:
    """Unified polymorphic AI Provider Adapter with Air-Gap Security & Credential Gating."""

    def __init__(
        self,
        config: Optional[SessionAIConfig] = None,
        provider: Optional[str] = None,
        model_id: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        cloud_consent: bool = False,
        allow_deterministic_fallback: bool = True,
        is_mock: bool = False,
    ) -> None:
        if config is not None:
            self.config = config.model_copy()
        else:
            canon_provider = normalize_provider_name(provider or PROVIDER_OLLAMA)
            eff_model = model_id
            if not eff_model:
                if canon_provider == PROVIDER_OLLAMA:
                    eff_model = DEFAULT_OLLAMA_MODEL
                elif canon_provider == PROVIDER_OPENAI:
                    eff_model = DEFAULT_OPENAI_MODEL
                elif canon_provider == PROVIDER_ANTHROPIC:
                    eff_model = DEFAULT_ANTHROPIC_MODEL
                elif canon_provider == PROVIDER_GOOGLE:
                    eff_model = DEFAULT_GEMINI_MODEL
                elif canon_provider == PROVIDER_CUSTOM:
                    eff_model = DEFAULT_CUSTOM_MODEL
                else:
                    eff_model = "rule-engine-fallback"

            self.config = SessionAIConfig(
                provider=canon_provider,
                model_id=eff_model,
                api_key=api_key,
                base_url=base_url,
                cloud_consent=cloud_consent,
                allow_deterministic_fallback=allow_deterministic_fallback,
                is_mock=is_mock,
            )

        self._session_metadata: Dict[str, Any] = {}
        self._record_session_metadata()

    def _record_session_metadata(
        self,
        is_fallback: bool = False,
        fallback_reason: Optional[str] = None,
        tested_via_mock: bool = False,
    ) -> None:
        """Records immutable session metadata with credential masking and audit stamps."""
        now_utc = datetime.now(timezone.utc).isoformat()
        api_key_masked = mask_credential(self.config.api_key)

        metadata: Dict[str, Any] = {
            "provider": self.config.provider,
            "model_id": self.config.model_id,
            "timestamp_utc": now_utc,
            "config_version": self.config.config_version,
            "cloud_consent": self.config.cloud_consent,
            "api_key_masked": api_key_masked,
            "is_rule_based_fallback": is_fallback or (self.config.provider == PROVIDER_DETERMINISTIC_FALLBACK),
            "inference_mode": (
                "RULE_BASED_DETERMINISTIC_FALLBACK"
                if (is_fallback or self.config.provider == PROVIDER_DETERMINISTIC_FALLBACK)
                else "LLM_INFERENCE"
            ),
            "max_tool_steps": self.config.max_tool_steps,
            "request_limit": self.config.request_limit,
            "tested_via_mock": tested_via_mock or self.config.is_mock,
        }

        if self.config.base_url:
            metadata["endpoint"] = self.config.base_url
        elif self.config.provider == PROVIDER_OLLAMA:
            metadata["endpoint"] = resolve_ollama_base_url()

        if is_fallback:
            metadata["fallback_reason"] = fallback_reason or "Local service offline; deterministic rule-based fallback engaged."
            metadata["disclaimer"] = "Deterministic rule-based fallback engine: output produced via rule logic, NOT LLM inference."

        if metadata["tested_via_mock"]:
            metadata["mock_testing_disclaimer"] = (
                "Cloud service was tested via mock adapter (credentials absent; no live cloud verification claimed)."
            )

        self._session_metadata = metadata

    def get_session_metadata(self) -> Dict[str, Any]:
        """Returns non-sensitive session metadata dictionary."""
        return dict(self._session_metadata)

    def switch_session(
        self,
        provider: str,
        model_id: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        cloud_consent: Optional[bool] = None,
        allow_deterministic_fallback: Optional[bool] = None,
        is_mock: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Dynamically switches provider and model per session without code modification."""
        canon_p = normalize_provider_name(provider)

        # Default model selection if not explicitly provided
        eff_model = model_id
        if not eff_model:
            if canon_p == PROVIDER_OLLAMA:
                eff_model = DEFAULT_OLLAMA_MODEL
            elif canon_p == PROVIDER_OPENAI:
                eff_model = DEFAULT_OPENAI_MODEL
            elif canon_p == PROVIDER_ANTHROPIC:
                eff_model = DEFAULT_ANTHROPIC_MODEL
            elif canon_p == PROVIDER_GOOGLE:
                eff_model = DEFAULT_GEMINI_MODEL
            elif canon_p == PROVIDER_CUSTOM:
                eff_model = DEFAULT_CUSTOM_MODEL
            else:
                eff_model = "rule-engine-fallback"

        eff_consent = self.config.cloud_consent if cloud_consent is None else cloud_consent
        eff_fallback = self.config.allow_deterministic_fallback if allow_deterministic_fallback is None else allow_deterministic_fallback
        eff_mock = self.config.is_mock if is_mock is None else is_mock

        self.config = SessionAIConfig(
            provider=canon_p,
            model_id=eff_model,
            api_key=api_key,
            base_url=base_url,
            cloud_consent=eff_consent,
            allow_deterministic_fallback=eff_fallback,
            is_mock=eff_mock,
        )

        self._record_session_metadata()
        logger.info(
            "AI Provider session switched: provider=%s, model=%s, consent=%s, key=%s",
            self.config.provider,
            self.config.model_id,
            self.config.cloud_consent,
            mask_credential(self.config.api_key),
        )
        return self.get_session_metadata()

    def create_mock_cloud_model(
        self,
        provider: str,
        model_id: str,
        mock_output: Optional[ForensicInvestigationOutput] = None,
    ) -> FunctionModel:
        """Creates a mock model for clean testing of cloud providers when credentials are absent.

        Guarantees:
        - Output explicitly documents that cloud service was tested via mock.
        - Zero false claims of live cloud verification.
        """
        canon_p = normalize_provider_name(provider)

        def _mock_step_fn(messages: list, info: AgentInfo) -> Any:
            from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart

            case_id = "test-case"
            for msg in messages:
                for part in getattr(msg, "parts", []):
                    if hasattr(part, "content") and isinstance(part.content, str):
                        m = re.search(r"Case Identifier:\s*([^\r\n]+)", part.content)
                        if m:
                            case_id = m.group(1).strip()

            out = mock_output or ForensicInvestigationOutput(
                case_id=case_id,
                observed_facts=[],
                rule_detections=[],
                external_labels=[],
                analyst_interpretations=[],
                conclusions=[f"Mock verification completed for {canon_p} ({model_id})."],
                uncertainty_and_limitations=[
                    f"Notice: Tested via mock adapter ({canon_p}:{model_id}) - no live cloud API called."
                ],
                metadata={
                    "is_mock": True,
                    "tested_via_mock": True,
                    "provider": canon_p,
                    "model_id": model_id,
                    "disclaimer": "Cloud service tested via mock (credentials absent; no live cloud verification claimed).",
                },
            )
            # Serialize for structured return
            return ModelResponse(parts=[TextPart(out.model_dump_json())])

        return FunctionModel(_mock_step_fn, model_name=f"mock-{canon_p}-{model_id}")

    def create_model(
        self,
        provider: Optional[str] = None,
        model_id: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        cloud_consent: Optional[bool] = None,
        is_mock: Optional[bool] = None,
        **kwargs: Any,
    ) -> Model:
        """Polymorphic factory instantiating configured Model with security & air-gap gating.

        Rules:
        1. Default: local Ollama.
        2. Strictly NO automatic fallback to cloud.
        3. Cloud providers (OpenAI, Anthropic, Google) REQUIRE cloud_consent=True and valid credentials.
        4. Mock testing: if is_mock=True, creates a clean mock model with transparent disclaimers.
        5. Deterministic fallback: returns FunctionModel clearly labeled as rule-based fallback.
        """
        canon_p = normalize_provider_name(provider or self.config.provider)
        eff_model_id = model_id or self.config.model_id
        eff_consent = self.config.cloud_consent if cloud_consent is None else cloud_consent
        eff_is_mock = self.config.is_mock if is_mock is None else is_mock
        eff_base_url = base_url or self.config.base_url

        # Check mock testing mode first
        if eff_is_mock:
            self._record_session_metadata(tested_via_mock=True)
            logger.info("Instantiating clean mock model for %s (%s)", canon_p, eff_model_id)
            return self.create_mock_cloud_model(canon_p, eff_model_id)

        # ----------------------------------------------------------------------
        # 1. Local Ollama (Default, dynamic models, not locked to qwen3:8b)
        # ----------------------------------------------------------------------
        if canon_p == PROVIDER_OLLAMA:
            resolved_url = resolve_ollama_base_url(eff_base_url)
            self._record_session_metadata(is_fallback=False)
            logger.info("Initializing Ollama provider: model='%s', endpoint='%s'", eff_model_id, resolved_url)
            prov = OllamaProvider(base_url=resolved_url)
            return OllamaModel(eff_model_id, provider=prov, **kwargs)

        # ----------------------------------------------------------------------
        # 2. Cloud Providers: OpenAI, Anthropic, Google
        # ----------------------------------------------------------------------
        if canon_p in CLOUD_PROVIDERS:
            # Air-gap Gating: Explicit user session consent required
            if not eff_consent:
                raise CloudConsentRequiredError(
                    f"Air-Gap Security Gate: Cloud AI provider '{canon_p}' requested without explicit session consent. "
                    "Cloud API calls require explicit user credentials and session consent before initiating external transmission."
                )

            # Resolve credentials
            key, key_src = resolve_provider_credentials(
                canon_p,
                override_key=api_key or self.config.api_key,
                cloud_consent=eff_consent,
            )
            if not key:
                raise MissingCredentialsError(
                    f"Credential Gating Violation: Valid API key required for cloud provider '{canon_p}'. "
                    f"Please provide an explicit api_key or set the appropriate environment variable with session consent."
                )

            logger.info(
                "Initializing cloud provider '%s' (%s) with masked key: %s (source: %s)",
                canon_p,
                eff_model_id,
                mask_credential(key),
                key_src,
            )
            self._record_session_metadata(is_fallback=False)

            if canon_p == PROVIDER_OPENAI:
                prov = OpenAIProvider(api_key=key, base_url=eff_base_url) if eff_base_url else OpenAIProvider(api_key=key)
                return OpenAIChatModel(eff_model_id, provider=prov, **kwargs)

            if canon_p == PROVIDER_ANTHROPIC:
                prov = AnthropicProvider(api_key=key)
                return AnthropicModel(eff_model_id, provider=prov, **kwargs)

            if canon_p == PROVIDER_GOOGLE:
                prov = GoogleProvider(api_key=key)
                return GoogleModel(eff_model_id, provider=prov, **kwargs)

        # ----------------------------------------------------------------------
        # 3. Custom Provider (OpenAI-compatible endpoints)
        # ----------------------------------------------------------------------
        if canon_p == PROVIDER_CUSTOM:
            target_url = eff_base_url or "http://127.0.0.1:8080/v1"
            # If target URL is not a loopback address, require cloud consent
            is_loopback = any(h in target_url for h in ("127.0.0.1", "localhost", "0.0.0.0", "::1"))
            if not is_loopback and not eff_consent:
                raise CloudConsentRequiredError(
                    f"Air-Gap Security Gate: Non-local custom endpoint '{target_url}' requires explicit session consent."
                )

            key, _ = resolve_provider_credentials(canon_p, override_key=api_key or self.config.api_key, cloud_consent=eff_consent)
            effective_key = key or "custom-key"

            self._record_session_metadata(is_fallback=False)
            logger.info("Initializing custom OpenAI-compatible provider at '%s'", target_url)
            prov = OpenAICompatibleProvider("custom", base_url=target_url, api_key=effective_key)
            return OpenAIChatModel(eff_model_id, provider=prov, **kwargs)

        # ----------------------------------------------------------------------
        # 4. Deterministic Fallback Engine (FunctionModel / TestModel)
        # ----------------------------------------------------------------------
        if canon_p == PROVIDER_DETERMINISTIC_FALLBACK:
            self._record_session_metadata(
                is_fallback=True,
                fallback_reason="Explicit deterministic rule-based fallback engine selected.",
            )
            logger.info("Engaging deterministic rule-based fallback engine.")
            fn = kwargs.pop("function", None)
            if fn:
                return FunctionModel(fn, model_name="deterministic-rule-fallback", **kwargs)
            return create_offline_forensic_model(max_steps=self.config.max_tool_steps)

        raise ProviderUnavailableError(
            f"Unsupported AI provider '{canon_p}'. Supported: {sorted({PROVIDER_OLLAMA, PROVIDER_OPENAI, PROVIDER_ANTHROPIC, PROVIDER_GOOGLE, PROVIDER_CUSTOM, PROVIDER_DETERMINISTIC_FALLBACK})}"
        )

    def validate_observed_facts(
        self,
        observed_facts: List[ObservedFact],
        db: sqlite3.Connection,
    ) -> ReferenceCheckResult:
        """Executes two-stage RefChecker validation against the canonical database.

        Stage 1: existence_ref_ratio (verifies tx_hash and entities exist in SQLite).
        Stage 2: content_match_ratio (field-by-field verification of block, addresses, amounts).
        """
        if not observed_facts:
            return ReferenceCheckResult(
                is_valid=True,
                existence_ref_ratio=1.0,
                content_match_ratio=1.0,
                field_match_ratio=1.0,
                total_facts=0,
                matched_facts=0,
                total_refs_checked=0,
                existing_refs_count=0,
                mismatches=[],
                status="NOT_EVALUATED",
            )

        content_ratio, mismatches = verify_observed_facts(observed_facts, db)

        # Calculate existence ratio
        exist_count = 0
        for fact in observed_facts:
            row = db.execute(
                "SELECT 1 FROM transactions WHERE lower(tx_hash) = lower(?) UNION "
                "SELECT 1 FROM asset_transfers WHERE lower(tx_hash) = lower(?)",
                (fact.tx_hash, fact.tx_hash),
            ).fetchone()
            if row:
                exist_count += 1

        existence_ratio = exist_count / len(observed_facts) if observed_facts else 1.0
        is_valid = (content_ratio >= 1.0) and (len(mismatches) == 0) and (existence_ratio >= 1.0)
        status = "PASS" if is_valid else "CONTENT_MISMATCH"

        return ReferenceCheckResult(
            is_valid=is_valid,
            existence_ref_ratio=round(existence_ratio, 4),
            content_match_ratio=round(content_ratio, 4),
            field_match_ratio=round(content_ratio, 4),
            total_facts=len(observed_facts),
            matched_facts=len(observed_facts) - len(mismatches),
            total_refs_checked=len(observed_facts),
            existing_refs_count=exist_count,
            mismatches=mismatches,
            status=status,
        )

    def execute_investigation(
        self,
        case_context: Dict[str, Any],
        prompt: str,
        readonly_db: Optional[sqlite3.Connection] = None,
        staging_db: Optional[sqlite3.Connection] = None,
        benchmark_db: Optional[sqlite3.Connection] = None,
        strict_ref_checker: bool = False,
        **kwargs: Any,
    ) -> ForensicInvestigationOutput:
        """Executes an investigation session applying Air-Gap security and RefChecker validation.

        Pipeline:
        1. Air-Gap Data Protection: Scans prompt payload for secrets, private keys, or raw DB leaks.
        2. Security Decoupling Check: Ensures P8 ML and P9 ZKML models are unaltered.
        3. Model Instantiation: Polymorphic creation via adapter.
        4. Investigation Run: Executes bounded read-only investigation.
        5. Two-Stage RefChecker Validation: existence_ref_ratio and content_match_ratio against SQLite.
        6. Metadata Injection: provider, model_id, timestamp_utc, config_version, masked credentials.
        """
        case_id = str(case_context.get("case_id") or "forensic-case").strip()

        # Step 1: Air-Gap Payload Protection Guard
        sanitized_prompt = AirGapDataProtectionGuard.sanitize_and_audit_payload(
            prompt,
            allow_cloud_transmission=self.config.cloud_consent,
        )

        # Step 2: Decoupling verification
        verify_p8_p9_decoupling()

        # Step 3: Instantiate model
        model = self.create_model(**kwargs)

        # Step 4: Execute via ForensicInvestigator coordinator
        investigator = ForensicInvestigator(
            model=model,
            readonly_db=readonly_db,
            staging_db=staging_db,
            benchmark_db=benchmark_db,
            enable_threat_intel=benchmark_db is not None,
            strict_ref_checker=strict_ref_checker,
        )

        inv_result = investigator.investigate(
            case_id=case_id,
            query=sanitized_prompt,
            readonly_db=readonly_db,
            staging_db=staging_db,
            benchmark_db=benchmark_db,
        )

        output = inv_result.output

        # Step 5: Independent Two-Stage RefChecker
        if readonly_db is not None:
            ref_result = self.validate_observed_facts(output.observed_facts, readonly_db)
            output.metadata["ref_checker"] = {
                "status": ref_result.status,
                "existence_ref_ratio": ref_result.existence_ref_ratio,
                "content_match_ratio": ref_result.content_match_ratio,
                "total_facts": ref_result.total_facts,
                "mismatch_count": len(ref_result.mismatches),
            }

        # Step 6: Inject complete session metadata
        meta = self.get_session_metadata()
        output.metadata.update(meta)

        return output
