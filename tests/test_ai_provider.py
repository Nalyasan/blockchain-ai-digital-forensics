"""Test Suite for P5 AI Investigator Gemini Provider.

Verifies:
- Configurable environment settings (AI_PROVIDER, AI_MODEL, MAX_AI_TOOL_STEPS, AI_REQUEST_LIMIT)
- Secure credential resolution and masking (precedence, zero raw leaks)
- GoogleModel & GoogleProvider integration with gemini-3.8-flash
- Deterministic offline fallback to TestModel and FunctionModel
- Bounded inference requests via UsageLimits (AI_REQUEST_LIMIT = 8)
- G5-02 invariant: zero forbidden mutating statements
"""

import ast
import os
from pathlib import Path
import pytest
from pydantic import BaseModel
from pydantic_ai import Agent, UsageLimits
from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.messages import ModelMessage, ModelResponse, TextPart
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.models.google import GoogleModel
from pydantic_ai.models.test import TestModel

import forensics.ai.provider as provider
from forensics.ai.provider import (
    AIConfig,
    InvalidProviderError,
    MissingAPIKeyError,
    create_function_model,
    create_gemini_model,
    create_gemini_provider,
    create_model,
    create_test_model,
    get_ai_config,
    get_usage_limits,
    mask_api_key,
    resolve_api_key,
)


class TestProviderSecurityAndCredentials:
    """Credential resolution and masking tests."""

    def test_resolve_api_key_explicit_override(self, monkeypatch):
        monkeypatch.setenv("GOOGLE_API_KEY", "env_google_key")
        monkeypatch.setenv("GEMINI_API_KEY", "env_gemini_key")
        key, src = resolve_api_key("explicit_key_123")
        assert key == "explicit_key_123"
        assert src == "explicit"

    def test_resolve_api_key_google_precedence(self, monkeypatch):
        monkeypatch.setenv("GOOGLE_API_KEY", "google_val_123")
        monkeypatch.setenv("GEMINI_API_KEY", "gemini_val_123")
        key, src = resolve_api_key()
        assert key == "google_val_123"
        assert src == "GOOGLE_API_KEY"

    def test_resolve_api_key_gemini_fallback(self, monkeypatch):
        monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
        monkeypatch.setenv("GEMINI_API_KEY", "gemini_val_123")
        key, src = resolve_api_key()
        assert key == "gemini_val_123"
        assert src == "GEMINI_API_KEY"

    def test_resolve_api_key_none_when_empty(self, monkeypatch):
        monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        key, src = resolve_api_key()
        assert key is None
        assert src == "none"

    def test_mask_api_key_redaction(self):
        assert mask_api_key(None) == "[ABSENT]"
        assert mask_api_key("") == "[ABSENT]"
        assert mask_api_key("   ") == "[ABSENT]"
        assert mask_api_key("12345") == "***"
        assert mask_api_key("12345678") == "***"
        assert mask_api_key("AIzaSyDummySecretKey123456") == "AIza...3456"

    def test_safe_summary_does_not_leak_raw_key(self, monkeypatch):
        secret = "AIzaSySuperSecretKey9988776655"
        monkeypatch.setenv("GOOGLE_API_KEY", secret)
        cfg = AIConfig()
        summary = cfg.safe_summary()
        summary_str = str(summary)
        assert secret not in summary_str
        assert summary["api_key_configured"] is True
        assert summary["api_key_masked"] == "AIza...6655"
        assert summary["api_key_source"] == "GOOGLE_API_KEY"


class TestAIConfigValidation:
    """Config schema and validation tests."""

    def test_default_config_values(self, monkeypatch):
        monkeypatch.delenv("AI_PROVIDER", raising=False)
        monkeypatch.delenv("AI_MODEL", raising=False)
        monkeypatch.delenv("MAX_AI_TOOL_STEPS", raising=False)
        monkeypatch.delenv("AI_REQUEST_LIMIT", raising=False)
        monkeypatch.delenv("AI_OFFLINE_FALLBACK", raising=False)

        cfg = AIConfig()
        assert cfg.provider == "gemini"
        assert cfg.model_name == "gemini-3.8-flash"
        assert cfg.max_tool_steps == 5
        assert cfg.request_limit == 8
        assert cfg.allow_offline_fallback is True

    def test_env_overrides(self, monkeypatch):
        monkeypatch.setenv("AI_PROVIDER", "test")
        monkeypatch.setenv("AI_MODEL", "gemini-2.5-flash")
        monkeypatch.setenv("MAX_AI_TOOL_STEPS", "4")
        monkeypatch.setenv("AI_REQUEST_LIMIT", "10")
        monkeypatch.setenv("AI_OFFLINE_FALLBACK", "false")

        cfg = AIConfig()
        assert cfg.provider == "test"
        assert cfg.model_name == "gemini-2.5-flash"
        assert cfg.max_tool_steps == 4
        assert cfg.request_limit == 10
        assert cfg.allow_offline_fallback is False

    def test_bounds_validation(self):
        with pytest.raises(ValueError):
            AIConfig(max_tool_steps=0)
        with pytest.raises(ValueError):
            AIConfig(request_limit=0)


class TestUsageLimits:
    """Inference bounds tests (AI_REQUEST_LIMIT = 8)."""

    def test_default_usage_limits(self):
        limits = get_usage_limits()
        assert isinstance(limits, UsageLimits)
        assert limits.request_limit == 8

    def test_custom_usage_limits_from_config(self):
        cfg = AIConfig(request_limit=12)
        limits = get_usage_limits(config=cfg)
        assert limits.request_limit == 12

    def test_explicit_override_usage_limits(self):
        cfg = AIConfig(request_limit=12)
        limits = get_usage_limits(config=cfg, request_limit=3)
        assert limits.request_limit == 3

    def test_usage_limits_enforced_by_agent(self):
        os.environ["PYDANTIC_AI_NO_BANNER"] = "1"
        model = create_test_model(call_tools=["step1", "step2"])
        agent = Agent(model)

        @agent.tool_plain
        def step1() -> str:
            return "ok1"

        @agent.tool_plain
        def step2() -> str:
            return "ok2"

        limits = UsageLimits(request_limit=1)
        with pytest.raises(UsageLimitExceeded):
            agent.run_sync("test run", usage_limits=limits)


class TestModelFactories:
    """Model factory and offline fallback tests."""

    def test_create_gemini_model_with_key(self):
        dummy_key = "AIzaSyDummyKeyForLiveModelTests123456"
        model = create_gemini_model(model_name="gemini-3.8-flash", api_key=dummy_key)
        assert isinstance(model, GoogleModel)
        assert model.model_name == "gemini-3.8-flash"

    def test_create_gemini_provider_missing_key_raises(self, monkeypatch):
        monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        with pytest.raises(MissingAPIKeyError, match="Gemini API key is required"):
            create_gemini_provider()

    def test_create_model_fallback_to_test_model_when_key_absent(self, monkeypatch):
        monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        cfg = AIConfig(provider="gemini", allow_offline_fallback=True)
        model = create_model(config=cfg)
        assert isinstance(model, TestModel)

    def test_create_model_strict_mode_raises_when_key_absent(self, monkeypatch):
        monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        cfg = AIConfig(provider="gemini", allow_offline_fallback=False)
        with pytest.raises(MissingAPIKeyError, match="offline fallback is disabled"):
            create_model(config=cfg)

    def test_create_test_model_explicit(self):
        model = create_test_model(call_tools=["tool_a"], seed=42)
        assert isinstance(model, TestModel)

    def test_create_function_model_explicit(self):
        def mock_fn(msgs: list[ModelMessage], info) -> ModelResponse:
            return ModelResponse(parts=[TextPart(content="custom mock")])

        model = create_function_model(function=mock_fn)
        assert isinstance(model, FunctionModel)

    def test_create_model_invalid_provider_raises(self):
        cfg = AIConfig(provider="unsupported_ai")
        with pytest.raises(InvalidProviderError, match="Unsupported AI provider"):
            create_model(config=cfg)


class TestAgentExecutionIntegration:
    """End-to-end integration tests using deterministic TestModel."""

    class InvestigationReport(BaseModel):
        case_id: str
        findings: list[str]

    def test_agent_structured_output_with_test_model(self):
        os.environ["PYDANTIC_AI_NO_BANNER"] = "1"
        model = create_test_model(
            custom_output_args={
                "case_id": "euler_incident",
                "findings": ["Flash loan liquidation flaw detected"],
            }
        )
        agent = Agent(model, output_type=self.InvestigationReport)
        res = agent.run_sync("Analyze case")
        assert isinstance(res.output, self.InvestigationReport)
        assert res.output.case_id == "euler_incident"
        assert len(res.output.findings) == 1

    def test_agent_with_function_model(self):
        os.environ["PYDANTIC_AI_NO_BANNER"] = "1"

        def mock_callback(msgs: list[ModelMessage], info) -> ModelResponse:
            return ModelResponse(parts=[TextPart(content="Deterministic analysis complete.")])

        model = create_function_model(function=mock_callback)
        agent = Agent(model)
        res = agent.run_sync("Run forensic scan")
        assert "Deterministic analysis complete." in res.output


class TestForensicInvariants:
    """Verification of invariant rules (G5-02)."""

    def test_zero_insert_or_replace_invariant(self):
        code_path = Path("forensics/ai/provider.py")
        content = code_path.read_text(encoding="utf-8").upper()
        assert "INSERT OR REPLACE" not in content, "Forbidden 'INSERT OR REPLACE' found"
        assert "REPLACE INTO" not in content, "Forbidden 'REPLACE INTO' found"
        assert "INSERT OR IGNORE" not in content, "Forbidden 'INSERT OR IGNORE' found"

    def test_ast_validity(self):
        code_path = Path("forensics/ai/provider.py")
        tree = ast.parse(code_path.read_text(encoding="utf-8"), filename="provider.py")
        assert isinstance(tree, ast.Module)
