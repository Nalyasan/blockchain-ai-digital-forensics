"""P5 AI Investigator Gemini Provider & Offline Fallbacks.

This module provides the core model and provider orchestration layer for the
P5 AI Investigator forensics engine, built on Pydantic AI and Google Gemini Flash.

Security & Architecture Guarantees:
1. Official Gemini Integration:
   Uses Pydantic AI `GoogleModel` backed by `GoogleProvider` for the `gemini-3.8-flash` model.
2. Configurable Environment Settings:
   - `AI_PROVIDER`: "gemini" (default), "google", "test", or "function"
   - `AI_MODEL`: "gemini-3.8-flash" (default)
   - `MAX_AI_TOOL_STEPS`: Maximum tool execution steps (default: 5)
   - `AI_REQUEST_LIMIT`: Maximum model inference requests (default: 8)
   - `AI_OFFLINE_FALLBACK`: Enable deterministic offline TestModel fallback when API keys are absent (default: true)
3. Zero Hardcoded Credentials & Safe Masking:
   Resolves `GOOGLE_API_KEY` first, then falls back to `GEMINI_API_KEY`.
   Credentials are never logged, printed, or exposed in error messages. Safe redaction helper
   `mask_api_key` exposes only first 4 and last 4 characters.
4. Deterministic Offline Fallbacks:
   When credentials are missing or `AI_PROVIDER=test`, seamlessly instantiates Pydantic AI `TestModel`.
   Also supports `FunctionModel` for deterministic callback-driven mock responses.
5. Bounded Inference Requests:
   Provides `get_usage_limits()` enforcing `AI_REQUEST_LIMIT = 8` via Pydantic AI `UsageLimits`.
6. Forensic Invariant Compliance:
   Contains strictly zero state-mutating SQL operations.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Callable, Dict, List, Literal, Optional, Tuple, Union

os.environ.setdefault("PYDANTIC_AI_NO_BANNER", "1")

from pydantic import BaseModel, Field, field_validator
from pydantic_ai import UsageLimits
from pydantic_ai.models import Model
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.models.google import GoogleModel
from pydantic_ai.models.test import TestModel
from pydantic_ai.providers.google import GoogleProvider

try:
    from pydantic_ai.models.openai import OpenAIChatModel
    from pydantic_ai.providers.openai import OpenAIProvider
    from pydantic_ai.providers.openai_compatible import OpenAICompatibleProvider
except ImportError:
    OpenAIChatModel = None  # type: ignore[assignment, misc]
    OpenAIProvider = None  # type: ignore[assignment, misc]
    OpenAICompatibleProvider = None  # type: ignore[assignment, misc]

try:
    from pydantic_ai.models.anthropic import AnthropicModel
    from pydantic_ai.providers.anthropic import AnthropicProvider
except ImportError:
    AnthropicModel = None  # type: ignore[assignment, misc]
    AnthropicProvider = None  # type: ignore[assignment, misc]

try:
    from pydantic_ai.models.ollama import OllamaModel
    from pydantic_ai.providers.ollama import OllamaProvider
except ImportError:
    OllamaModel = None  # type: ignore[assignment, misc]
    OllamaProvider = None  # type: ignore[assignment, misc]

OpenAIModel = OpenAIChatModel

logger = logging.getLogger("forensics.ai.provider")

__all__ = [
    "AIConfig",
    "DEFAULT_MAX_TOOL_STEPS",
    "DEFAULT_MODEL",
    "DEFAULT_OFFLINE_FALLBACK",
    "DEFAULT_PROVIDER",
    "DEFAULT_REQUEST_LIMIT",
    "InvalidConfigurationError",
    "InvalidProviderError",
    "MissingAPIKeyError",
    "ProviderError",
    "create_function_model",
    "create_gemini_model",
    "create_gemini_provider",
    "create_anthropic_model",
    "create_anthropic_provider",
    "create_model",
    "create_ollama_model",
    "create_ollama_provider",
    "create_openai_model",
    "create_openai_provider",
    "create_test_model",
    "get_ai_config",
    "get_usage_limits",
    "mask_api_key",
    "resolve_api_key",
    "resolve_ollama_base_url",
]

DEFAULT_PROVIDER: str = "gemini"
DEFAULT_MODEL: str = "gemini-3.8-flash"
DEFAULT_MAX_TOOL_STEPS: int = 5
DEFAULT_REQUEST_LIMIT: int = 8
DEFAULT_OFFLINE_FALLBACK: bool = True


class ProviderError(Exception):
    """Base exception for forensics AI provider errors."""


class MissingAPIKeyError(ProviderError):
    """Raised when an API key is required but missing from environment and parameters."""


class InvalidProviderError(ProviderError):
    """Raised when an unrecognized AI provider name is configured."""


class InvalidConfigurationError(ProviderError):
    """Raised when provider configuration parameters fail validation."""


# Credential Security & Redaction


def resolve_api_key(override_key: Optional[str] = None) -> Tuple[Optional[str], str]:
    """Resolves the Gemini API key from explicit parameter or environment variables.

    Precedence order:
    1. override_key parameter (if provided and non-empty)
    2. GOOGLE_API_KEY environment variable
    3. GEMINI_API_KEY environment variable

    Returns:
        Tuple of (resolved_api_key, source_identifier).
        source_identifier is one of: 'explicit', 'GOOGLE_API_KEY', 'GEMINI_API_KEY', 'none'.
    """
    if override_key and override_key.strip():
        return override_key.strip(), "explicit"

    google_key = os.getenv("GOOGLE_API_KEY")
    if google_key and google_key.strip():
        return google_key.strip(), "GOOGLE_API_KEY"

    gemini_key = os.getenv("GEMINI_API_KEY")
    if gemini_key and gemini_key.strip():
        return gemini_key.strip(), "GEMINI_API_KEY"

    return None, "none"


def mask_api_key(key: Optional[str]) -> str:
    """Safely masks an API key for logs and audit reports without revealing credentials.

    Examples:
        - None or empty -> "[ABSENT]"
        - "AIza123" (short) -> "***"
        - "AIzaSySecretKey12345678" -> "AIza...5678"
    """
    if not key or not key.strip():
        return "[ABSENT]"
    cleaned = key.strip()
    if len(cleaned) <= 8:
        return "***"
    return f"{cleaned[:4]}...{cleaned[-4:]}"


def resolve_ollama_base_url(override_url: Optional[str] = None) -> str:
    """Resolves the Ollama API base URL with standard fallback order.

    Precedence order:
    1. override_url parameter (if non-empty)
    2. OLLAMA_BASE_URL environment variable
    3. OLLAMA_HOST environment variable (auto-formatted with http:// and /v1)
    4. Default: http://127.0.0.1:11434/v1
    """
    if override_url and override_url.strip():
        raw = override_url.strip()
    elif os.getenv("OLLAMA_BASE_URL") and os.getenv("OLLAMA_BASE_URL", "").strip():
        raw = os.getenv("OLLAMA_BASE_URL", "").strip()
    elif os.getenv("OLLAMA_HOST") and os.getenv("OLLAMA_HOST", "").strip():
        raw = os.getenv("OLLAMA_HOST", "").strip()
    else:
        raw = "127.0.0.1:11434"

    if not raw.startswith(("http://", "https://")):
        raw = f"http://{raw}"
    if not raw.endswith("/v1"):
        raw = f"{raw.rstrip('/')}/v1"
    return raw


# Configuration Schema


def _env_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("true", "1", "yes", "on")


def _env_int(name: str, default: int) -> int:
    val = os.getenv(name)
    if val is None:
        return default
    try:
        return int(val.strip())
    except ValueError:
        return default


class AIConfig(BaseModel):
    """Forensics AI Provider Configuration Model.

    Reads environment defaults dynamically while allowing full programmatic overrides.
    """

    provider: str = Field(
        default_factory=lambda: os.getenv("AI_PROVIDER", DEFAULT_PROVIDER).strip().lower()
    )
    model_name: str = Field(
        default_factory=lambda: os.getenv("AI_MODEL", DEFAULT_MODEL).strip()
    )
    max_tool_steps: int = Field(
        default_factory=lambda: _env_int("MAX_AI_TOOL_STEPS", DEFAULT_MAX_TOOL_STEPS)
    )
    request_limit: int = Field(
        default_factory=lambda: _env_int("AI_REQUEST_LIMIT", DEFAULT_REQUEST_LIMIT)
    )
    allow_offline_fallback: bool = Field(
        default_factory=lambda: _env_bool("AI_OFFLINE_FALLBACK", DEFAULT_OFFLINE_FALLBACK)
    )
    test_seed: int = 0
    custom_output_text: Optional[str] = None
    custom_output_args: Any = None
    call_tools: Union[List[str], Literal["all"]] = "all"

    @field_validator("max_tool_steps")
    @classmethod
    def validate_max_tool_steps(cls, v: int) -> int:
        if v < 1:
            raise ValueError(f"max_tool_steps must be >= 1, got {v}")
        return v

    @field_validator("request_limit")
    @classmethod
    def validate_request_limit(cls, v: int) -> int:
        if v < 1:
            raise ValueError(f"request_limit must be >= 1, got {v}")
        return v

    def safe_summary(self) -> Dict[str, Any]:
        """Returns non-sensitive configuration dictionary for logs and reports."""
        api_key, key_src = resolve_api_key()
        summary: Dict[str, Any] = {
            "provider": self.provider,
            "model_name": self.model_name,
            "max_tool_steps": self.max_tool_steps,
            "request_limit": self.request_limit,
            "allow_offline_fallback": self.allow_offline_fallback,
            "api_key_configured": api_key is not None,
            "api_key_source": key_src,
            "api_key_masked": mask_api_key(api_key),
        }
        if self.provider.strip().lower() in ("ollama", "local", "local_ollama"):
            summary["ollama_base_url"] = resolve_ollama_base_url()
        return summary


def get_ai_config(**overrides: Any) -> AIConfig:
    """Helper to instantiate or override an AIConfig instance."""
    return AIConfig(**overrides)


def get_usage_limits(
    config: Optional[AIConfig] = None,
    request_limit: Optional[int] = None,
) -> UsageLimits:
    """Builds bounded Pydantic AI UsageLimits instance enforcing AI_REQUEST_LIMIT.

    Args:
        config: Optional AIConfig instance. If omitted, uses default config.
        request_limit: Optional explicit request limit override.

    Returns:
        UsageLimits with request_limit set (default 8).
    """
    effective_limit = request_limit
    if effective_limit is None:
        cfg = config or AIConfig()
        effective_limit = cfg.request_limit
    return UsageLimits(request_limit=effective_limit)


# Model & Provider Factories


def create_gemini_provider(
    api_key: Optional[str] = None,
    **kwargs: Any,
) -> GoogleProvider:
    """Creates an authenticated GoogleProvider for Google Gemini API.

    Args:
        api_key: Optional explicit API key. If omitted, resolves from environment.
        **kwargs: Extra parameters passed to GoogleProvider (e.g. http_client, retry_options).

    Raises:
        MissingAPIKeyError: If neither parameter nor environment contains a valid API key.
    """
    key, src = resolve_api_key(api_key)
    if not key:
        raise MissingAPIKeyError(
            "Gemini API key is required. Set GOOGLE_API_KEY or GEMINI_API_KEY in environment."
        )
    logger.debug("Instantiating GoogleProvider using credential source: %s", src)
    return GoogleProvider(api_key=key, **kwargs)


def create_gemini_model(
    model_name: Optional[str] = None,
    api_key: Optional[str] = None,
    **kwargs: Any,
) -> GoogleModel:
    """Creates a GoogleModel targeting Google Gemini Flash (default: gemini-3.8-flash).

    Args:
        model_name: Model identifier (defaults to gemini-3.8-flash).
        api_key: Optional explicit API key.
        **kwargs: Extra parameters passed to GoogleModel.
    """
    name = model_name or DEFAULT_MODEL
    provider = create_gemini_provider(api_key=api_key)
    return GoogleModel(name, provider=provider, **kwargs)


def create_test_model(
    call_tools: Union[List[str], Literal["all"]] = "all",
    custom_output_text: Optional[str] = None,
    custom_output_args: Any = None,
    seed: int = 0,
    model_name: str = "test",
    **kwargs: Any,
) -> TestModel:
    """Creates a deterministic TestModel for offline testing and verification.

    Args:
        call_tools: List of tool names to call, or 'all'.
        custom_output_text: Optional mock text response.
        custom_output_args: Optional mock structured response argument.
        seed: Deterministic random seed.
        model_name: Label for test model.
        **kwargs: Extra parameters passed to TestModel.
    """
    return TestModel(
        call_tools=call_tools,
        custom_output_text=custom_output_text,
        custom_output_args=custom_output_args,
        seed=seed,
        model_name=model_name,
        **kwargs,
    )


def create_function_model(
    function: Optional[Callable[..., Any]] = None,
    model_name: Optional[str] = None,
    **kwargs: Any,
) -> FunctionModel:
    """Creates a FunctionModel for callback-driven deterministic testing.

    Args:
        function: Callable receiving (messages, info) and returning ModelResponse.
        model_name: Label for function model.
        **kwargs: Extra parameters passed to FunctionModel.
    """
    return FunctionModel(function=function, model_name=model_name, **kwargs)


def create_ollama_provider(
    base_url: Optional[str] = None,
    **kwargs: Any,
) -> Any:
    """Creates an authenticated/configured OllamaProvider for local or remote Ollama.

    Args:
        base_url: Optional explicit base URL (e.g. http://192.168.99.1:11434/v1).
        **kwargs: Extra parameters passed to OllamaProvider.
    """
    if OllamaProvider is None:
        raise InvalidProviderError("pydantic_ai.providers.ollama.OllamaProvider is not available.")
    effective_url = resolve_ollama_base_url(base_url)
    logger.debug("Instantiating OllamaProvider with base_url: %s", effective_url)
    return OllamaProvider(base_url=effective_url, **kwargs)


def create_ollama_model(
    model_name: Optional[str] = None,
    base_url: Optional[str] = None,
    **kwargs: Any,
) -> Any:
    """Creates an OllamaModel targeting a local or remote Ollama instance (default: qwen3:8b).

    Args:
        model_name: Model identifier (defaults to qwen3:8b).
        base_url: Optional explicit base URL.
        **kwargs: Extra parameters passed to OllamaModel.
    """
    if OllamaModel is None:
        raise InvalidProviderError("pydantic_ai.models.ollama.OllamaModel is not available.")
    name = model_name or "qwen3:8b"
    provider = create_ollama_provider(base_url=base_url)
    effective_url = resolve_ollama_base_url(base_url)
    logger.info("Initializing Ollama model '%s' via %s", name, effective_url)
    return OllamaModel(name, provider=provider, **kwargs)


def create_openai_provider(
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    **kwargs: Any,
) -> Any:
    """Creates an authenticated OpenAIProvider."""
    if OpenAIProvider is None:
        raise InvalidProviderError("pydantic_ai.providers.openai.OpenAIProvider is not available.")
    key = api_key or os.getenv("OPENAI_API_KEY")
    if not key:
        raise MissingAPIKeyError("OpenAI API key is required. Set OPENAI_API_KEY in environment or pass explicitly.")
    if base_url:
        return OpenAIProvider(api_key=key, base_url=base_url, **kwargs)
    return OpenAIProvider(api_key=key, **kwargs)


def create_openai_model(
    model_name: Optional[str] = None,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    **kwargs: Any,
) -> Any:
    """Creates an OpenAIChatModel targeting OpenAI API."""
    if OpenAIChatModel is None:
        raise InvalidProviderError("pydantic_ai.models.openai.OpenAIChatModel is not available.")
    name = model_name or "gpt-4o"
    provider = create_openai_provider(api_key=api_key, base_url=base_url)
    return OpenAIChatModel(name, provider=provider, **kwargs)


def create_anthropic_provider(
    api_key: Optional[str] = None,
    **kwargs: Any,
) -> Any:
    """Creates an authenticated AnthropicProvider."""
    if AnthropicProvider is None:
        raise InvalidProviderError("pydantic_ai.providers.anthropic.AnthropicProvider is not available.")
    key = api_key or os.getenv("ANTHROPIC_API_KEY")
    if not key:
        raise MissingAPIKeyError("Anthropic API key is required. Set ANTHROPIC_API_KEY in environment or pass explicitly.")
    return AnthropicProvider(api_key=key, **kwargs)


def create_anthropic_model(
    model_name: Optional[str] = None,
    api_key: Optional[str] = None,
    **kwargs: Any,
) -> Any:
    """Creates an AnthropicModel targeting Anthropic Claude API."""
    if AnthropicModel is None:
        raise InvalidProviderError("pydantic_ai.models.anthropic.AnthropicModel is not available.")
    name = model_name or "claude-3-5-sonnet-20241022"
    provider = create_anthropic_provider(api_key=api_key)
    return AnthropicModel(name, provider=provider, **kwargs)


def create_model(
    config: Optional[AIConfig] = None,
    override_api_key: Optional[str] = None,
    **kwargs: Any,
) -> Model:
    """Polymorphic factory instantiating the configured AI Model.

    Behavior:
    1. provider in ('gemini', 'google'):
       - If API key exists: creates GoogleModel(model_name, provider=GoogleProvider).
       - If API key missing and allow_offline_fallback=True:
         falls back to deterministic TestModel.
       - If API key missing and allow_offline_fallback=False:
         raises MissingAPIKeyError.
    2. provider == 'test':
       - creates TestModel.
    3. provider == 'function':
       - creates FunctionModel using 'function' kwarg if supplied.
    4. other:
       - raises InvalidProviderError.

    Args:
        config: AIConfig instance. If omitted, loads default config.
        override_api_key: Optional API key override.
        **kwargs: Forwarded to model constructors.

    Returns:
        An instance of Pydantic AI Model (GoogleModel, TestModel, or FunctionModel).
    """
    cfg = config or AIConfig()
    provider_name = cfg.provider.strip().lower()

    if provider_name in ("gemini", "google"):
        key, src = resolve_api_key(override_api_key)
        if key:
            logger.info(
                "Initializing Gemini model '%s' via %s (key masked: %s)",
                cfg.model_name,
                src,
                mask_api_key(key),
            )
            return create_gemini_model(
                model_name=cfg.model_name,
                api_key=key,
                **kwargs,
            )

        if cfg.allow_offline_fallback:
            logger.warning(
                "Gemini API key is absent. Gracefully falling back to deterministic TestModel."
            )
            test_kwargs = dict(kwargs)
            call_tools = test_kwargs.pop("call_tools", cfg.call_tools)
            custom_output_text = test_kwargs.pop(
                "custom_output_text", cfg.custom_output_text
            )
            custom_output_args = test_kwargs.pop(
                "custom_output_args", cfg.custom_output_args
            )
            seed = test_kwargs.pop("seed", cfg.test_seed)
            return create_test_model(
                call_tools=call_tools,
                custom_output_text=custom_output_text,
                custom_output_args=custom_output_args,
                seed=seed,
                **test_kwargs,
            )

        raise MissingAPIKeyError(
            "Gemini API key not found in GOOGLE_API_KEY or GEMINI_API_KEY, "
            "and offline fallback is disabled."
        )

    if provider_name in ("test", "offline", "none"):
        test_kwargs = dict(kwargs)
        call_tools = test_kwargs.pop("call_tools", cfg.call_tools)
        custom_output_text = test_kwargs.pop(
            "custom_output_text", cfg.custom_output_text
        )
        custom_output_args = test_kwargs.pop(
            "custom_output_args", cfg.custom_output_args
        )
        seed = test_kwargs.pop("seed", cfg.test_seed)
        return create_test_model(
            call_tools=call_tools,
            custom_output_text=custom_output_text,
            custom_output_args=custom_output_args,
            seed=seed,
            **test_kwargs,
        )

    if provider_name == "function":
        fn = kwargs.pop("function", None)
        return create_function_model(function=fn, **kwargs)

    if provider_name in ("ollama", "local", "local_ollama"):
        base_url = kwargs.pop("base_url", None)
        return create_ollama_model(model_name=cfg.model_name, base_url=base_url, **kwargs)

    if provider_name in ("openai", "chatgpt", "gpt"):
        return create_openai_model(
            model_name=cfg.model_name if cfg.model_name != DEFAULT_MODEL else "gpt-4o",
            api_key=override_api_key,
            **kwargs,
        )

    if provider_name in ("anthropic", "claude"):
        return create_anthropic_model(
            model_name=cfg.model_name if cfg.model_name != DEFAULT_MODEL else "claude-3-5-sonnet-20241022",
            api_key=override_api_key,
            **kwargs,
        )

    if provider_name in ("custom", "openai_compatible", "openai-compatible"):
        base_url = kwargs.pop("base_url", "http://127.0.0.1:8080/v1")
        return create_openai_model(
            model_name=cfg.model_name if cfg.model_name != DEFAULT_MODEL else "custom-model",
            api_key=override_api_key or "custom-key",
            base_url=base_url,
            **kwargs,
        )

    raise InvalidProviderError(
        f"Unsupported AI provider: '{cfg.provider}'. "
        f"Supported providers: 'gemini', 'google', 'ollama', 'openai', 'anthropic', 'custom', 'test', 'offline', 'none', 'function'."
    )
