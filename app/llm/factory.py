# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Provider selection.

``LLM_PROVIDER=mock`` is the default, so a fresh checkout answers without a key. Every other
value is validated at startup (the settings validator refuses to boot when, for example,
``LLM_PROVIDER=openai`` is set without ``OPENAI_API_KEY``), which means a misconfigured deployment
fails immediately rather than on the user's first request.
"""

from __future__ import annotations

import httpx

from app.config import Settings
from app.core.logging import get_logger
from app.llm.anthropic import AnthropicProvider
from app.llm.base import LLMProvider
from app.llm.mock import MockLLMProvider
from app.llm.ollama import OllamaProvider
from app.llm.openai_compatible import OpenAICompatibleProvider

__all__ = ["build_provider", "provider_label"]

logger = get_logger("llm")


def build_provider(
    settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None
) -> LLMProvider:
    """
    Build the configured provider.

    ``transport`` exists so tests can inject a mocked HTTP layer; it is never set from user input.
    """
    provider = settings.llm_provider

    if provider == "mock":
        return MockLLMProvider()

    if provider == "openai":
        return OpenAICompatibleProvider(
            api_key=_secret(settings.openai_api_key),
            model=settings.openai_model,
            base_url=settings.openai_base_url,
            timeout=settings.llm_timeout_seconds,
            name="openai",
            transport=transport,
        )

    if provider == "anthropic":
        return AnthropicProvider(
            api_key=_secret(settings.anthropic_api_key),
            model=settings.anthropic_model,
            base_url=settings.anthropic_base_url,
            timeout=settings.llm_timeout_seconds,
            max_tokens=settings.llm_max_tokens,
            transport=transport,
        )

    if provider == "ollama":
        return OllamaProvider(
            model=settings.ollama_model,
            base_url=settings.ollama_base_url,
            timeout=settings.llm_timeout_seconds,
            transport=transport,
        )

    return OpenAICompatibleProvider(
        api_key=_secret(settings.openai_compatible_api_key),
        model=settings.openai_compatible_model,
        base_url=settings.openai_compatible_base_url,
        timeout=settings.llm_timeout_seconds,
        name="openai_compatible",
        transport=transport,
    )


def provider_label(settings: Settings) -> str:
    """Human-readable provider description for the health and admin surfaces (never a key)."""
    return {
        "mock": "mock planner (offline)",
        "openai": f"openai:{settings.openai_model}",
        "anthropic": f"anthropic:{settings.anthropic_model}",
        "ollama": f"ollama:{settings.ollama_model}",
        "openai_compatible": f"openai_compatible:{settings.openai_compatible_model}",
    }.get(settings.llm_provider, settings.llm_provider)


def _secret(value: object) -> str:
    if value is None:
        return ""
    getter = getattr(value, "get_secret_value", None)
    if callable(getter):
        return str(getter())
    return str(value)
