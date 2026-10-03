# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""LLM router: selects the configured provider adapter and normalizes its output.

``LLM_PROVIDER=ashna`` (default) routes to Ashna AI's hosted ``ashna-x1`` model via
:mod:`app.chat.providers.ashna_adapter`; ``ollama`` and ``openai_compatible`` remain
available for local development and offline fallback. Every provider returns the same
normalized :class:`LLMResult` shape, so the chat pipeline and WS events are unaffected
by provider selection.
"""

import asyncio
import logging
from typing import Any

import httpx

from app.chat.llm_core import (  # noqa: F401  (re-exported for router call sites/tests)
    _SYSTEM_PROMPT,
    LLMResult,
    LLMToolCall,
    LLMUnavailable,
    _content,
    _parse_arguments,
    _tool_calls,
)
from app.chat.providers.ashna_adapter import AshnaAdapter
from app.config import Settings

__all__ = [
    "LLMResult",
    "LLMToolCall",
    "LLMUnavailable",
    "_SYSTEM_PROMPT",
    "_content",
    "_parse_arguments",
    "_tool_calls",
    "complete",
]

logger = logging.getLogger("armx.chat.llm")


async def complete(
    settings: Settings,
    *,
    user_text: str,
    tools: list[dict[str, Any]],
) -> LLMResult:
    if settings.llm_provider == "ashna":
        return await AshnaAdapter(settings).complete(user_text=user_text, tools=tools)

    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": user_text},
    ]
    timeout = httpx.Timeout(settings.llm_timeout_seconds)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            if settings.llm_provider == "ollama":
                response = await client.post(
                    f"{settings.ollama_base_url.rstrip('/')}/api/chat",
                    json={
                        "model": settings.ollama_model,
                        "messages": messages,
                        "tools": tools or None,
                        "stream": False,
                    },
                )
                response.raise_for_status()
                payload = response.json()
                message = payload.get("message", {}) if isinstance(payload, dict) else {}
                if not isinstance(message, dict):
                    raise LLMUnavailable
                return LLMResult(
                    text=_content(message.get("content")),
                    tool_calls=_tool_calls(message.get("tool_calls")),
                    finish_reason="tool_calls" if message.get("tool_calls") else "stop",
                )

            if settings.llm_provider == "groq":
                base_url = settings.groq_base_url.rstrip("/")
                api_key = settings.groq_api_key
                model = settings.groq_model
            else:
                base_url = (settings.openai_compatible_base_url or "").rstrip("/")
                api_key = settings.openai_compatible_api_key
                model = settings.openai_compatible_model
            headers: dict[str, str] = {}
            if api_key is not None:
                headers["Authorization"] = f"Bearer {api_key.get_secret_value()}"
            request_body: dict[str, Any] = {
                "model": model,
                "messages": messages,
                "stream": False,
            }
            if tools:
                request_body["tools"] = tools
                request_body["tool_choice"] = "auto"
            response = await client.post(
                f"{base_url}/chat/completions",
                json=request_body,
                headers=headers,
            )
            response.raise_for_status()
            payload = response.json()
            choices = payload.get("choices", []) if isinstance(payload, dict) else []
            if not choices or not isinstance(choices[0], dict):
                raise LLMUnavailable
            choice = choices[0]
            message = choice.get("message", {})
            if not isinstance(message, dict):
                raise LLMUnavailable
            calls = _tool_calls(message.get("tool_calls"))
            return LLMResult(
                text=_content(message.get("content")),
                tool_calls=calls,
                finish_reason="tool_calls"
                if calls
                else str(choice.get("finish_reason", "stop"))[:32],
            )
    except asyncio.CancelledError:
        raise
    except (httpx.HTTPError, ValueError, KeyError, TypeError, LLMUnavailable):
        logger.warning("LLM provider request failed; prompt and credentials omitted")
        raise LLMUnavailable from None
