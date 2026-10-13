# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
OpenAI and OpenAI-compatible chat providers.

One implementation covers three configured cases: ``LLM_PROVIDER=openai`` (the default for a real
deployment), ``LLM_PROVIDER=openai_compatible`` (vLLM, Together, Groq, a local gateway - anything
that speaks the same ``/chat/completions`` shape) and a custom ``OPENAI_BASE_URL``.

Two details matter for this system's threat model:

* Tool definitions are sent exactly as the registry declares them. There is no way for the model
  to describe a tool the server does not have, because the server is the one that lists them.
* The raw response is parsed defensively. A malformed tool call becomes a reply with no tool
  calls rather than an exception that could be mistaken for a successful action.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

import httpx

from app.core.logging import get_logger
from app.llm.base import LLMError, LLMMessage, LLMProvider, LLMReply, LLMToolCall, LLMUnavailable

__all__ = ["OpenAICompatibleProvider"]

logger = get_logger("llm.openai")


class OpenAICompatibleProvider(LLMProvider):
    """Chat-completions provider with function calling."""

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        base_url: str = "https://api.openai.com/v1",
        timeout: float = 45.0,
        name: str = "openai",
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.name = name
        self.model = model
        self._base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=httpx.Timeout(timeout, connect=min(10.0, timeout)),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            follow_redirects=False,
            transport=transport,
        )

    async def complete(
        self,
        messages: Sequence[LLMMessage],
        *,
        tools: Sequence[dict[str, Any]] = (),
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMReply:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [message.to_dict() for message in messages],
        }
        # ``to_dict`` already carries an assistant turn's ``tool_calls`` array when present.
        if temperature is not None:
            payload["temperature"] = temperature
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        if tools:
            payload["tools"] = [{"type": "function", "function": tool} for tool in tools]
            payload["tool_choice"] = "auto"

        try:
            response = await self._client.post("/chat/completions", json=payload)
        except httpx.TimeoutException as exc:
            raise LLMUnavailable("The model provider timed out") from exc
        except httpx.HTTPError as exc:
            logger.warning("provider transport error: %s", type(exc).__name__)
            raise LLMUnavailable() from exc

        if response.status_code == 429:
            raise LLMUnavailable("The model provider is rate limiting us")
        if response.status_code >= 500:
            raise LLMUnavailable()
        if response.status_code >= 400:
            # Never echo the body: it can echo the request, and the request has user text.
            logger.warning("provider rejected the request with status %s", response.status_code)
            raise LLMError("The model provider rejected the request")

        try:
            body = response.json()
            choice = body["choices"][0]
            message = choice["message"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            logger.warning("provider returned an unexpected payload")
            raise LLMUnavailable("The model provider returned an unexpected response") from exc

        tool_calls: list[LLMToolCall] = []
        for index, raw_call in enumerate(message.get("tool_calls") or []):
            function = raw_call.get("function") or {}
            name = str(function.get("name") or "").strip()
            if not name:
                continue
            try:
                parsed = json.loads(function.get("arguments") or "{}")
            except (json.JSONDecodeError, TypeError):
                parsed = {}
            tool_calls.append(
                LLMToolCall(
                    id=str(raw_call.get("id") or f"call_{index}"),
                    name=name,
                    arguments=parsed if isinstance(parsed, dict) else {},
                )
            )

        usage = body.get("usage") or {}
        return LLMReply(
            text=str(message.get("content") or ""),
            tool_calls=tool_calls,
            finish_reason=str(choice.get("finish_reason") or "stop"),
            usage={
                "prompt_tokens": int(usage.get("prompt_tokens") or 0),
                "completion_tokens": int(usage.get("completion_tokens") or 0),
            },
        )

    async def aclose(self) -> None:
        await self._client.aclose()
