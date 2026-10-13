# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Ollama adapter (local models, including the small models a Raspberry-Pi-class host can run).

Ollama exposes the same chat shape as OpenAI's ``/chat/completions`` but at ``/api/chat`` with a
slightly different request body, so it gets its own small adapter rather than a flag on the other
one. A local model is a first-class option here: the assistant keeps working with no third-party
API and no data leaving the deployment.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import httpx

from app.core.logging import get_logger
from app.llm.base import LLMMessage, LLMProvider, LLMReply, LLMToolCall, LLMUnavailable

__all__ = ["OllamaProvider"]

logger = get_logger("llm.ollama")


class OllamaProvider(LLMProvider):
    """Local chat provider."""

    name = "ollama"

    def __init__(
        self,
        *,
        model: str,
        base_url: str = "http://localhost:11434",
        timeout: float = 60.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.model = model
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=httpx.Timeout(timeout, connect=5.0),
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
        options: dict[str, Any] = {}
        if temperature is not None:
            options["temperature"] = temperature
        if max_tokens is not None:
            options["num_predict"] = max_tokens

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [message.to_dict() for message in messages],
            "stream": False,
        }
        if options:
            payload["options"] = options
        if tools:
            payload["tools"] = [{"type": "function", "function": tool} for tool in tools]

        try:
            response = await self._client.post("/api/chat", json=payload)
        except httpx.HTTPError as exc:
            logger.warning("ollama request failed: %s", type(exc).__name__)
            raise LLMUnavailable("The local model is not reachable") from exc

        if response.status_code >= 400:
            raise LLMUnavailable("The local model refused the request")

        try:
            body = response.json()
            message = body.get("message") or {}
        except (ValueError, TypeError) as exc:
            raise LLMUnavailable("The local model returned an unexpected response") from exc

        tool_calls: list[LLMToolCall] = []
        for index, raw_call in enumerate(message.get("tool_calls") or []):
            function = raw_call.get("function") or {}
            name = str(function.get("name") or "").strip()
            if not name:
                continue
            arguments = function.get("arguments")
            tool_calls.append(
                LLMToolCall(
                    id=f"call_{index}",
                    name=name,
                    arguments=arguments if isinstance(arguments, dict) else {},
                )
            )

        return LLMReply(
            text=str(message.get("content") or ""),
            tool_calls=tool_calls,
            finish_reason=str(body.get("done_reason") or ("tool_calls" if tool_calls else "stop")),
            usage={
                "prompt_tokens": int(body.get("prompt_eval_count") or 0),
                "completion_tokens": int(body.get("eval_count") or 0),
            },
        )

    async def aclose(self) -> None:
        await self._client.aclose()
