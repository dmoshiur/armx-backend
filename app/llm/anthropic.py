# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""Anthropic (Claude) messages API adapter."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

import httpx

from app.core.logging import get_logger
from app.llm.base import LLMError, LLMMessage, LLMProvider, LLMReply, LLMToolCall, LLMUnavailable

__all__ = ["AnthropicProvider"]

logger = get_logger("llm.anthropic")


class AnthropicProvider(LLMProvider):
    """Messages API provider with tool use."""

    name = "anthropic"

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        base_url: str = "https://api.anthropic.com/v1",
        timeout: float = 45.0,
        max_tokens: int = 1024,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.model = model
        self._max_tokens = max_tokens
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=httpx.Timeout(timeout, connect=min(10.0, timeout)),
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
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
        system_parts = [message.content for message in messages if message.role == "system"]
        conversation: list[dict[str, Any]] = []
        for message in messages:
            if message.role == "system":
                continue
            if message.role == "tool":
                conversation.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": message.tool_call_id or "",
                                "content": message.content,
                            }
                        ],
                    }
                )
            elif message.role == "assistant" and message.tool_calls:
                blocks: list[dict[str, Any]] = []
                if message.content:
                    blocks.append({"type": "text", "text": message.content})
                for call in message.tool_calls:
                    function = call.get("function") or {}
                    try:
                        arguments = json.loads(function.get("arguments") or "{}")
                    except (json.JSONDecodeError, TypeError):
                        arguments = {}
                    blocks.append(
                        {
                            "type": "tool_use",
                            "id": str(call.get("id") or "tool_use"),
                            "name": str(function.get("name") or ""),
                            "input": arguments if isinstance(arguments, dict) else {},
                        }
                    )
                conversation.append({"role": "assistant", "content": blocks})
            else:
                conversation.append({"role": message.role, "content": message.content})

        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens or self._max_tokens,
            "messages": conversation,
        }
        if system_parts:
            payload["system"] = "\n\n".join(system_parts)
        if temperature is not None:
            payload["temperature"] = temperature
        if tools:
            payload["tools"] = [
                {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "input_schema": tool.get("parameters", {"type": "object"}),
                }
                for tool in tools
            ]

        try:
            response = await self._client.post("/messages", json=payload)
        except httpx.TimeoutException as exc:
            raise LLMUnavailable("The model provider timed out") from exc
        except httpx.HTTPError as exc:
            logger.warning("provider transport error: %s", type(exc).__name__)
            raise LLMUnavailable() from exc

        if response.status_code == 429 or response.status_code >= 500:
            raise LLMUnavailable()
        if response.status_code >= 400:
            logger.warning("provider rejected the request with status %s", response.status_code)
            raise LLMError("The model provider rejected the request")

        try:
            body = response.json()
            blocks = body["content"]
        except (ValueError, KeyError, TypeError) as exc:
            raise LLMUnavailable("The model provider returned an unexpected response") from exc

        text_parts: list[str] = []
        tool_calls: list[LLMToolCall] = []
        for block in blocks:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text":
                text_parts.append(str(block.get("text") or ""))
            elif block.get("type") == "tool_use":
                arguments = block.get("input")
                tool_calls.append(
                    LLMToolCall(
                        id=str(block.get("id") or "tool_use"),
                        name=str(block.get("name") or ""),
                        arguments=arguments if isinstance(arguments, dict) else {},
                    )
                )

        return LLMReply(
            text="".join(text_parts),
            tool_calls=tool_calls,
            finish_reason=str(body.get("stop_reason") or "stop"),
            usage={
                "prompt_tokens": int((body.get("usage") or {}).get("input_tokens") or 0),
                "completion_tokens": int((body.get("usage") or {}).get("output_tokens") or 0),
            },
        )

    async def aclose(self) -> None:
        await self._client.aclose()
