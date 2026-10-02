# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""Ashna AI (``ashna-x1``) adapter for the A.R.M.X LLM router.

Verified against the official AshnaAI API reference on 2026-10-02
(https://www.ashna.ai/api-docs):

* The hosted API is **OpenAI Chat Completions-compatible**, so this adapter reuses the
  same request/response mapping as the router's OpenAI-compatible path — pointed at
  Ashna's documented base URL (``https://api.ashna.ai/v1/api``) with Bearer auth. No
  bespoke client was written for a compatible API.
* ``POST /chat/completions`` accepts ``model``, ``messages``, optional ``tools`` /
  ``tool_choice`` (native client tool calling with ``tool_calls`` round-trips) and
  ``stream: true`` for OpenAI SSE chunks ending with ``data: [DONE]``.
* Model id for the hosted orchestration model: ``ashna-x1``.
* Errors use the OpenAI envelope ``{ "error": { "message", "type", "code", "param" } }``
  with 400/401/403/404/429/500 statuses (no numeric rate-limit quotas are published).

The API key comes only from the ``ASHNA_API_KEY`` environment variable (AGENTS.md rule 9)
and is redacted from every log line this module emits.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import httpx

from app.chat.llm_core import (
    _MAX_ASSISTANT_TEXT,
    _SYSTEM_PROMPT,
    LLMResult,
    LLMUnavailable,
    _content,
    _tool_calls,
)
from app.config import Settings

logger = logging.getLogger("armx.chat.providers.ashna")

DEFAULT_BASE_URL = "https://api.ashna.ai/v1/api"
DEFAULT_MODEL = "ashna-x1"

# Retry policy mirrors the other router paths: bounded attempts, exponential backoff,
# retry only on rate-limit / server / transport failures — never on 4xx client errors.
_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
_MAX_ATTEMPTS = 3
_STREAM_DONE_MARKER = "[DONE]"
_MAX_TOOL_CALL_DELTA_INDEX = 8


class AshnaUnavailable(LLMUnavailable):
    """Ashna AI request failed; surfaced through the router's existing LLM error path."""


@dataclass(frozen=True, slots=True)
class TokenDelta:
    """Internal token-stream shape: one piece of streamed assistant text."""

    token: str


@dataclass(frozen=True, slots=True)
class StreamResult:
    """Terminal stream event carrying the same normalized result as ``complete()``."""

    result: LLMResult


def redact_secret(secret: str, text: str) -> str:
    """Remove any occurrence of a credential from text destined for logs (rule 9)."""

    if secret and text:
        return text.replace(secret, "[REDACTED]")
    return text


def build_messages(user_text: str) -> list[dict[str, Any]]:
    """Same instruction shape as the rest of the router; external content is never
    merged into the system prompt (AGENTS.md rule 7)."""

    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": user_text},
    ]


def build_request_body(
    settings: Settings, messages: list[dict[str, Any]], tools: list[dict[str, Any]], *, stream: bool
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "model": settings.ashna_model,
        "messages": messages,
        "stream": stream,
    }
    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"
    return body


def parse_completion_payload(payload: Any) -> LLMResult:
    """Normalize an OpenAI-shaped ``chat.completion`` body into the router's result."""

    choices = payload.get("choices", []) if isinstance(payload, dict) else []
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise AshnaUnavailable
    choice = choices[0]
    message = choice.get("message", {})
    if not isinstance(message, dict):
        raise AshnaUnavailable
    calls = _tool_calls(message.get("tool_calls"))
    return LLMResult(
        text=_content(message.get("content")),
        tool_calls=calls,
        finish_reason="tool_calls" if calls else str(choice.get("finish_reason", "stop"))[:32],
    )


def parse_sse_line(line: str) -> dict[str, Any] | None:
    """Parse one SSE line of an OpenAI-compatible stream.

    Returns the JSON event dict, ``{"done": True}`` for the ``data: [DONE]`` terminator,
    or ``None`` for blank lines, comments, non-data fields, and malformed payloads
    (malformed lines are skipped rather than aborting the stream).
    """

    stripped = line.strip()
    if not stripped or stripped.startswith(":") or not stripped.startswith("data:"):
        return None
    data = stripped[len("data:") :].strip()
    if not data:
        return None
    if data == _STREAM_DONE_MARKER:
        return {"done": True}
    try:
        parsed = json.loads(data)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _merge_tool_call_delta(acc: dict[int, dict[str, str]], item: Any) -> None:
    """Accumulate one OpenAI streaming ``tool_calls`` delta entry by its index."""

    if not isinstance(item, dict):
        return
    raw_index = item.get("index", 0)
    try:
        index = int(raw_index)
    except (TypeError, ValueError):
        return
    if index < 0 or index > _MAX_TOOL_CALL_DELTA_INDEX:
        return
    entry = acc.setdefault(index, {"id": "", "name": "", "arguments": ""})
    if isinstance(item.get("id"), str) and not entry["id"]:
        entry["id"] = item["id"]
    function = item.get("function")
    if isinstance(function, dict):
        if isinstance(function.get("name"), str):
            entry["name"] += function["name"]
        if isinstance(function.get("arguments"), str):
            entry["arguments"] += function["arguments"]


def _accumulated_tool_calls(acc: dict[int, dict[str, str]]) -> list[dict[str, Any]]:
    return [
        {
            "id": entry["id"] or None,
            "function": {"name": entry["name"], "arguments": entry["arguments"]},
        }
        for _, entry in sorted(acc.items())
        if entry["name"]
    ]


def _backoff_seconds(attempt: int) -> float:
    return min(4.0, 0.5 * (2.0 ** (attempt - 1)))


def _error_message_from_response(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return f"HTTP {response.status_code}"
    error = payload.get("error") if isinstance(payload, dict) else None
    message = error.get("message") if isinstance(error, dict) else None
    if isinstance(message, str):
        return message
    return f"HTTP {response.status_code}"


class AshnaAdapter:
    """LLM router adapter for Ashna AI's hosted ``ashna-x1`` model."""

    def __init__(self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None):
        key = settings.ashna_api_key
        if key is None or not key.get_secret_value().strip():
            # Startup validation already rejects this configuration; fail typed anyway so
            # a misconstructed adapter surfaces through the existing LLM error path.
            raise AshnaUnavailable
        self._api_key = key.get_secret_value().strip()
        self._base_url = settings.ashna_base_url.rstrip("/")
        self._settings = settings
        self._transport = transport

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

    def _timeout(self) -> httpx.Timeout:
        return httpx.Timeout(self._settings.llm_timeout_seconds)

    async def complete(self, *, user_text: str, tools: list[dict[str, Any]]) -> LLMResult:
        """Single (non-streamed) completion, normalized into the router's shape."""

        body = build_request_body(self._settings, build_messages(user_text), tools, stream=False)
        payload = await self._post_json(body)
        return parse_completion_payload(payload)

    async def stream(
        self, *, user_text: str, tools: list[dict[str, Any]]
    ) -> AsyncIterator[TokenDelta | StreamResult]:
        """OpenAI-SSE stream translated into the router's internal token-stream shape.

        Yields :class:`TokenDelta` events as assistant text arrives and finishes with a
        :class:`StreamResult` whose ``result`` matches what ``complete()`` would return.
        Retries apply before the first response byte; a failure mid-stream raises
        :class:`AshnaUnavailable` (partial tokens were already emitted).
        """

        body = build_request_body(self._settings, build_messages(user_text), tools, stream=True)
        url = f"{self._base_url}/chat/completions"
        attempt = 0
        while True:
            attempt += 1
            try:
                async with httpx.AsyncClient(
                    timeout=self._timeout(), transport=self._transport
                ) as client:
                    async with client.stream(
                        "POST", url, json=body, headers=self._headers()
                    ) as response:
                        if response.status_code >= 400:
                            await response.aread()
                            if (
                                response.status_code in _RETRYABLE_STATUS
                                and attempt < _MAX_ATTEMPTS
                            ):
                                await asyncio.sleep(_backoff_seconds(attempt))
                                continue
                            logger.warning(
                                "Ashna stream rejected status=%s detail=%s; credentials omitted",
                                response.status_code,
                                redact_secret(
                                    self._api_key, _error_message_from_response(response)
                                )[:200],
                            )
                            raise AshnaUnavailable from None
                        async for result in self._consume_stream(response):
                            yield result
                        return
            except asyncio.CancelledError:
                raise
            except AshnaUnavailable:
                raise
            except (httpx.HTTPError, ValueError, KeyError, TypeError):
                if attempt >= _MAX_ATTEMPTS:
                    logger.warning(
                        "Ashna stream failed after %s attempt(s); credentials omitted", attempt
                    )
                    raise AshnaUnavailable from None
                await asyncio.sleep(_backoff_seconds(attempt))

    async def _consume_stream(
        self, response: httpx.Response
    ) -> AsyncIterator[TokenDelta | StreamResult]:
        text_parts: list[str] = []
        text_length = 0
        finish_reason = "stop"
        tool_acc: dict[int, dict[str, str]] = {}
        async for line in response.aiter_lines():
            event = parse_sse_line(line)
            if event is None:
                continue
            if event.get("done") is True:
                break
            choices = event.get("choices")
            if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
                continue
            choice = choices[0]
            if isinstance(choice.get("finish_reason"), str) and choice["finish_reason"]:
                finish_reason = choice["finish_reason"][:32]
            delta = choice.get("delta")
            if not isinstance(delta, dict):
                continue
            content = delta.get("content")
            if isinstance(content, str) and content and text_length < _MAX_ASSISTANT_TEXT:
                text_parts.append(content)
                text_length += len(content)
                yield TokenDelta(token=content)
            tool_deltas = delta.get("tool_calls")
            if isinstance(tool_deltas, list):
                for item in tool_deltas:
                    _merge_tool_call_delta(tool_acc, item)
        calls = _tool_calls(_accumulated_tool_calls(tool_acc))
        result = LLMResult(
            text=_content("".join(text_parts)),
            tool_calls=calls,
            finish_reason="tool_calls" if calls else finish_reason,
        )
        yield StreamResult(result=result)

    async def _post_json(self, body: dict[str, Any]) -> dict[str, Any]:
        url = f"{self._base_url}/chat/completions"
        attempt = 0
        while True:
            attempt += 1
            detail = "request failed"
            retryable = False
            try:
                async with httpx.AsyncClient(
                    timeout=self._timeout(), transport=self._transport
                ) as client:
                    response = await client.post(url, json=body, headers=self._headers())
            except asyncio.CancelledError:
                raise
            except httpx.HTTPError:
                retryable = True
            else:
                if response.status_code in _RETRYABLE_STATUS:
                    retryable = True
                    detail = f"HTTP {response.status_code}"
                elif response.status_code >= 400:
                    logger.warning(
                        "Ashna request rejected status=%s detail=%s; credentials omitted",
                        response.status_code,
                        redact_secret(self._api_key, _error_message_from_response(response))[:200],
                    )
                    raise AshnaUnavailable from None
                else:
                    try:
                        payload = response.json()
                    except ValueError:
                        logger.warning(
                            "Ashna returned a non-JSON success response; credentials omitted"
                        )
                        raise AshnaUnavailable from None
                    if not isinstance(payload, dict):
                        raise AshnaUnavailable from None
                    return payload
            if not retryable or attempt >= _MAX_ATTEMPTS:
                logger.warning(
                    "Ashna request failed after %s attempt(s); %s; credentials omitted",
                    attempt,
                    detail,
                )
                raise AshnaUnavailable from None
            await asyncio.sleep(_backoff_seconds(attempt))
