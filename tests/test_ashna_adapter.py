# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import json
import logging
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from app.chat import llm
from app.chat.llm_core import (
    UNTRUSTED_CONTENT_CLOSE,
    UNTRUSTED_CONTENT_OPEN,
    LLMResult,
    LLMUnavailable,
    delimit_untrusted_content,
)
from app.chat.providers import ashna_adapter
from app.chat.providers.ashna_adapter import (
    AshnaAdapter,
    AshnaUnavailable,
    StreamResult,
    TokenDelta,
    parse_sse_line,
    redact_secret,
)
from app.config import Settings

API_KEY = "ashna-secret-key-do-not-log"
_NOTES_CREATE_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "notes_create",
            "description": "Create a private note.",
            "parameters": {
                "type": "object",
                "properties": {"title": {"type": "string"}, "body": {"type": "string"}},
                "required": ["title", "body"],
            },
        },
    }
]


def _settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "_env_file": None,
        "environment": "demo",
        "demo_insecure": True,
        "jwt_secret_key": "test-signing-key-that-is-long-enough-012345",
        "llm_provider": "ashna",
        "ashna_api_key": SecretStr(API_KEY),
    }
    base.update(overrides)
    return Settings(**base)


def _completion_body(
    content: str = "Hello from Ashna",
    tool_calls: list[dict[str, Any]] | None = None,
    finish_reason: str = "stop",
) -> dict[str, Any]:
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1704369000,
        "model": "ashna-x1",
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }


def _sse(events: list[dict[str, Any] | str]) -> str:
    lines: list[str] = []
    for event in events:
        lines.append("data: " + (event if isinstance(event, str) else json.dumps(event)))
        lines.append("")
    return "\n".join(lines)


def _chunk(delta: dict[str, Any], finish_reason: str | None = None, **extra: Any) -> dict[str, Any]:
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion.chunk",
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
        **extra,
    }


@pytest.fixture(autouse=True)
def _no_backoff_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ashna_adapter, "_backoff_seconds", lambda attempt: 0.0)


@pytest.mark.asyncio
async def test_ashna_request_mapping_and_response_normalization() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization")
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json=_completion_body(
                content="I can prepare that.",
                tool_calls=[
                    {
                        "id": "call-7",
                        "type": "function",
                        "function": {
                            "name": "notes_create",
                            "arguments": json.dumps({"title": "Demo", "body": "Body"}),
                        },
                    }
                ],
                finish_reason="tool_calls",
            ),
        )

    adapter = AshnaAdapter(_settings(), transport=httpx.MockTransport(handler))
    result = await adapter.complete(user_text="Create a note", tools=_NOTES_CREATE_TOOLS)

    assert captured["url"] == "https://api.ashna.ai/v1/api/chat/completions"
    assert captured["auth"] == f"Bearer {API_KEY}"
    body = captured["body"]
    assert body["model"] == "ashna-x1"
    assert body["stream"] is False
    assert body["tools"] == _NOTES_CREATE_TOOLS
    assert body["tool_choice"] == "auto"
    assert body["messages"][0]["role"] == "system"
    assert body["messages"][1] == {"role": "user", "content": "Create a note"}

    assert result.text == "I can prepare that."
    assert result.finish_reason == "tool_calls"
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0].call_id == "call-7"
    assert result.tool_calls[0].arguments == {"title": "Demo", "body": "Body"}


@pytest.mark.asyncio
async def test_ashna_omits_tool_fields_without_tools() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json=_completion_body())

    adapter = AshnaAdapter(_settings(), transport=httpx.MockTransport(handler))
    result = await adapter.complete(user_text="Hello", tools=[])
    assert "tools" not in captured["body"]
    assert "tool_choice" not in captured["body"]
    assert result.text == "Hello from Ashna"
    assert result.finish_reason == "stop"
    assert result.tool_calls == ()


@pytest.mark.asyncio
async def test_ashna_unauthorized_raises_typed_error_without_retry() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(
            401,
            json={
                "error": {
                    "message": "Invalid API key provided.",
                    "type": "invalid_request_error",
                    "code": "invalid_api_key",
                    "param": None,
                }
            },
        )

    adapter = AshnaAdapter(_settings(), transport=httpx.MockTransport(handler))
    with pytest.raises(AshnaUnavailable):
        await adapter.complete(user_text="hi", tools=[])
    assert calls["n"] == 1
    # The typed error flows through the router's existing LLM failure path unchanged.
    assert issubclass(AshnaUnavailable, LLMUnavailable)


@pytest.mark.asyncio
async def test_ashna_retries_rate_limit_and_server_errors_then_succeeds() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, json={"error": {"message": "Rate limit exceeded"}})
        if calls["n"] == 2:
            return httpx.Response(503, json={"error": {"message": "Upstream busy"}})
        return httpx.Response(200, json=_completion_body(content="recovered"))

    adapter = AshnaAdapter(_settings(), transport=httpx.MockTransport(handler))
    result = await adapter.complete(user_text="hi", tools=[])
    assert result.text == "recovered"
    assert calls["n"] == 3


@pytest.mark.asyncio
async def test_ashna_exhausted_retries_raise_typed_error() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(500, json={"error": {"message": "Server error"}})

    adapter = AshnaAdapter(_settings(), transport=httpx.MockTransport(handler))
    with pytest.raises(AshnaUnavailable):
        await adapter.complete(user_text="hi", tools=[])
    assert calls["n"] == ashna_adapter._MAX_ATTEMPTS


@pytest.mark.asyncio
async def test_ashna_timeout_raises_typed_error_after_retries() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        raise httpx.ReadTimeout("read timed out", request=request)

    adapter = AshnaAdapter(_settings(), transport=httpx.MockTransport(handler))
    with pytest.raises(AshnaUnavailable):
        await adapter.complete(user_text="hi", tools=[])
    assert calls["n"] == ashna_adapter._MAX_ATTEMPTS


@pytest.mark.asyncio
async def test_ashna_malformed_success_payload_raises_typed_error() -> None:
    def not_json(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>oops</html>")

    def missing_choices(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"choices": []})

    with pytest.raises(AshnaUnavailable):
        await AshnaAdapter(_settings(), transport=httpx.MockTransport(not_json)).complete(
            user_text="hi", tools=[]
        )
    with pytest.raises(AshnaUnavailable):
        await AshnaAdapter(_settings(), transport=httpx.MockTransport(missing_choices)).complete(
            user_text="hi", tools=[]
        )


@pytest.mark.asyncio
async def test_ashna_stream_translates_sse_to_internal_token_shape() -> None:
    tool_arguments = json.dumps({"query": "lights"})
    body = _sse(
        [
            _chunk({"role": "assistant", "content": ""}),
            ": keep-alive",
            _chunk({"content": "Hel"}),
            _chunk({"content": "lo"}),
            _chunk(
                {
                    "tool_calls": [
                        {
                            "index": 0,
                            "id": "call-9",
                            "function": {"name": "notes_", "arguments": tool_arguments[:6]},
                        }
                    ]
                }
            ),
            _chunk(
                {
                    "tool_calls": [
                        {
                            "index": 0,
                            "function": {"name": "search", "arguments": tool_arguments[6:]},
                        }
                    ]
                },
                finish_reason="tool_calls",
            ),
            {"usage": {"prompt_tokens": 8, "completion_tokens": 3, "total_tokens": 11}},
            "data-malformed-not-json",
            "[DONE]",
        ]
    )

    def handler(request: httpx.Request) -> httpx.Response:
        parsed = json.loads(request.content)
        assert parsed["stream"] is True
        return httpx.Response(200, text=body, headers={"content-type": "text/event-stream"})

    adapter = AshnaAdapter(_settings(), transport=httpx.MockTransport(handler))
    events = [event async for event in adapter.stream(user_text="hi", tools=[])]

    tokens = [event.token for event in events if isinstance(event, TokenDelta)]
    assert tokens == ["Hel", "lo"]
    final = events[-1]
    assert isinstance(final, StreamResult)
    assert final.result.text == "Hello"
    assert final.result.finish_reason == "tool_calls"
    assert len(final.result.tool_calls) == 1
    call = final.result.tool_calls[0]
    assert call.call_id == "call-9"
    assert call.name == "notes_search"
    assert call.arguments == {"query": "lights"}


@pytest.mark.asyncio
async def test_ashna_stream_retries_before_first_byte_then_succeeds() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, json={"error": {"message": "slow down"}})
        return httpx.Response(
            200,
            text=_sse([_chunk({"content": "ok"}), _chunk({}, finish_reason="stop"), "[DONE]"]),
            headers={"content-type": "text/event-stream"},
        )

    adapter = AshnaAdapter(_settings(), transport=httpx.MockTransport(handler))
    events = [event async for event in adapter.stream(user_text="hi", tools=[])]
    assert calls["n"] == 2
    final = events[-1]
    assert isinstance(final, StreamResult)
    assert final.result.text == "ok"


@pytest.mark.asyncio
async def test_ashna_stream_error_status_raises_typed_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": {"message": "Model not allowed for key"}})

    adapter = AshnaAdapter(_settings(), transport=httpx.MockTransport(handler))
    with pytest.raises(AshnaUnavailable):
        _ = [event async for event in adapter.stream(user_text="hi", tools=[])]


def test_sse_line_parsing_edge_cases() -> None:
    assert parse_sse_line(": keep-alive") is None
    assert parse_sse_line("") is None
    assert parse_sse_line("event: message") is None
    assert parse_sse_line("data: {not-json") is None
    assert parse_sse_line("data: [1, 2]") is None
    assert parse_sse_line("data: [DONE]") == {"done": True}
    assert parse_sse_line('data: {"a": 1}') == {"a": 1}


@pytest.mark.asyncio
async def test_api_key_is_redacted_from_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={
                "error": {
                    "message": f"Invalid API key provided: {API_KEY}",
                    "type": "invalid_request_error",
                    "code": "invalid_api_key",
                }
            },
        )

    adapter = AshnaAdapter(_settings(), transport=httpx.MockTransport(handler))
    with caplog.at_level(logging.WARNING, logger="armx.chat.providers.ashna"):
        with pytest.raises(AshnaUnavailable):
            await adapter.complete(user_text="hi", tools=[])

    assert API_KEY not in caplog.text
    assert "[REDACTED]" in caplog.text


def test_redact_secret_helper() -> None:
    assert redact_secret("s3cret", "key s3cret leaked") == "key [REDACTED] leaked"
    assert redact_secret("", "nothing to redact") == "nothing to redact"


def test_settings_ashna_requires_api_key_at_startup() -> None:
    with pytest.raises(ValueError, match="ASHNA_API_KEY is required"):
        Settings(
            _env_file=None,
            environment="demo",
            demo_insecure=True,
            jwt_secret_key="test-signing-key-that-is-long-enough-012345",
            llm_provider="ashna",
        )
    with pytest.raises(ValueError, match="ASHNA_API_KEY is required"):
        Settings(
            _env_file=None,
            environment="demo",
            demo_insecure=True,
            jwt_secret_key="test-signing-key-that-is-long-enough-012345",
            llm_provider="ashna",
            ashna_api_key=SecretStr("   "),
        )
    # The offline fallback remains valid without any Ashna configuration.
    fallback = Settings(
        _env_file=None,
        environment="demo",
        demo_insecure=True,
        jwt_secret_key="test-signing-key-that-is-long-enough-012345",
        llm_provider="ollama",
    )
    assert fallback.llm_provider == "ollama"


def test_settings_ashna_requires_https_outside_demo() -> None:
    with pytest.raises(ValueError, match="ASHNA_BASE_URL"):
        Settings(
            _env_file=None,
            environment="demo",
            demo_insecure=False,
            jwt_secret_key="test-signing-key-that-is-long-enough-012345",
            llm_provider="ashna",
            ashna_api_key=SecretStr(API_KEY),
            ashna_base_url="http://api.ashna.ai/v1/api",
        )


def test_adapter_refuses_configuration_without_key() -> None:
    settings = _settings().model_copy(update={"ashna_api_key": SecretStr("")})
    with pytest.raises(AshnaUnavailable):
        AshnaAdapter(settings)


@pytest.mark.asyncio
async def test_llm_router_dispatches_ashna_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = LLMResult(text="from ashna stub", tool_calls=(), finish_reason="stop")

    class StubAdapter:
        def __init__(self, settings: Settings) -> None:
            assert settings.llm_provider == "ashna"

        async def complete(self, *, user_text: str, tools: list[dict[str, Any]]) -> LLMResult:
            assert user_text == "hello"
            assert tools == []
            return sentinel

    monkeypatch.setattr(llm, "AshnaAdapter", StubAdapter)
    result = await llm.complete(_settings(), user_text="hello", tools=[])
    assert result is sentinel


def test_untrusted_content_is_delimited_and_bounded() -> None:
    wrapped = delimit_untrusted_content("issue body from GitHub")
    assert wrapped.startswith(UNTRUSTED_CONTENT_OPEN)
    assert wrapped.endswith(UNTRUSTED_CONTENT_CLOSE)
    assert "issue body from GitHub" in wrapped
    bounded = delimit_untrusted_content("x" * 20_000)
    assert bounded.count("x") <= 12_000
