# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from app.chat import llm
from app.config import Settings


def _settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "_env_file": None,
        "environment": "demo",
        "demo_insecure": True,
        "database_url": "sqlite+aiosqlite:///./groq-test.db",
        "jwt_secret_key": "g" * 32,
        "llm_provider": "groq",
        "groq_api_key": SecretStr("groq-test-secret"),
    }
    values.update(overrides)
    return Settings(**values)


def test_groq_requires_key_and_https_endpoint() -> None:
    with pytest.raises(ValidationError, match="GROQ_API_KEY is required"):
        _settings(groq_api_key=None)
    with pytest.raises(ValidationError, match="safe HTTPS endpoint"):
        _settings(groq_base_url="http://api.groq.com/openai/v1")


@pytest.mark.asyncio
async def test_groq_router_sends_configured_model_and_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return {"choices": [{"message": {"content": "Groq replied"}, "finish_reason": "stop"}]}

    class Client:
        def __init__(self, **kwargs: Any) -> None:
            captured["timeout"] = kwargs.get("timeout")

        async def __aenter__(self) -> Client:
            return self

        async def __aexit__(self, *args: Any) -> None:
            return None

        async def post(
            self, url: str, *, json: dict[str, Any], headers: dict[str, str]
        ) -> Response:
            captured.update(url=url, body=json, headers=headers)
            return Response()

    monkeypatch.setattr(llm.httpx, "AsyncClient", Client)
    tool = {"type": "function", "function": {"name": "devices.list"}}
    result = await llm.complete(_settings(), user_text="hello", tools=[tool])

    assert result.text == "Groq replied"
    assert captured["url"] == "https://api.groq.com/openai/v1/chat/completions"
    assert captured["headers"] == {"Authorization": "Bearer groq-test-secret"}
    assert captured["body"]["model"] == "qwen/qwen3.8-27b"
    assert captured["body"]["tools"] == [tool]
    assert captured["body"]["tool_choice"] == "auto"
