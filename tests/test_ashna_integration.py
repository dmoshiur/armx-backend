# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""Integration tests for the Ashna (ashna-x1) LLM provider.

* ``test_ws_chat_pipeline_is_unaffected_by_ashna_provider`` re-runs the PROMPT_06 WS chat
  flow (assistant.token / assistant.done / tool.request confirmation loop) with the router
  pointed at the Ashna provider and a mocked Ashna HTTP endpoint, proving the chat pipeline
  and WS contract are unchanged by the provider swap.
* ``test_ashna_failure_surfaces_through_existing_error_ui`` proves LLM failures reach the
  frontend through the same ``assistant.done`` error shape the client already renders.
* ``test_ashna_live_smoke_round_trip`` performs a real round trip against Ashna AI and is
  skipped unless the environment provides a real ``ASHNA_API_KEY`` and opts in with
  ``ARMX_LIVE_LLM_TESTS=1``.
"""

import json
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import select

from app.auth.dependencies import Principal
from app.chat.providers.ashna_adapter import AshnaAdapter
from app.config import Settings
from app.db.models import AuthSession, Device, PendingToolCall, ToolToggle, User
from app.ws import routes as websocket_routes
from app.ws.manager import SocketIdentity, connection_manager
from app.ws.schemas import ChatSendFrame
from tests.helpers import Harness, _harness


def _ashna_settings(harness: Harness) -> Settings:
    return harness.settings.model_copy(
        update={
            "llm_provider": "ashna",
            "ashna_api_key": SecretStr("ashna-test-key"),
            "ashna_base_url": "https://api.ashna.ai/v1/api",
            "ashna_model": "ashna-x1",
        }
    )


@asynccontextmanager
async def _principal(harness: Harness) -> AsyncIterator[tuple[Any, Principal]]:
    async with harness.factory() as session:
        user = await session.scalar(select(User).where(User.username == "owner"))
        device = await session.scalar(select(Device).where(Device.public_id == "device-owner"))
        assert user is not None and device is not None
        session.add(ToolToggle(name="DB", enabled=True))
        auth_session = AuthSession(
            user_id=user.id,
            device_id=device.id,
            refresh_token_hash="c" * 64,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        session.add(auth_session)
        await session.flush()
        yield session, Principal(user=user, device=device, auth_session=auth_session)


@pytest.mark.asyncio
async def test_ws_chat_pipeline_is_unaffected_by_ashna_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = await _harness()
    settings = _ashna_settings(harness)
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization")
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "id": "chatcmpl-1",
                "object": "chat.completion",
                "created": 1704369000,
                "model": "ashna-x1",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "I can prepare that note for approval.",
                            "tool_calls": [
                                {
                                    "id": "call-1",
                                    "type": "function",
                                    "function": {
                                        "name": "notes_create",
                                        "arguments": json.dumps(
                                            {"title": "Demo", "body": "Pending approval"}
                                        ),
                                    },
                                }
                            ],
                        },
                        "finish_reason": "tool_calls",
                    }
                ],
                "usage": {"prompt_tokens": 12, "completion_tokens": 9, "total_tokens": 21},
            },
        )

    # Route the real AshnaAdapter through a mocked Ashna endpoint; everything else —
    # router dispatch, normalization, tool confirmation loop, WS events — stays live.
    def mocked_adapter(provider_settings: Settings) -> AshnaAdapter:
        return AshnaAdapter(provider_settings, transport=httpx.MockTransport(handler))

    monkeypatch.setattr("app.chat.llm.AshnaAdapter", mocked_adapter)

    async with _principal(harness) as (session, principal):
        websocket = AsyncMock()
        await connection_manager.connect(
            websocket, SocketIdentity(user_id=principal.user.id, device_id=principal.device.id)
        )
        try:
            await websocket_routes._send_chat(
                websocket,
                session,
                principal,
                settings,
                ChatSendFrame(type="chat.send", text="Create a note"),
            )
        finally:
            await connection_manager.disconnect(websocket)

        # The provider swap must not change the wire behavior of the chat pipeline.
        pending = await session.scalar(select(PendingToolCall))
        assert pending is not None and pending.status == "PENDING"
        events = [call.args[0] for call in websocket.send_json.call_args_list]
        token_events = [event for event in events if event.get("type") == "assistant.token"]
        assert token_events
        assert "".join(event["token"] for event in token_events) == (
            "I can prepare that note for approval."
        )
        assert all(len(event["token"]) <= 48 for event in token_events)
        assert [event["index"] for event in token_events] == list(range(len(token_events)))
        tool_requests = [event for event in events if event.get("type") == "tool.request"]
        assert len(tool_requests) == 1
        assert tool_requests[0]["call"]["tool"] == "notes_create"
        done = [event for event in events if event.get("type") == "assistant.done"][-1]
        assert done["finish_reason"] == "tool_calls"
        assert done["text"] == "I can prepare that note for approval."

        # The request actually sent to the Ashna-shaped endpoint.
        assert captured["url"] == "https://api.ashna.ai/v1/api/chat/completions"
        assert captured["auth"] == "Bearer ashna-test-key"
        assert captured["body"]["model"] == "ashna-x1"
        assert captured["body"]["stream"] is False
        assert captured["body"]["tool_choice"] == "auto"
    await harness.engine.dispose()


@pytest.mark.asyncio
async def test_ashna_failure_surfaces_through_existing_error_ui(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = await _harness()
    settings = _ashna_settings(harness)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": "Invalid API key provided."}})

    def mocked_adapter(provider_settings: Settings) -> AshnaAdapter:
        return AshnaAdapter(provider_settings, transport=httpx.MockTransport(handler))

    monkeypatch.setattr("app.chat.llm.AshnaAdapter", mocked_adapter)

    async with _principal(harness) as (session, principal):
        websocket = AsyncMock()
        await connection_manager.connect(
            websocket, SocketIdentity(user_id=principal.user.id, device_id=principal.device.id)
        )
        try:
            await websocket_routes._send_chat(
                websocket,
                session,
                principal,
                settings,
                ChatSendFrame(type="chat.send", text="Hello"),
            )
        finally:
            await connection_manager.disconnect(websocket)

        events = [call.args[0] for call in websocket.send_json.call_args_list]
        done = [event for event in events if event.get("type") == "assistant.done"]
        assert len(done) == 1
        # Same event shape the PROMPT_08 frontend error UI already renders.
        assert done[0]["finish_reason"] == "unavailable"
        assert done[0]["blocked"] is False
        assert "unavailable" in done[0]["text"].lower()
    await harness.engine.dispose()


@pytest.mark.asyncio
async def test_ashna_live_smoke_round_trip() -> None:
    api_key = os.environ.get("ASHNA_API_KEY", "").strip()
    if os.environ.get("ARMX_LIVE_LLM_TESTS") != "1" or not api_key:
        pytest.skip("Live Ashna round-trip requires ARMX_LIVE_LLM_TESTS=1 and a real ASHNA_API_KEY")
    settings = Settings(
        _env_file=None,
        environment="demo",
        demo_insecure=True,
        jwt_secret_key="live-test-signing-key-0123456789abcdef",
        llm_provider="ashna",
        ashna_api_key=SecretStr(api_key),
    )
    result = await AshnaAdapter(settings).complete(
        user_text="Reply with exactly one word: pong", tools=[]
    )
    assert result.text.strip()
