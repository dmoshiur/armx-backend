# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import asyncio
import json
import logging
import re
from datetime import UTC, datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import authenticate_principal
from app.chat.llm import LLMUnavailable, complete
from app.config import Settings, get_settings
from app.core.errors import APIError
from app.core.privacy import contains_raw_biometric_data
from app.db.session import get_session
from app.ws.manager import SocketIdentity, connection_manager
from app.ws.schemas import ChatSendFrame

router = APIRouter(tags=["websocket"])
logger = logging.getLogger("armx.ws.routes")


def _message_id(value: str | None) -> str:
    if value and re.fullmatch(r"[A-Za-z0-9._:-]{1,96}", value):
        return value
    return f"msg-{uuid4().hex[:12]}"


def _send_text(text: str, message_id: str, conversation_id: str) -> list[dict[str, object]]:
    return [
        {
            "type": "assistant.token",
            "message_id": message_id,
            "conversation_id": conversation_id,
            "token": text[offset : offset + 48],
            "index": index,
        }
        for index, offset in enumerate(range(0, len(text), 48))
    ]


async def _send_chat(
    websocket: WebSocket,
    settings: Settings,
    frame: ChatSendFrame,
) -> None:
    message_id = _message_id(frame.message_id)
    if contains_raw_biometric_data({"user_text": frame.text}):
        await connection_manager.send(
            websocket,
            {
                "type": "assistant.done",
                "message_id": message_id,
                "text": "Raw biometric data is not accepted by the A.R.M.X backend.",
                "finish_reason": "blocked",
                "blocked": True,
            },
        )
        return
    try:
        result = await complete(settings, user_text=frame.text, tools=[])
    except LLMUnavailable:
        await connection_manager.send(
            websocket,
            {
                "type": "assistant.done",
                "message_id": message_id,
                "text": "The assistant service is unavailable. Please try again later.",
                "finish_reason": "unavailable",
                "blocked": False,
            },
        )
        return

    for event in _send_text(result.text, message_id, frame.conversation_id):
        await connection_manager.send(websocket, event)
    await connection_manager.send(
        websocket,
        {
            "type": "assistant.done",
            "message_id": message_id,
            "text": result.text,
            "finish_reason": result.finish_reason,
            "blocked": False,
        },
    )


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> None:
    if not settings.demo_insecure and websocket.url.scheme.lower() not in {"https", "wss"}:
        await websocket.close(code=1008, reason="TLS required")
        return

    try:
        principal = await authenticate_principal(
            websocket.headers.get("authorization"),
            websocket.headers.get("x-armx-device-key"),
            session,
            settings,
        )
    except APIError:
        await websocket.close(code=4401, reason="Authentication failed")
        return

    principal.device.last_seen_at = datetime.now(UTC)
    await session.commit()
    await connection_manager.connect(
        websocket, SocketIdentity(user_id=principal.user.id, device_id=principal.device.id)
    )
    try:
        while True:
            raw = await websocket.receive_text()
            if len(raw.encode("utf-8")) > 16_384:
                await websocket.close(code=1009, reason="Frame too large")
                return
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            if payload.get("type") == "system.heartbeat":
                await connection_manager.send(websocket, {"type": "system.heartbeat"})
                continue
            try:
                frame = ChatSendFrame.model_validate(payload)
            except ValidationError:
                continue
            await _send_chat(websocket, settings, frame)
    except WebSocketDisconnect:
        pass
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.warning("WebSocket session ended unexpectedly; details omitted")
    finally:
        await connection_manager.disconnect(websocket)
