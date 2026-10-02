# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import asyncio
import json
import logging
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import write_audit
from app.auth.dependencies import Principal, authenticate_principal
from app.chat.llm import LLMUnavailable, complete
from app.config import Settings, get_settings
from app.core.errors import APIError
from app.core.execution import execution_registry
from app.core.privacy import contains_raw_biometric_data
from app.core.system_state import is_kill_switch_engaged
from app.core.verification import consume_owner_assertion
from app.db.models import PendingToolCall
from app.db.session import get_session
from app.mcp.tools import available_tool_schemas, derive_risk_tier, execute_tool
from app.ws.manager import SocketIdentity, connection_manager
from app.ws.schemas import ChatSendFrame, ToolDecisionFrame

router = APIRouter(tags=["websocket"])
logger = logging.getLogger("armx.ws.routes")
_HEARTBEAT_SECONDS = 25
_TOOL_CALL_TTL = timedelta(minutes=5)


def _message_id(value: str | None) -> str:
    if value and re.fullmatch(r"[A-Za-z0-9._:-]{1,96}", value):
        return value
    return f"msg-{uuid4().hex[:12]}"


def _send_text(text: str, message_id: str, conversation_id: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    index = 0
    for offset in range(0, len(text), 48):
        events.append(
            {
                "type": "assistant.token",
                "message_id": message_id,
                "conversation_id": conversation_id,
                "token": text[offset : offset + 48],
                "index": index,
            }
        )
        index += 1
    return events


async def _assistant_done(
    websocket: WebSocket,
    message_id: str,
    text: str,
    *,
    finish_reason: str = "stop",
    blocked: bool = False,
) -> None:
    await connection_manager.send(
        websocket,
        {
            "type": "assistant.done",
            "message_id": message_id,
            "text": text,
            "finish_reason": finish_reason,
            "blocked": blocked,
        },
    )


async def _heartbeat(websocket: WebSocket, stop: asyncio.Event) -> None:
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=_HEARTBEAT_SECONDS)
        except TimeoutError:
            try:
                await connection_manager.send(websocket, {"type": "system.heartbeat"})
            except WebSocketDisconnect:
                return
        except asyncio.CancelledError:
            raise


async def _send_chat(
    websocket: WebSocket,
    session: AsyncSession,
    principal: Principal,
    settings: Settings,
    frame: ChatSendFrame,
) -> None:
    message_id = _message_id(frame.message_id)
    if contains_raw_biometric_data({"user_text": frame.text}):
        await _assistant_done(
            websocket,
            message_id,
            "Raw biometric data is not accepted by the A.R.M.X backend.",
            finish_reason="blocked",
            blocked=True,
        )
        return
    if await is_kill_switch_engaged(session):
        await _assistant_done(
            websocket,
            message_id,
            "The global kill-switch is engaged. No assistant or tool work was started.",
            finish_reason="blocked",
            blocked=True,
        )
        return

    tools = await available_tool_schemas(session, settings, principal)
    task = asyncio.current_task()
    if task is not None:
        await execution_registry.register(task)
    try:
        if await is_kill_switch_engaged(session):
            await _assistant_done(
                websocket,
                message_id,
                "The global kill-switch is engaged. No assistant or tool work was started.",
                finish_reason="blocked",
                blocked=True,
            )
            return
        result = await complete(settings, user_text=frame.text, tools=tools)
    except LLMUnavailable:
        await _assistant_done(
            websocket,
            message_id,
            "The assistant service is unavailable. Please try again later.",
            finish_reason="unavailable",
            blocked=False,
        )
        return
    finally:
        if task is not None:
            await execution_registry.unregister(task)

    assistant_text = result.text
    events = _send_text(assistant_text, message_id, frame.conversation_id)
    pending_events: list[dict[str, Any]] = []
    allowed_names = {
        schema["function"]["name"] for schema in tools if isinstance(schema.get("function"), dict)
    }
    for call in result.tool_calls:
        if call.name not in allowed_names:
            await connection_manager.send(
                websocket,
                {
                    "type": "tool.result",
                    "tool_call_id": call.call_id,
                    "success": False,
                    "summary": "That tool is not enabled or available.",
                },
            )
            continue
        if len(json.dumps(call.arguments, ensure_ascii=False).encode("utf-8")) > 16_384:
            await connection_manager.send(
                websocket,
                {
                    "type": "tool.result",
                    "tool_call_id": call.call_id,
                    "success": False,
                    "summary": "Tool request was too large and was not queued.",
                },
            )
            continue
        if contains_raw_biometric_data(call.arguments):
            await connection_manager.send(
                websocket,
                {
                    "type": "tool.result",
                    "tool_call_id": call.call_id,
                    "success": False,
                    "summary": "Raw biometric or audio data is not accepted; nothing was queued.",
                },
            )
            continue
        tier = await derive_risk_tier(session, principal, call.name, call.arguments)
        tool_call_id = f"tc-{uuid4().hex[:12]}"
        pending = PendingToolCall(
            id=tool_call_id,
            user_id=principal.user.id,
            device_id=principal.device.id,
            tool=call.name,
            parameters=call.arguments,
            risk_tier=tier.value,
            reason=(
                "Assistant-proposed tool call; explicit approval and fresh verification required."
            ),
            status="PENDING",
            expires_at=datetime.now(UTC) + _TOOL_CALL_TTL,
        )
        session.add(pending)
        await write_audit(
            session,
            actor_user_id=principal.user.id,
            subject_user_id=principal.user.id,
            device_id=principal.device.id,
            action="tool.request",
            target=tool_call_id,
            risk_tier=tier.value,
            outcome="SUCCESS",
            detail="Tool request queued for explicit user approval; no action executed.",
        )
        pending_events.append(
            {
                "type": "tool.request",
                "call": {
                    "id": tool_call_id,
                    "tool": call.name,
                    "parameters": call.arguments,
                    "risk_tier": tier.value,
                    "reason": pending.reason,
                },
            }
        )
    await session.commit()
    for event in events:
        await connection_manager.send(websocket, event)
    for event in pending_events:
        await connection_manager.send(websocket, event)

    if pending_events:
        final_text = assistant_text or "A tool action is ready for your explicit approval."
        await _assistant_done(
            websocket,
            message_id,
            final_text,
            finish_reason="tool_calls",
            blocked=False,
        )
    else:
        await _assistant_done(
            websocket,
            message_id,
            assistant_text,
            finish_reason=result.finish_reason,
            blocked=False,
        )


async def _send_tool_result(
    websocket: WebSocket, tool_call_id: str, success: bool, summary: str
) -> None:
    await connection_manager.send(
        websocket,
        {
            "type": "tool.result",
            "tool_call_id": tool_call_id,
            "success": success,
            "summary": summary[:500],
        },
    )


async def _decide_tool(
    websocket: WebSocket,
    session: AsyncSession,
    principal: Principal,
    settings: Settings,
    frame: ToolDecisionFrame,
) -> None:
    pending = await session.get(PendingToolCall, frame.tool_call_id)
    if (
        pending is None
        or pending.user_id != principal.user.id
        or pending.device_id != principal.device.id
    ):
        await write_audit(
            session,
            actor_user_id=principal.user.id,
            subject_user_id=principal.user.id,
            device_id=principal.device.id,
            action="tool.decision.rejected",
            target=frame.tool_call_id,
            risk_tier="HIGH",
            outcome="DENIED",
            detail="Tool decision did not match a pending call for this device.",
        )
        await session.commit()
        await _send_tool_result(
            websocket, frame.tool_call_id, False, "Tool request is unavailable."
        )
        return
    if pending.status != "PENDING":
        await _send_tool_result(
            websocket,
            pending.id,
            pending.status == "EXECUTED",
            pending.result_summary or f"Tool request is {pending.status.lower()}.",
        )
        return

    expires_at = (
        pending.expires_at.replace(tzinfo=UTC)
        if pending.expires_at.tzinfo is None
        else pending.expires_at
    )
    if expires_at <= datetime.now(UTC):
        pending.status = "EXPIRED"
        pending.decided_at = datetime.now(UTC)
        pending.result_summary = "Tool request expired before approval."
        await write_audit(
            session,
            actor_user_id=principal.user.id,
            subject_user_id=principal.user.id,
            device_id=principal.device.id,
            action="tool.expired",
            target=pending.id,
            risk_tier=pending.risk_tier,
            outcome="DENIED",
            detail="Tool request expired before execution.",
        )
        await session.commit()
        await _send_tool_result(websocket, pending.id, False, pending.result_summary)
        return

    if not frame.approve:
        pending.status = "DENIED"
        pending.decided_at = datetime.now(UTC)
        pending.result_summary = "The user denied this tool request; no action was taken."
        await write_audit(
            session,
            actor_user_id=principal.user.id,
            subject_user_id=principal.user.id,
            device_id=principal.device.id,
            action="tool.denied",
            target=pending.id,
            risk_tier=pending.risk_tier,
            outcome="DENIED",
            detail="User explicitly denied the proposed tool action.",
        )
        await session.commit()
        await _send_tool_result(websocket, pending.id, False, pending.result_summary)
        return

    if await is_kill_switch_engaged(session):
        pending.status = "EXPIRED"
        pending.decided_at = datetime.now(UTC)
        pending.result_summary = "Kill-switch active; no action was executed."
        await session.commit()
        await _send_tool_result(websocket, pending.id, False, pending.result_summary)
        return

    tier = await derive_risk_tier(session, principal, pending.tool, pending.parameters)
    if tier.value != pending.risk_tier:
        pending.status = "EXPIRED"
        pending.decided_at = datetime.now(UTC)
        pending.result_summary = "Server-side action policy changed; request the action again."
        await write_audit(
            session,
            actor_user_id=principal.user.id,
            subject_user_id=principal.user.id,
            device_id=principal.device.id,
            action="tool.policy_changed",
            target=pending.id,
            risk_tier=tier.value,
            outcome="DENIED",
            detail="Tool request expired because its server-side risk tier changed.",
        )
        await session.commit()
        await _send_tool_result(websocket, pending.id, False, pending.result_summary)
        return

    try:
        await consume_owner_assertion(
            session,
            principal,
            frame.owner_verified,
            tier=tier,
            max_ttl_seconds=settings.owner_assertion_ttl_seconds,
        )
    except APIError as exc:
        await write_audit(
            session,
            actor_user_id=principal.user.id,
            subject_user_id=principal.user.id,
            device_id=principal.device.id,
            action="tool.verification.rejected",
            target=pending.id,
            risk_tier=tier.value,
            outcome="DENIED",
            detail="Tool execution was blocked by the signed risk policy.",
        )
        await session.commit()
        summary = "Fresh signed verification is required; no action was executed."
        if exc.code == "owner_assertion_replayed":
            summary = "This verification was already used; capture fresh evidence."
        await _send_tool_result(websocket, pending.id, False, summary)
        return

    task = asyncio.current_task()
    if task is not None:
        await execution_registry.register(task)
    try:
        if await is_kill_switch_engaged(session):
            pending.status = "EXPIRED"
            pending.decided_at = datetime.now(UTC)
            pending.result_summary = "Kill-switch active; no action was executed."
            await write_audit(
                session,
                actor_user_id=principal.user.id,
                subject_user_id=principal.user.id,
                device_id=principal.device.id,
                action="tool.cancelled",
                target=pending.id,
                risk_tier=tier.value,
                outcome="DENIED",
                detail="Kill-switch prevented execution after user confirmation.",
            )
            await session.commit()
            await _send_tool_result(websocket, pending.id, False, pending.result_summary)
            return

        pending.status = "EXECUTING"
        pending.decided_at = datetime.now(UTC)
        await write_audit(
            session,
            actor_user_id=principal.user.id,
            subject_user_id=principal.user.id,
            device_id=principal.device.id,
            action="tool.approved",
            target=pending.id,
            risk_tier=tier.value,
            outcome="SUCCESS",
            detail="User confirmed the tool action; execution started after verification.",
        )
        await session.commit()
        summary = await execute_tool(
            session,
            principal,
            settings,
            name=pending.tool,
            parameters=pending.parameters,
            tier=tier,
        )
        pending.status = "EXECUTED"
        pending.result_summary = summary[:500]
        await write_audit(
            session,
            actor_user_id=principal.user.id,
            subject_user_id=principal.user.id,
            device_id=principal.device.id,
            action="tool.result",
            target=pending.id,
            risk_tier=tier.value,
            outcome="SUCCESS",
            detail="Confirmed tool action completed.",
        )
        await session.commit()
        await _send_tool_result(websocket, pending.id, True, summary)
    except asyncio.CancelledError:

        async def record_cancellation() -> None:
            await session.rollback()
            current = await session.get(PendingToolCall, frame.tool_call_id, populate_existing=True)
            cancellation_summary = "Execution was canceled; external completion may be uncertain."
            if current is not None and current.status in {"PENDING", "EXECUTING", "EXPIRED"}:
                current.status = "EXPIRED"
                current.result_summary = cancellation_summary
                await write_audit(
                    session,
                    actor_user_id=principal.user.id,
                    subject_user_id=principal.user.id,
                    device_id=principal.device.id,
                    action="tool.cancelled",
                    target=current.id,
                    risk_tier=tier.value,
                    outcome="DENIED",
                    detail="In-flight tool task was canceled; external completion is uncertain.",
                )
                await session.commit()

        try:
            await asyncio.shield(record_cancellation())
        except Exception:
            logger.warning("Canceled tool cleanup failed; no action details logged")
        raise
    except APIError as exc:
        await session.rollback()
        current = await session.get(PendingToolCall, frame.tool_call_id, populate_existing=True)
        safe_summary = exc.message[:400]
        if current is not None and current.status == "EXECUTING":
            current.status = "EXPIRED" if exc.code == "kill_switch_active" else "FAILED"
            current.result_summary = safe_summary
            await write_audit(
                session,
                actor_user_id=principal.user.id,
                subject_user_id=principal.user.id,
                device_id=principal.device.id,
                action="tool.cancelled" if exc.code == "kill_switch_active" else "tool.result",
                target=pending.id,
                risk_tier=tier.value,
                outcome="DENIED" if exc.code == "kill_switch_active" else "FAILURE",
                detail=(
                    "Kill-switch stopped the tool before transport execution."
                    if exc.code == "kill_switch_active"
                    else "Confirmed tool execution failed; sensitive parameters omitted."
                ),
            )
            await session.commit()
        await _send_tool_result(websocket, pending.id, False, safe_summary)
    except Exception:
        await session.rollback()
        current = await session.get(PendingToolCall, frame.tool_call_id, populate_existing=True)
        if current is not None and current.status == "EXECUTING":
            current.status = "FAILED"
            current.result_summary = "Tool execution failed; sensitive details were omitted."
            await write_audit(
                session,
                actor_user_id=principal.user.id,
                subject_user_id=principal.user.id,
                device_id=principal.device.id,
                action="tool.result",
                target=current.id,
                risk_tier=tier.value,
                outcome="FAILURE",
                detail="Unexpected tool execution failure; sensitive values omitted.",
            )
            await session.commit()
            await _send_tool_result(websocket, current.id, False, current.result_summary)
    finally:
        if task is not None:
            await execution_registry.unregister(task)


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> None:
    # Trust the ASGI scheme established by the configured TLS terminator; never let a
    # caller-supplied X-Forwarded-Proto header bypass the TLS policy.
    is_secure = websocket.url.scheme.lower() in {"https", "wss"}
    if not settings.demo_insecure and not is_secure:
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

    if await is_kill_switch_engaged(session):
        await websocket.close(code=4423, reason="Kill-switch active")
        return
    now = datetime.now(UTC)
    principal.device.last_seen_at = now
    await session.commit()

    await connection_manager.connect(
        websocket,
        SocketIdentity(user_id=principal.user.id, device_id=principal.device.id),
    )
    stop_heartbeat = asyncio.Event()
    heartbeat_task = asyncio.create_task(_heartbeat(websocket, stop_heartbeat))
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
            frame_type = payload.get("type")
            try:
                if frame_type == "chat.send":
                    chat_frame = ChatSendFrame.model_validate(payload)
                    await _send_chat(websocket, session, principal, settings, chat_frame)
                elif frame_type == "tool.confirm":
                    decision_frame = ToolDecisionFrame.model_validate(payload)
                    await _decide_tool(websocket, session, principal, settings, decision_frame)
                elif frame_type == "system.heartbeat":
                    await connection_manager.send(websocket, {"type": "system.heartbeat"})
            except ValidationError:
                continue
            except APIError:
                # Public WS event shapes do not define an error frame. Keep the socket
                # alive and fail closed; no raw exception or user input is logged.
                continue
    except WebSocketDisconnect:
        pass
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.warning("WebSocket session ended unexpectedly; details omitted")
    finally:
        stop_heartbeat.set()
        heartbeat_task.cancel()
        await asyncio.gather(heartbeat_task, return_exceptions=True)
        await connection_manager.disconnect(websocket)
