# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Streaming assistant over a WebSocket.

The client sends a message, the server streams events as they happen (``text`` while the model is
composing, ``tool_call`` when it proposes an action, ``approval_required`` when a HIGH-tier action
is waiting for the user, ``tool_result``, then ``final``).

Authentication happens on the first frame, not only at connect time: browsers cannot set headers on
a WebSocket handshake, so the token arrives as a query parameter or in the first ``auth`` frame,
and it is verified by the same code path the REST API uses. Everything the socket can do is a
subset of the REST surface - it is a transport, not a new privilege.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import actor_for, app_registry, app_settings
from app.audit.service import record_event
from app.auth.dependencies import Principal
from app.auth.tokens import TokenError, decode_access_token
from app.config import Settings
from app.core.enums import AuditOutcome, AuditSource
from app.core.errors import ErrorCode
from app.core.logging import get_logger
from app.db.models import Session, User
from app.db.session import get_sessionmaker
from app.harness.runner import run_turn
from app.llm.factory import build_provider
from app.registry.core import ToolRegistry

logger = get_logger("assistant.ws")

router = APIRouter(tags=["assistant"])

_MAX_FRAME_BYTES = 64 * 1024


@router.websocket("/assistant/stream")
async def assistant_stream(websocket: WebSocket) -> None:
    """Stream one turn at a time over a persistent connection."""
    settings: Settings = app_settings(websocket)  # type: ignore[arg-type]
    registry: ToolRegistry = app_registry(websocket)  # type: ignore[arg-type]
    await websocket.accept()

    principal: Principal | None = None
    session: AsyncSession | None = None
    try:
        session = await _open_session(settings)
        principal = await _authenticate(websocket, session, settings)
        if principal is None:
            await websocket.send_json(
                {
                    "type": "error",
                    "error": {
                        "code": ErrorCode.UNAUTHENTICATED,
                        "message": "Send an auth frame with a valid access token first",
                    },
                }
            )
            await websocket.close(code=4401)
            return

        provider = build_provider(settings)
        await websocket.send_json(
            {
                "type": "ready",
                "user": {"id": str(principal.user_id), "role": principal.role.value},
            }
        )

        while True:
            raw = await websocket.receive_text()
            if len(raw) > _MAX_FRAME_BYTES:
                await websocket.send_json(
                    {
                        "type": "error",
                        "error": {
                            "code": ErrorCode.PAYLOAD_TOO_LARGE,
                            "message": "Frame is too large",
                        },
                    }
                )
                continue
            frame = _parse_frame(raw)
            frame_type = frame.get("type")

            if frame_type == "ping":
                await websocket.send_json({"type": "pong"})
                continue
            if frame_type == "auth":
                principal = await _authenticate(websocket, session, settings, frame=frame)
                await websocket.send_json(
                    {
                        "type": "ready" if principal else "error",
                        **({} if principal else {"error": {"code": ErrorCode.UNAUTHENTICATED}}),
                    }
                )
                continue
            if frame_type != "message":
                await websocket.send_json(
                    {
                        "type": "error",
                        "error": {
                            "code": ErrorCode.INVALID_REQUEST,
                            "message": "Unsupported frame type",
                        },
                    }
                )
                continue

            text = str(frame.get("text") or "").strip()
            if not text or len(text) > 8000:
                await websocket.send_json(
                    {
                        "type": "error",
                        "error": {
                            "code": ErrorCode.INVALID_REQUEST,
                            "message": "Message must be 1-8000 characters",
                        },
                    }
                )
                continue

            async def emit(event_type: str, data: dict[str, Any]) -> None:
                await websocket.send_json(
                    {"type": "event", "event": {"type": event_type, "data": data}}
                )

            turn = await run_turn(
                session,
                settings=settings,
                provider=provider,
                registry=registry,
                actor=actor_for(principal),
                user_message=text,
                history=frame.get("history") if isinstance(frame.get("history"), list) else [],
                device_id=principal.device_id,
                session_id=principal.session_id,
                trace_id=_trace_id(websocket),
                ip_address=websocket.client.host if websocket.client else None,
                dry_run=bool(frame.get("dry_run")),
                emit=emit,
            )
            await record_event(
                session,
                name="assistant.turn",
                outcome=(
                    AuditOutcome.SUCCEEDED if turn.status == "completed" else AuditOutcome.FAILED
                ),
                actor_user_id=principal.user_id,
                actor_role=principal.role,
                session_id=principal.session_id,
                device_id=principal.device_id,
                arguments={"chars": len(text), "transport": "websocket"},
                error_code=turn.error_code,
                result_summary=f"status={turn.status} tool_calls={turn.tool_calls}",
                duration_ms=turn.duration_ms,
                trace_id=_trace_id(websocket),
                source=AuditSource.API,
            )
            await session.commit()
            await websocket.send_json(
                {
                    "type": "done",
                    "turn": {
                        "status": turn.status,
                        "reply": turn.reply,
                        "tool_calls": turn.tool_calls,
                        "model_turns": turn.model_turns,
                        "pending_approvals": [str(item) for item in turn.pending_approvals],
                        "error_code": turn.error_code,
                        "duration_ms": turn.duration_ms,
                    },
                }
            )
    except WebSocketDisconnect:
        logger.info("assistant socket disconnected")
    except Exception as exc:
        logger.exception("assistant socket failed: %s", type(exc).__name__)
        try:
            await websocket.send_json(
                {
                    "type": "error",
                    "error": {
                        "code": ErrorCode.INTERNAL_ERROR,
                        "message": "The assistant stream stopped unexpectedly",
                    },
                }
            )
            await websocket.close(code=1011)
        except Exception:
            logger.debug("could not report the socket failure")
    finally:
        if session is not None:
            await session.close()


async def _open_session(settings: Settings) -> AsyncSession:
    factory = await get_sessionmaker(settings)
    return factory()


async def _authenticate(
    websocket: WebSocket,
    session: AsyncSession,
    settings: Settings,
    *,
    frame: dict[str, Any] | None = None,
) -> Principal | None:
    """
    Resolve the caller from a query parameter or an auth frame.

    The checks mirror the REST dependency exactly - account active, session epoch current, session
    not revoked - so a socket cannot outlive a logout.
    """
    token = str(websocket.query_params.get("token") or "").strip()
    if not token and frame:
        token = str(frame.get("token") or "").strip()
    if not token:
        return None
    try:
        claims = decode_access_token(settings, token)
    except TokenError:
        return None

    user = (
        (await session.execute(select(User).where(User.id == claims.subject)))
        .scalars()
        .one_or_none()
    )
    if user is None or not user.is_active or claims.session_epoch != user.session_epoch:
        return None
    if claims.session_id is not None:
        row = (
            (await session.execute(select(Session).where(Session.id == claims.session_id)))
            .scalars()
            .one_or_none()
        )
        if row is None or row.revoked_at is not None or row.user_id != user.id:
            return None

    from app.auth.scopes import scopes_for_role

    return Principal(
        user=user,
        session_id=claims.session_id,
        device_id=claims.device_id,
        claims=claims,
        scopes=scopes_for_role(user.role),
        source="websocket",
    )


def _parse_frame(raw: str) -> dict[str, Any]:
    import json

    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {"type": "invalid"}
    return parsed if isinstance(parsed, dict) else {"type": "invalid"}


def _trace_id(websocket: WebSocket) -> str:
    return str(getattr(websocket.state, "trace_id", "") or uuid.uuid4().hex[:16])
