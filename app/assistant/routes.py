# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
The assistant endpoint.

One request runs one bounded turn: the model may propose tool calls, each of which is decided by
the Security Gateway, and the transcript of what actually happened comes back in ``events``.

The response is the same whether the caller asked for a single turn or streamed it over the
WebSocket - both go through :func:`app.harness.runner.run_turn`. The events carry no secrets: tool
results are the tool's own output, and an argument that looks like a credential is redacted before
it is echoed anywhere.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    actor_for,
    app_llm,
    app_registry,
    app_settings,
    db_session,
)
from app.assistant.schemas import AssistantEvent, AssistantMessageRequest, AssistantMessageResponse
from app.audit.service import record_event
from app.auth.dependencies import CurrentPrincipal
from app.config import Settings
from app.core.enums import AuditOutcome, AuditSource
from app.core.time import utcnow
from app.harness.runner import run_turn
from app.llm.base import LLMProvider
from app.registry.core import ToolRegistry

router = APIRouter(prefix="/assistant", tags=["assistant"])


@router.post("/message", response_model=AssistantMessageResponse)
async def send_message(
    payload: AssistantMessageRequest,
    request: Request,
    principal: CurrentPrincipal,
    session: AsyncSession = Depends(db_session),
    settings: Settings = Depends(app_settings),
    provider: LLMProvider = Depends(app_llm),
    registry: ToolRegistry = Depends(app_registry),
) -> AssistantMessageResponse:
    """Send one user message and get the model's answer plus what it actually did."""
    started = utcnow()
    turn = await run_turn(
        session,
        settings=settings,
        provider=provider,
        registry=registry,
        actor=actor_for(principal),
        user_message=payload.text,
        history=[message.model_dump() for message in payload.history],
        device_id=principal.device_id,
        session_id=principal.session_id,
        trace_id=getattr(request.state, "trace_id", None),
        ip_address=request.client.host if request.client else None,
        dry_run=payload.dry_run,
    )

    await record_event(
        session,
        name="assistant.turn",
        outcome=AuditOutcome.SUCCEEDED if turn.status == "completed" else AuditOutcome.FAILED,
        actor_user_id=principal.user_id,
        actor_role=principal.role,
        session_id=principal.session_id,
        device_id=principal.device_id,
        arguments={
            "chars": len(payload.text),
            "dry_run": payload.dry_run,
            "history": len(payload.history),
        },
        error_code=turn.error_code,
        result_summary=(
            f"status={turn.status} tool_calls={turn.tool_calls} model_turns={turn.model_turns}"
        ),
        duration_ms=turn.duration_ms,
        trace_id=getattr(request.state, "trace_id", None),
        source=AuditSource.API,
        occurred_at=started,
    )
    await session.commit()

    return AssistantMessageResponse(
        status=turn.status,
        reply=turn.reply,
        events=[AssistantEvent(type=event.type, data=event.data) for event in turn.events],
        tool_calls=turn.tool_calls,
        model_turns=turn.model_turns,
        pending_approvals=turn.pending_approvals,
        error_code=turn.error_code,
        duration_ms=turn.duration_ms,
        usage=turn.usage,
    )
