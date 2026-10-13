# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
The operator console: the endpoints that belong to whoever runs the deployment.

Today that is the kill-switch. It is Admin-only, it is audited on every change, and it is
deliberately *not* protected by a tool, an approval or the model: it is a plain, small endpoint
that works even when the database is degraded, because that is precisely the situation it exists
for. Engaging it stops every tool call except the health checks named in
``KILL_SWITCH_ALLOWED_TOOLS``; the assistant keeps answering questions but cannot act.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session
from app.audit.service import record_event
from app.auth.dependencies import CurrentPrincipal, require_admin
from app.core.enums import AuditOutcome, AuditSource
from app.security.kill_switch import KillSwitch

router = APIRouter(prefix="/admin", tags=["admin"])

__all__ = ["KillSwitchRequest", "KillSwitchStatus", "router"]


class KillSwitchRequest(BaseModel):
    """A reason is required: an unexplained emergency stop is useless in a post-mortem."""

    reason: str = Field(min_length=3, max_length=200)


class KillSwitchStatus(BaseModel):
    engaged: bool
    reason: str | None = None
    updated_at: str | None = None
    updated_by: str | None = None
    allowed_tools: list[str] = Field(default_factory=list)


@router.get("/kill-switch", response_model=KillSwitchStatus, dependencies=[Depends(require_admin)])
async def kill_switch_status(
    request: Request,
    session: Annotated[AsyncSession, Depends(db_session)],
) -> KillSwitchStatus:
    """Current state. Any signed-in Admin (and the console) can read this at any time."""
    settings = request.app.state.settings
    state = await KillSwitch(settings).state(session)
    return KillSwitchStatus(
        engaged=bool(state.get("engaged")),
        reason=state.get("reason"),
        updated_at=str(state["updated_at"]) if state.get("updated_at") else None,
        updated_by=str(state["updated_by"]) if state.get("updated_by") else None,
        allowed_tools=sorted(settings.kill_switch_allowed_tool_set),
    )


@router.post(
    "/kill-switch/engage", response_model=KillSwitchStatus, dependencies=[Depends(require_admin)]
)
async def engage_kill_switch(
    payload: KillSwitchRequest,
    request: Request,
    principal: CurrentPrincipal,
    session: Annotated[AsyncSession, Depends(db_session)],
) -> KillSwitchStatus:
    """
    Stop every action in the system, immediately.

    Takes effect on the next tool call: the gateway reads the flag from the database before every
    decision, so there is no cache to wait out and no process to restart.
    """
    settings = request.app.state.settings
    switcher = KillSwitch(settings)
    state = await switcher.engage(session, actor_user_id=principal.user_id, reason=payload.reason)
    await record_event(
        session,
        name="admin.kill_switch",
        outcome=AuditOutcome.SUCCEEDED,
        actor_user_id=principal.user_id,
        actor_role=principal.role,
        session_id=principal.session_id,
        device_id=principal.device_id,
        arguments={"engaged": True, "reason": payload.reason},
        result_summary="kill-switch engaged",
        trace_id=getattr(request.state, "trace_id", None),
        source=AuditSource.API,
    )
    await session.commit()
    return KillSwitchStatus(
        engaged=True,
        reason=state.get("reason") or payload.reason,
        updated_at=str(state["updated_at"]) if state.get("updated_at") else None,
        updated_by=str(principal.user_id),
        allowed_tools=sorted(settings.kill_switch_allowed_tool_set),
    )


@router.post(
    "/kill-switch/disengage", response_model=KillSwitchStatus, dependencies=[Depends(require_admin)]
)
async def disengage_kill_switch(
    payload: KillSwitchRequest,
    request: Request,
    principal: CurrentPrincipal,
    session: Annotated[AsyncSession, Depends(db_session)],
) -> KillSwitchStatus:
    """Release the stop. The reason is recorded next to the one that engaged it."""
    settings = request.app.state.settings
    switcher = KillSwitch(settings)
    state = await switcher.disengage(
        session, actor_user_id=principal.user_id, reason=payload.reason
    )
    await record_event(
        session,
        name="admin.kill_switch",
        outcome=AuditOutcome.SUCCEEDED,
        actor_user_id=principal.user_id,
        actor_role=principal.role,
        session_id=principal.session_id,
        device_id=principal.device_id,
        arguments={"engaged": False, "reason": payload.reason},
        result_summary="kill-switch released",
        trace_id=getattr(request.state, "trace_id", None),
        source=AuditSource.API,
    )
    await session.commit()
    return KillSwitchStatus(
        engaged=False,
        reason=state.get("reason") or payload.reason,
        updated_at=str(state["updated_at"]) if state.get("updated_at") else None,
        updated_by=str(principal.user_id),
        allowed_tools=sorted(settings.kill_switch_allowed_tool_set),
    )
