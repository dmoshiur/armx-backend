# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
The audit read API.

The audit trail is append-only: this module can read it and nothing anywhere can edit or delete a
row. Two scopes of access exist, and they are not the same endpoint with a flag:

* ``GET /audit`` returns *your own* activity, scoped to the authenticated account. A user id is
  never taken from the query string, so there is nothing to tamper with.
* ``GET /admin/audit`` returns everything and is Admin-only.

Both are read-only and both return redacted arguments: the raw argument bag is never stored, so
there is nothing more to leak here than a tool already saw.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session
from app.audit.service import audit_event_query, count_events
from app.auth.dependencies import CurrentPrincipal, Principal, require_admin
from app.core.enums import AuditOutcome, AuditSource, Role
from app.core.risk import Risk
from app.db.models import AuditEvent

router = APIRouter(tags=["audit"])

__all__ = ["AuditEventPage", "AuditEventView", "router"]


class AuditEventView(BaseModel):
    """One audit row, exactly as it is stored (minus the raw arguments, which are never stored)."""

    id: uuid.UUID
    occurred_at: datetime
    tool_name: str = Field(description="Tool name, or a dotted system event such as auth.login")
    tool_version: str = ""
    risk: Risk
    outcome: AuditOutcome
    source: AuditSource
    dry_run: bool = False
    actor_user_id: uuid.UUID | None = None
    actor_role: Role | None = None
    device_id: uuid.UUID | None = None
    session_id: uuid.UUID | None = None
    approval_id: uuid.UUID | None = None
    arguments_hash: str = ""
    arguments_redacted: dict[str, object] = Field(default_factory=dict)
    error_code: str | None = None
    result_summary: str | None = None
    duration_ms: int | None = None
    trace_id: str | None = None
    idempotency_key: str | None = None

    @classmethod
    def of(cls, event: AuditEvent) -> AuditEventView:
        return cls(
            id=event.id,
            occurred_at=event.occurred_at,
            tool_name=event.tool_name,
            tool_version=event.tool_version or "",
            risk=event.risk,
            outcome=event.outcome,
            source=event.source,
            dry_run=bool(event.dry_run),
            actor_user_id=event.actor_user_id,
            actor_role=event.actor_role,
            device_id=event.device_id,
            session_id=event.session_id,
            approval_id=event.approval_id,
            arguments_hash=event.arguments_hash or "",
            arguments_redacted=dict(event.arguments_redacted or {}),
            error_code=event.error_code,
            result_summary=event.result_summary,
            duration_ms=event.duration_ms,
            trace_id=event.trace_id,
            idempotency_key=event.idempotency_key,
        )


class AuditEventPage(BaseModel):
    items: list[AuditEventView]
    total: int
    limit: int
    offset: int


async def _page(
    session: AsyncSession,
    *,
    statement: Select[AuditEvent],
    limit: int,
    offset: int,
) -> AuditEventPage:
    total = await count_events(session, statement)
    rows = (await session.execute(statement.limit(limit).offset(offset))).scalars().all()
    return AuditEventPage(
        items=[AuditEventView.of(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/audit", response_model=AuditEventPage)
async def list_own_events(
    principal: CurrentPrincipal,
    session: Annotated[AsyncSession, Depends(db_session)],
    outcome: AuditOutcome | None = None,
    risk_at_least: Risk | None = None,
    tool_name: str | None = Query(default=None, max_length=64),
    trace_id: str | None = Query(default=None, max_length=64),
    since: datetime | None = None,
    until: datetime | None = None,
    search: str | None = Query(default=None, max_length=80),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> AuditEventPage:
    """The caller's own audit history, newest first."""
    statement = audit_event_query(
        actor_user_id=principal.user_id,
        tool_name=tool_name,
        outcome=outcome,
        risk_at_least=risk_at_least,
        trace_id=trace_id,
        since=since,
        until=until,
        search=search,
    )
    return await _page(session, statement=statement, limit=limit, offset=offset)


@router.get("/admin/audit", response_model=AuditEventPage, dependencies=[Depends(require_admin)])
async def list_all_events(
    session: Annotated[AsyncSession, Depends(db_session)],
    actor_user_id: uuid.UUID | None = None,
    outcome: AuditOutcome | None = None,
    risk_at_least: Risk | None = None,
    tool_name: str | None = Query(default=None, max_length=64),
    trace_id: str | None = Query(default=None, max_length=64),
    since: datetime | None = None,
    until: datetime | None = None,
    search: str | None = Query(default=None, max_length=80),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> AuditEventPage:
    """
    Every audit row, Admin only.

    Administrators read the trail; nobody writes to it. There is deliberately no update and no
    delete endpoint anywhere in the API.
    """
    statement = audit_event_query(
        actor_user_id=actor_user_id,
        tool_name=tool_name,
        outcome=outcome,
        risk_at_least=risk_at_least,
        trace_id=trace_id,
        since=since,
        until=until,
        search=search,
    )
    return await _page(session, statement=statement, limit=limit, offset=offset)


@router.get("/admin/audit/trace/{trace_id}", response_model=list[AuditEventView])
async def trace_timeline(
    trace_id: str,
    session: Annotated[AsyncSession, Depends(db_session)],
    principal: Annotated[Principal, Depends(require_admin)],
) -> list[AuditEventView]:
    """
    Every row sharing one trace id, oldest first.

    A trace id ties a whole assistant turn together - the model's requests, each gateway verdict
    and each tool result - which is what an operator needs to reconstruct an incident.
    """
    statement = (
        select(AuditEvent)
        .where(AuditEvent.trace_id == trace_id[:64])
        .order_by(AuditEvent.occurred_at.asc())
        .limit(500)
    )
    rows = (await session.execute(statement)).scalars().all()
    return [AuditEventView.of(row) for row in rows]
