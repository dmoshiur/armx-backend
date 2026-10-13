# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Audit writer.

Every tool call writes exactly one row here - approved, denied, failed, dry-run or succeeded -
plus the security-relevant non-tool events (login, device link, kill-switch, admin change).

The row records the *inputs to the decision*, not only its outcome: canonical argument hash,
risk tier, registry snapshot, actor, device, session and trace id. That is what makes an
incident review possible after the fact, and what makes a denial defensible.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Select, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import stable_hash
from app.core.enums import AuditOutcome, AuditSource, Role
from app.core.redaction import redact_arguments, sanitize_untrusted_text
from app.core.risk import Risk
from app.core.time import utcnow
from app.db.models import AuditEvent

__all__ = ["audit_event_query", "count_events", "record_event"]

_MAX_SUMMARY_CHARS = 600


def _summarise(value: str | None) -> str | None:
    """Strip control characters and guarantee the column-facing length cap."""
    if not value:
        return None
    sanitised = sanitize_untrusted_text(value, max_chars=_MAX_SUMMARY_CHARS)
    return sanitised[:_MAX_SUMMARY_CHARS]


async def record_event(
    session: AsyncSession,
    *,
    name: str,
    outcome: AuditOutcome,
    risk: Risk | None = None,
    tool_version: str = "",
    actor_user_id: uuid.UUID | None = None,
    actor_role: Role | None = None,
    device_id: uuid.UUID | None = None,
    session_id: uuid.UUID | None = None,
    arguments: dict[str, Any] | None = None,
    error_code: str | None = None,
    result_summary: str | None = None,
    duration_ms: int | None = None,
    trace_id: str | None = None,
    approval_id: uuid.UUID | None = None,
    idempotency_key: str | None = None,
    registry_snapshot_id: uuid.UUID | None = None,
    ip_hash: str | None = None,
    source: AuditSource = AuditSource.API,
    dry_run: bool = False,
    occurred_at: datetime | None = None,
) -> AuditEvent:
    """
    Write one audit row.

    ``name`` is a tool name for tool calls (``set_light``) or a dotted event name for
    everything else (``auth.login``, ``device.link``, ``admin.kill_switch``).
    """
    payload = arguments or {}
    event = AuditEvent(
        occurred_at=occurred_at or utcnow(),
        actor_user_id=actor_user_id,
        actor_role=actor_role,
        device_id=device_id,
        session_id=session_id,
        tool_name=name[:64],
        tool_version=tool_version[:16],
        # A system event may have no tier; LOW is the neutral default, never HIGH.
        risk=risk or Risk.LOW,
        source=source,
        dry_run=dry_run,
        arguments_hash=stable_hash(payload),
        arguments_redacted=redact_arguments(payload),
        outcome=outcome,
        error_code=(error_code or None),
        result_summary=_summarise(result_summary),
        duration_ms=duration_ms,
        trace_id=trace_id,
        approval_id=approval_id,
        idempotency_key=idempotency_key,
        registry_snapshot_id=registry_snapshot_id,
        ip_hash=ip_hash,
    )
    session.add(event)
    await session.flush()
    return event


def audit_event_query(
    *,
    actor_user_id: uuid.UUID | None = None,
    tool_name: str | None = None,
    outcome: AuditOutcome | None = None,
    risk_at_least: Risk | None = None,
    trace_id: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    search: str | None = None,
) -> Select[AuditEvent]:
    """
    Build an audit query.

    Callers must scope ``actor_user_id`` for non-admin users: the audit API is the one place
    where a missing scope check would leak every user's activity.
    """
    statement: Select[AuditEvent] = select(AuditEvent).order_by(AuditEvent.occurred_at.desc())
    if actor_user_id is not None:
        statement = statement.where(AuditEvent.actor_user_id == actor_user_id)
    if tool_name:
        statement = statement.where(AuditEvent.tool_name == tool_name)
    if outcome:
        statement = statement.where(AuditEvent.outcome == outcome)
    if risk_at_least:
        statement = statement.where(AuditEvent.risk >= risk_at_least)
    if trace_id:
        statement = statement.where(AuditEvent.trace_id == trace_id)
    if since:
        statement = statement.where(AuditEvent.occurred_at >= since)
    if until:
        statement = statement.where(AuditEvent.occurred_at <= until)
    if search:
        pattern = f"%{search[:80]}%"
        statement = statement.where(
            or_(AuditEvent.tool_name.ilike(pattern), AuditEvent.result_summary.ilike(pattern))
        )
    return statement


async def count_events(session: AsyncSession, statement: Select[AuditEvent]) -> int:
    """Total rows matching an audit query (used for pagination)."""
    subquery = statement.with_only_columns(AuditEvent.id).order_by(None).subquery()
    return int((await session.execute(select(func.count()).select_from(subquery))).scalar() or 0)
