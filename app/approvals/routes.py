# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
The approval prompt.

An approval is created by the Security Gateway when a HIGH-tier action (or a MEDIUM tool that
declares ``confirm=True``) is requested, and it names the exact action: tool, version, redacted
arguments, and an expiry. These endpoints let the user see it and decide.

Three properties are load-bearing and tested:

* **Only the actor decides.** An administrator cannot approve somebody else's action, and there is
  no endpoint that does so. ``require_approval_for`` looks the row up *and* checks ownership.
* **A decision is final.** Confirming is a one-way transition out of ``PENDING``; the arguments
  cannot be edited afterwards, because the hash was computed at creation from what was requested.
* **Consumption is separate from approval.** Confirming does not execute anything. Execution
  happens on the next invocation (the app retries it, or the assistant does), and at that moment
  the approval is spent atomically.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import app_settings, db_session
from app.approvals.schemas import ApprovalDecisionRequest, ApprovalListResponse, ApprovalSummary
from app.audit.service import record_event
from app.auth.dependencies import CurrentPrincipal
from app.config import Settings
from app.core.enums import ApprovalStatus, AuditOutcome
from app.core.time import utcnow
from app.db.models import Approval
from app.security.approvals import decide, list_for_actor, require_approval_for

router = APIRouter(prefix="/approvals", tags=["approvals"])


def _summary(approval: Approval) -> ApprovalSummary:
    remaining = max(0, int((approval.expires_at - utcnow()).total_seconds()))
    return ApprovalSummary(
        id=approval.id,
        tool=approval.tool_name,
        tool_version=approval.tool_version,
        risk=approval.risk.label,
        status=approval.status.value,
        summary=approval.summary,
        arguments=approval.arguments_redacted,
        created_at=approval.created_at,
        expires_at=approval.expires_at,
        seconds_remaining=remaining,
        single_use=approval.single_use,
        decided_at=approval.decided_at,
        deny_reason=approval.deny_reason,
        consumed_at=approval.consumed_at,
        trace_id=approval.trace_id,
    )


@router.get("", response_model=ApprovalListResponse)
async def list_approvals(
    principal: CurrentPrincipal,
    session: AsyncSession = Depends(db_session),
    status: str | None = Query(default=None, pattern="^(pending|approved|denied|expired)$"),
    limit: int = Query(default=50, ge=1, le=200),
) -> ApprovalListResponse:
    """The caller's own approvals, newest first."""
    parsed = ApprovalStatus(status) if status else None
    rows = await list_for_actor(
        session, actor_user_id=principal.user_id, status=parsed, limit=limit
    )
    return ApprovalListResponse(items=[_summary(row) for row in rows], total=len(rows))


@router.get("/{approval_id}", response_model=ApprovalSummary)
async def get_approval(
    approval_id: uuid.UUID,
    principal: CurrentPrincipal,
    session: AsyncSession = Depends(db_session),
) -> ApprovalSummary:
    """One approval, identified by id, scoped to the caller."""
    approval = await require_approval_for(
        session, approval_id=approval_id, actor_user_id=principal.user_id
    )
    return _summary(approval)


@router.post("/{approval_id}/confirm", response_model=ApprovalSummary)
async def confirm(
    approval_id: uuid.UUID,
    payload: ApprovalDecisionRequest,
    request: Request,
    principal: CurrentPrincipal,
    session: AsyncSession = Depends(db_session),
    settings: Settings = Depends(app_settings),
) -> ApprovalSummary:
    """
    Approve one exact action.

    Confirming does not run it: the next invocation with the same arguments (and this approval's
    id) is what executes, which means an argument that changed in between is refused rather than
    silently executed.
    """
    del settings
    approval = await require_approval_for(
        session, approval_id=approval_id, actor_user_id=principal.user_id
    )
    approval = await decide(session, approval, approve=True, reason=payload.reason)
    await record_event(
        session,
        name="approval.confirmed",
        outcome=AuditOutcome.APPROVED,
        risk=approval.risk,
        actor_user_id=principal.user_id,
        actor_role=principal.role,
        session_id=principal.session_id,
        device_id=principal.device_id,
        arguments={"tool": approval.tool_name, "approval_id": str(approval.id)},
        approval_id=approval.id,
        trace_id=getattr(request.state, "trace_id", None),
    )
    await session.commit()
    return _summary(approval)


@router.post("/{approval_id}/deny", response_model=ApprovalSummary)
async def deny(
    approval_id: uuid.UUID,
    payload: ApprovalDecisionRequest,
    request: Request,
    principal: CurrentPrincipal,
    session: AsyncSession = Depends(db_session),
) -> ApprovalSummary:
    """Refuse one exact action. Denying is recorded with the same weight as approving."""
    approval = await require_approval_for(
        session, approval_id=approval_id, actor_user_id=principal.user_id
    )
    approval = await decide(session, approval, approve=False, reason=payload.reason)
    await record_event(
        session,
        name="approval.denied",
        outcome=AuditOutcome.DENIED,
        risk=approval.risk,
        actor_user_id=principal.user_id,
        actor_role=principal.role,
        session_id=principal.session_id,
        device_id=principal.device_id,
        arguments={"tool": approval.tool_name, "approval_id": str(approval.id)},
        error_code="approval_denied",
        approval_id=approval.id,
        trace_id=getattr(request.state, "trace_id", None),
    )
    await session.commit()
    return _summary(approval)
