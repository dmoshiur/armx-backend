# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Approvals for the actions that require one.

An approval is bound to the exact action, not to the tool. The hash covers the tool name and
version, the canonical arguments, the actor, the device, the session, the approval nonce and the
expiry, so:

* changing any argument invalidates it (recompute the hash and it no longer matches),
* replaying it on another device or session fails,
* it cannot be used twice - consumption is an atomic compare-and-set,
* it stops working when it expires.

The nonce is stored in ``approvals.nonce`` (unique) and its hash is also recorded in
``used_nonces``, which is what makes a replayed approval a database-level failure rather than a
code-path that has to remember to check.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.core.crypto import new_nonce, sha256_hex, to_canonical_json
from app.core.enums import ApprovalStatus, AuditOutcome, AuditSource
from app.core.errors import APIError, ErrorCode
from app.core.logging import get_logger
from app.core.metrics import inc
from app.core.redaction import redact_arguments
from app.core.risk import Risk
from app.core.time import isoformat_z, utcnow
from app.db.models import Approval, AuditEvent, UsedNonce

__all__ = [
    "ApprovalPolicy",
    "action_hash",
    "consume",
    "create_approval",
    "decide",
    "expire_stale",
    "get_approval",
    "list_for_actor",
    "summarise_arguments",
]

logger = get_logger("security.approvals")


@dataclass(frozen=True, slots=True)
class ApprovalPolicy:
    """The facts an approval is bound to."""

    tool_name: str
    tool_version: str
    arguments: dict[str, object]
    actor_user_id: uuid.UUID | None
    device_id: uuid.UUID | None
    session_id: uuid.UUID | None
    nonce: str
    expires_at: str


def action_hash(policy: ApprovalPolicy) -> str:
    """
    Canonical hash of the exact action.

    ``to_canonical_json`` sorts keys and normalises scalars, so two identical requests produce
    the same hash regardless of key order or int/float spelling.
    """
    payload = {
        "tool": policy.tool_name,
        "version": policy.tool_version,
        "arguments": policy.arguments,
        "actor": str(policy.actor_user_id) if policy.actor_user_id else None,
        "device": str(policy.device_id) if policy.device_id else None,
        "session": str(policy.session_id) if policy.session_id else None,
        "nonce": policy.nonce,
        "expires_at": policy.expires_at,
    }
    return sha256_hex(to_canonical_json(payload))


def summarise_arguments(arguments: dict[str, object], *, limit: int = 300) -> str:
    """Short, redacted, human-readable summary shown on the approval prompt."""
    redacted = redact_arguments(arguments)
    parts = [f"{key}={value!r}" for key, value in sorted(redacted.items())]
    text = ", ".join(parts) if parts else "no arguments"
    return text[:limit]


async def create_approval(
    session: AsyncSession,
    settings: Settings,
    *,
    tool_name: str,
    tool_version: str,
    risk: Risk,
    arguments: dict[str, object],
    actor_user_id: uuid.UUID | None,
    device_id: uuid.UUID | None,
    session_id: uuid.UUID | None,
    trace_id: str | None = None,
    idempotency_key: str | None = None,
    registry_snapshot_id: uuid.UUID | None = None,
    ttl_seconds: int | None = None,
) -> Approval:
    """
    Create a pending approval for one exact action.

    Only ``actor_user_id`` may later confirm or deny it: a HIGH action is approved by the person
    it affects, not by whoever happens to be an administrator.
    """
    if actor_user_id is None:
        # A device or automation principal cannot self-approve, so a HIGH action from one is
        # impossible by construction.
        raise APIError(
            ErrorCode.APPROVAL_REQUIRED,
            "This action requires a signed-in user to approve it",
            status_code=403,
        )

    now = utcnow()
    expires_at = now + timedelta(seconds=ttl_seconds or settings.approval_ttl_seconds)
    nonce = new_nonce()

    pending = int(
        (
            await session.execute(
                select(func.count(Approval.id)).where(
                    Approval.actor_user_id == actor_user_id,
                    Approval.status == ApprovalStatus.PENDING,
                    Approval.expires_at > now,
                )
            )
        ).scalar()
        or 0
    )
    if pending >= settings.approval_max_pending_per_user:
        raise APIError(
            ErrorCode.RATE_LIMITED,
            "Too many approvals are waiting for a decision; resolve them first",
            status_code=429,
        )

    policy = ApprovalPolicy(
        tool_name=tool_name,
        tool_version=tool_version,
        arguments=arguments,
        actor_user_id=actor_user_id,
        device_id=device_id,
        session_id=session_id,
        nonce=nonce,
        expires_at=isoformat_z(expires_at),
    )
    approval = Approval(
        tool_name=tool_name,
        tool_version=tool_version,
        risk=risk,
        action_hash=action_hash(policy),
        arguments_hash=sha256_hex(to_canonical_json(arguments)),
        arguments_redacted=redact_arguments(arguments),
        summary=summarise_arguments(arguments),
        actor_user_id=actor_user_id,
        device_id=device_id,
        session_id=session_id,
        trace_id=trace_id,
        nonce=nonce,
        status=ApprovalStatus.PENDING,
        single_use=True,
        created_at=now,
        expires_at=expires_at,
        idempotency_key=idempotency_key,
        registry_snapshot_id=registry_snapshot_id,
    )
    session.add(approval)
    await session.flush()
    inc("approvals_created", {"risk": risk.label})
    return approval


async def get_approval(session: AsyncSession, approval_id: uuid.UUID) -> Approval | None:
    return (
        (await session.execute(select(Approval).where(Approval.id == approval_id)))
        .scalars()
        .one_or_none()
    )


async def require_approval_for(
    session: AsyncSession, *, approval_id: uuid.UUID, actor_user_id: uuid.UUID
) -> Approval:
    """Load an approval, insisting that it belongs to the caller."""
    approval = await get_approval(session, approval_id)
    if approval is None or approval.actor_user_id != actor_user_id:
        raise APIError.not_found("Approval not found")
    return approval


async def decide(
    session: AsyncSession,
    approval: Approval,
    *,
    approve: bool,
    reason: str | None = None,
) -> Approval:
    """
    Record the user's decision on a pending approval.

    Only a *pending, unexpired* approval can be decided; anything else is reported as such
    instead of being silently overwritten.
    """
    now = utcnow()
    if approval.consumed_at is not None:
        raise APIError(
            ErrorCode.APPROVAL_ALREADY_USED,
            "This action has already been carried out",
            status_code=409,
        )
    if approval.status is ApprovalStatus.DENIED:
        raise APIError(ErrorCode.APPROVAL_DENIED, "This action was denied", status_code=409)
    if approval.status is not ApprovalStatus.PENDING:
        raise APIError(
            ErrorCode.APPROVAL_INVALID, "This approval can no longer be decided", status_code=409
        )
    if approval.expires_at <= now:
        approval.status = ApprovalStatus.EXPIRED
        await session.flush()
        raise APIError(ErrorCode.APPROVAL_EXPIRED, "This approval has expired", status_code=409)

    approval.status = ApprovalStatus.APPROVED if approve else ApprovalStatus.DENIED
    approval.decided_at = now
    approval.decided_by_user_id = approval.actor_user_id
    approval.deny_reason = (reason or "")[:200] or None
    await session.flush()
    inc("approvals_decided", {"decision": "approved" if approve else "denied"})
    return approval


async def consume(
    session: AsyncSession,
    approval: Approval,
    *,
    expected_action_hash: str,
    expected_tool: str,
) -> Approval:
    """
    Mark an approved action as carried out, atomically.

    The ``UPDATE ... WHERE status = 'approved' AND consumed_at IS NULL`` is the check: two
    concurrent executions of the same approval cannot both succeed, and a changed argument set
    (different hash) is refused rather than executed.
    """
    now = utcnow()
    if approval.expires_at <= now:
        raise APIError(ErrorCode.APPROVAL_EXPIRED, "This approval has expired", status_code=409)
    if approval.tool_name != expected_tool:
        raise APIError(
            ErrorCode.APPROVAL_ARGUMENT_MISMATCH,
            "This approval was granted for a different action",
            status_code=409,
        )
    if approval.action_hash != expected_action_hash:
        raise APIError(
            ErrorCode.APPROVAL_ARGUMENT_MISMATCH,
            "The arguments changed after approval; request a new one",
            status_code=409,
        )

    result = await session.execute(
        update(Approval)
        .where(
            Approval.id == approval.id,
            Approval.status == ApprovalStatus.APPROVED,
            Approval.consumed_at.is_(None),
        )
        .values(consumed_at=now)
        .returning(Approval.id)
    )
    if result.first() is None:
        await session.rollback()
        raise APIError(
            ErrorCode.APPROVAL_ALREADY_USED, "This approval has already been used", status_code=409
        )

    # Belt and braces: the nonce is also recorded as used, so a replay fails at the database
    # level even if some other code path ever forgets to go through this function.
    session.add(
        UsedNonce(
            nonce_hash=sha256_hex(approval.nonce),
            scope=f"approval:{approval.tool_name}"[:48],
            created_at=now,
            expires_at=approval.expires_at + timedelta(hours=1),
        )
    )
    await session.flush()
    await session.refresh(approval)
    inc("approvals_consumed")
    return approval


async def list_for_actor(
    session: AsyncSession,
    *,
    actor_user_id: uuid.UUID,
    status: ApprovalStatus | None = None,
    limit: int = 50,
) -> list[Approval]:
    """The caller's own approvals, newest first."""
    statement = select(Approval).where(Approval.actor_user_id == actor_user_id)
    if status is not None:
        statement = statement.where(Approval.status == status)
    statement = statement.order_by(Approval.created_at.desc()).limit(limit)
    return list((await session.execute(statement)).scalars().all())


async def expire_stale(session: AsyncSession, *, limit: int = 500) -> int:
    """
    Expire approvals whose window has closed, and leave evidence of each one.

    Called by the maintenance loop. An expired approval is not garbage: it is the record of an
    action the user was asked about and never answered, so the row survives and gets an audit
    entry of its own. Bounded by ``limit`` so a backlog drains over several passes instead of
    holding a long transaction while the API is serving.
    """
    now = utcnow()
    stale = (
        (
            await session.execute(
                select(Approval)
                .where(
                    Approval.status.in_([ApprovalStatus.PENDING, ApprovalStatus.APPROVED]),
                    Approval.expires_at < now,
                )
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    for approval in stale:
        approval.status = ApprovalStatus.EXPIRED
        approval.decided_at = now
        approval.deny_reason = approval.deny_reason or "expired before a decision"
        session.add(
            AuditEvent(
                occurred_at=now,
                actor_user_id=approval.actor_user_id,
                device_id=approval.device_id,
                session_id=approval.session_id,
                tool_name=approval.tool_name,
                tool_version=approval.tool_version,
                risk=approval.risk,
                source=AuditSource.SYSTEM,
                dry_run=False,
                arguments_hash=approval.arguments_hash,
                arguments_redacted=approval.arguments_redacted,
                outcome=AuditOutcome.CANCELLED,
                error_code=ErrorCode.APPROVAL_EXPIRED,
                result_summary="approval expired without a decision",
                trace_id=approval.trace_id,
                approval_id=approval.id,
                registry_snapshot_id=approval.registry_snapshot_id,
            )
        )
    await session.flush()
    count = len(stale)
    if count:
        logger.info("expired %d stale approvals", count)
        inc("approvals_expired", {"count": str(count)})
    return count
