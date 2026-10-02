# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import re
from datetime import datetime
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.auth.dependencies import Principal, public_device_id, public_user_id
from app.db.models import AuditLog, Device, User

_FORBIDDEN_AUDIT_KEY = re.compile(
    r"token|secret|password|credential|authorization|face|voice|biometric|embedding|template|audio|pcm",
    re.IGNORECASE,
)


def _safe_metadata(values: dict[str, Any] | None) -> dict[str, str]:
    safe: dict[str, str] = {}
    for key, value in (values or {}).items():
        if _FORBIDDEN_AUDIT_KEY.search(key):
            continue
        if isinstance(value, (str, int, float, bool)):
            safe[key[:48]] = str(value)[:120]
    return safe


async def write_audit(
    session: AsyncSession,
    *,
    actor_user_id: Any | None,
    subject_user_id: Any | None = None,
    device_id: Any | None = None,
    action: str,
    target: str = "",
    risk_tier: str = "LOW",
    outcome: str = "SUCCESS",
    detail: str = "",
    metadata: dict[str, Any] | None = None,
) -> AuditLog:
    """Append a sanitized audit row; this service never updates or deletes rows."""

    entry = AuditLog(
        actor_user_id=actor_user_id,
        subject_user_id=subject_user_id,
        device_id=device_id,
        action=action[:120],
        target=target[:180],
        risk_tier=risk_tier.upper() if risk_tier.upper() in {"LOW", "MEDIUM", "HIGH"} else "HIGH",
        outcome=outcome.upper()
        if outcome.upper() in {"SUCCESS", "FAILURE", "DENIED"}
        else "FAILURE",
        detail=detail[:500],
        metadata_json=_safe_metadata(metadata),
    )
    session.add(entry)
    return entry


async def query_audit(
    session: AsyncSession,
    principal: Principal,
    *,
    from_at: datetime | None = None,
    to_at: datetime | None = None,
    risk_tier: str | None = None,
    outcome: str | None = None,
    actor: str = "",
    search: str = "",
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    actor_user = aliased(User)
    subject_user = aliased(User)
    audit_device = aliased(Device)
    statement = (
        select(AuditLog, actor_user, subject_user, audit_device)
        .outerjoin(actor_user, AuditLog.actor_user_id == actor_user.id)
        .outerjoin(subject_user, AuditLog.subject_user_id == subject_user.id)
        .outerjoin(audit_device, AuditLog.device_id == audit_device.id)
    )
    is_admin = bool(
        {role.lower() for role in principal.user.roles}.intersection({"admin", "owner"})
    )
    if not is_admin:
        statement = statement.where(
            or_(
                AuditLog.actor_user_id == principal.user.id,
                AuditLog.subject_user_id == principal.user.id,
            )
        )
    filters = []
    if from_at is not None:
        filters.append(AuditLog.created_at >= from_at)
    if to_at is not None:
        filters.append(AuditLog.created_at <= to_at)
    if risk_tier:
        filters.append(AuditLog.risk_tier == risk_tier.upper())
    if outcome:
        filters.append(AuditLog.outcome == outcome.upper())
    if actor:
        filters.append(
            or_(
                actor_user.username.ilike(f"%{actor}%"), actor_user.display_name.ilike(f"%{actor}%")
            )
        )
    if search:
        filters.append(
            or_(
                AuditLog.action.ilike(f"%{search}%"),
                AuditLog.target.ilike(f"%{search}%"),
                AuditLog.detail.ilike(f"%{search}%"),
            )
        )
    if filters:
        statement = statement.where(and_(*filters))
    statement = statement.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit)
    rows = (await session.execute(statement)).all()
    return [
        {
            "id": f"aud-{entry.id.hex[:8]}",
            "at": entry.created_at,
            "actor": (user.display_name or user.username) if user else "system",
            "action": entry.action,
            "target": entry.target,
            "risk_tier": entry.risk_tier,
            "outcome": entry.outcome,
            "detail": entry.detail,
            "device_id": public_device_id(device) if device else None,
            "metadata": entry.metadata_json,
            # Admins can see the specific subject of an audit row. An ordinary user
            # sees their own public ID only, never another participant's identity.
            "subject_user_id": (
                public_user_id(subject)
                if subject is not None and (is_admin or subject.id == principal.user.id)
                else None
            ),
        }
        for entry, user, subject, device in rows
    ]
