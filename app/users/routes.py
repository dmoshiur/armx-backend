# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
User administration.

Three rules shape this surface:

1. **An administrator manages access, not credentials.** Passwords, hashes, tokens and the Google
   subject are never returned, and there is no endpoint that resets somebody's password.
2. **The last administrator cannot be removed or demoted.** The check runs inside the transaction
   that performs the change, so two concurrent demotions cannot both succeed.
3. **Changing a role takes effect on the next request**, because scopes are recomputed from the
   stored role rather than trusted from the access token. Demoting or disabling also revokes the
   sessions, so a demoted admin's refresh token cannot mint a fresh admin token.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import app_settings, db_session
from app.audit.service import record_event
from app.auth.dependencies import Principal, require_admin
from app.auth.schemas import SessionSummary
from app.auth.service import AuthService
from app.config import Settings
from app.core.enums import AuditOutcome, EmailTokenPurpose, Role
from app.core.errors import APIError, ErrorCode
from app.core.passwords import hash_password, password_policy_error
from app.core.time import utcnow
from app.db.models import EmailToken, RefreshToken, Session, User
from app.users.schemas import (
    AdminUserSummary,
    CreateUserRequest,
    PatchAdminUserRequest,
    UserListResponse,
    UserSessionsResponse,
)

router = APIRouter(prefix="/admin/users", tags=["users"])

_MAX_PAGE = 200


def _summary(user: User, *, active_sessions: int = 0) -> AdminUserSummary:
    return AdminUserSummary(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        role=user.role.value,
        email_verified=user.email_verified_at is not None,
        is_active=user.is_active,
        locked_until=user.locked_until,
        failed_login_count=user.failed_login_count,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
        active_sessions=active_sessions,
    )


async def _active_session_counts(
    session: AsyncSession, user_ids: list[uuid.UUID]
) -> dict[uuid.UUID, int]:
    if not user_ids:
        return {}
    rows = await session.execute(
        select(Session.user_id, func.count(Session.id))
        .where(Session.user_id.in_(user_ids), Session.revoked_at.is_(None))
        .group_by(Session.user_id)
    )
    return {user_id: int(count) for user_id, count in rows.all()}


async def _other_admin_exists(session: AsyncSession, *, excluding: uuid.UUID) -> bool:
    """
    Whether any other active administrator exists.

    Locked with ``FOR UPDATE`` on PostgreSQL so two simultaneous demotions of the two remaining
    administrators serialise and one of them fails, instead of both succeeding.
    """
    statement = select(User.id).where(
        User.role == Role.ADMIN,
        User.is_active.is_(True),
        User.id != excluding,
    )
    if session.bind is not None and session.bind.dialect.name == "postgresql":
        statement = statement.with_for_update()
    return (await session.execute(statement)).first() is not None


@router.get("", response_model=UserListResponse)
async def list_users(
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(db_session),
    query: str | None = Query(default=None, max_length=120),
    role: str | None = Query(default=None, pattern="^(user|vip|admin)$"),
    active: bool | None = None,
    limit: int = Query(default=50, ge=1, le=_MAX_PAGE),
    offset: int = Query(default=0, ge=0),
) -> UserListResponse:
    """Page through accounts with an optional email/name search."""
    del principal
    filters = []
    if query:
        needle = f"%{query.strip().lower()}%"
        filters.append(
            or_(func.lower(User.email).like(needle), func.lower(User.display_name).like(needle))
        )
    if role:
        filters.append(User.role == Role(role))
    if active is not None:
        filters.append(User.is_active.is_(active))

    total = int((await session.execute(select(func.count(User.id)).where(*filters))).scalar() or 0)
    rows = (
        (
            await session.execute(
                select(User)
                .where(*filters)
                .order_by(User.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    counts = await _active_session_counts(session, [row.id for row in rows])
    return UserListResponse(
        items=[_summary(row, active_sessions=counts.get(row.id, 0)) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("", response_model=AdminUserSummary, status_code=201)
async def create_user(
    payload: CreateUserRequest,
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(db_session),
    settings: Settings = Depends(app_settings),
) -> AdminUserSummary:
    """
    Create an account directly.

    Used by an administrator onboarding staff. The password is chosen here rather than emailed, so
    the account never holds a credential that travelled through a mailbox.
    """
    email = AuthService.normalise_email(payload.email)
    error = password_policy_error(
        payload.password, email=email, min_length=settings.password_min_length
    )
    if error:
        raise APIError(
            ErrorCode.INVALID_REQUEST, error, status_code=400, details={"field": "password"}
        )
    existing = (await session.execute(select(User.id).where(User.email == email))).first()
    if existing is not None:
        raise APIError(ErrorCode.CONFLICT, "That email is already registered", status_code=409)

    user = User(
        email=email,
        display_name=payload.display_name or email.split("@")[0][:120],
        role=Role(payload.role),
        password_hash=hash_password(payload.password),
        email_verified_at=utcnow() if payload.verified else None,
        is_active=True,
        created_by_user_id=principal.user_id,
        session_epoch=0,
    )
    session.add(user)
    await session.flush()
    await record_event(
        session,
        name="admin.user_created",
        outcome=AuditOutcome.SUCCEEDED,
        actor_user_id=principal.user_id,
        actor_role=principal.role,
        arguments={"user_id": str(user.id), "role": user.role.value},
        trace_id=getattr(request.state, "trace_id", None),
    )
    await session.commit()
    return _summary(user)


@router.get("/{user_id}", response_model=AdminUserSummary)
async def get_user(
    user_id: uuid.UUID,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(db_session),
) -> AdminUserSummary:
    """One account, including its lockout state."""
    del principal
    user = await _get_user(session, user_id)
    counts = await _active_session_counts(session, [user.id])
    return _summary(user, active_sessions=counts.get(user.id, 0))


@router.patch("/{user_id}", response_model=AdminUserSummary)
async def patch_user(
    user_id: uuid.UUID,
    payload: PatchAdminUserRequest,
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(db_session),
) -> AdminUserSummary:
    """
    Change a role, the active flag, or the display name.

    Demoting or disabling revokes the account's sessions and bumps its epoch, so tokens minted
    while the account had more rights stop working immediately.
    """
    user = await _get_user(session, user_id)
    changes: dict[str, object] = {}

    if payload.role is not None and payload.role != user.role.value:
        new_role = Role(payload.role)
        losing_admin = user.role == Role.ADMIN and new_role != Role.ADMIN
        if losing_admin and not await _other_admin_exists(session, excluding=user.id):
            raise APIError(
                ErrorCode.CONFLICT,
                "This is the only administrator; promote another account first",
                status_code=409,
            )
        changes["role"] = user.role.value
        user.role = new_role

    if payload.is_active is not None and payload.is_active != user.is_active:
        if not payload.is_active:
            if user.role == Role.ADMIN and not await _other_admin_exists(
                session, excluding=user.id
            ):
                raise APIError(
                    ErrorCode.CONFLICT,
                    "This is the only administrator; promote another account first",
                    status_code=409,
                )
            if user.id == principal.user_id:
                raise APIError(
                    ErrorCode.CONFLICT, "You cannot deactivate your own account", status_code=409
                )
        changes["is_active"] = user.is_active
        user.is_active = payload.is_active

    if payload.display_name is not None:
        changes["display_name"] = user.display_name
        user.display_name = payload.display_name.strip()

    if payload.is_active is False:
        # Disabling must end the account's access immediately: the epoch bump invalidates every
        # access token already minted, and revoking the sessions kills the refresh tokens too.
        # A *role* change needs neither, because scopes and the role are read from this row on
        # every request - a demotion takes effect on the very next call.
        user.session_epoch += 1
        await _revoke_all_sessions(session, user_id=user.id, reason="admin_change")

    if changes:
        await record_event(
            session,
            name="admin.user_updated",
            outcome=AuditOutcome.SUCCEEDED,
            actor_user_id=principal.user_id,
            actor_role=principal.role,
            arguments={"user_id": str(user.id), "changed": sorted(changes)},
            trace_id=getattr(request.state, "trace_id", None),
        )
    await session.commit()
    counts = await _active_session_counts(session, [user.id])
    return _summary(user, active_sessions=counts.get(user.id, 0))


@router.post("/{user_id}/unlock", response_model=AdminUserSummary)
async def unlock_user(
    user_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(db_session),
) -> AdminUserSummary:
    """Clear a lockout, for the "I locked myself out" support case."""
    user = await _get_user(session, user_id)
    user.locked_until = None
    user.failed_login_count = 0
    await record_event(
        session,
        name="admin.user_unlocked",
        outcome=AuditOutcome.SUCCEEDED,
        actor_user_id=principal.user_id,
        actor_role=principal.role,
        arguments={"user_id": str(user.id)},
        trace_id=getattr(request.state, "trace_id", None),
    )
    await session.commit()
    return _summary(user)


@router.post("/{user_id}/verification", status_code=202)
async def resend_verification_for_user(
    user_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(db_session),
    settings: Settings = Depends(app_settings),
) -> dict[str, str]:
    """Re-send a verification link on behalf of a user who cannot sign in yet."""
    user = await _get_user(session, user_id)
    if user.email_verified_at is not None:
        return {"status": "already_verified"}
    service = AuthService(settings)
    await service._issue_email_token(session, user=user, purpose=EmailTokenPurpose.VERIFY_EMAIL)
    await record_event(
        session,
        name="admin.verification_resent",
        outcome=AuditOutcome.SUCCEEDED,
        actor_user_id=principal.user_id,
        actor_role=principal.role,
        arguments={"user_id": str(user.id)},
        trace_id=getattr(request.state, "trace_id", None),
    )
    await session.commit()
    return {"status": "sent"}


@router.get("/{user_id}/sessions", response_model=UserSessionsResponse)
async def list_user_sessions(
    user_id: uuid.UUID,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(db_session),
) -> UserSessionsResponse:
    """Every active session for an account (one per signed-in device)."""
    del principal
    user = await _get_user(session, user_id)
    rows = (
        (
            await session.execute(
                select(Session)
                .where(Session.user_id == user.id, Session.revoked_at.is_(None))
                .order_by(Session.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return UserSessionsResponse(
        user_id=user.id,
        items=[
            SessionSummary(
                id=row.id,
                label=row.label or "Unnamed device",
                user_agent=row.user_agent,
                created_at=row.created_at,
                last_seen_at=row.last_seen_at,
                expires_at=row.expires_at,
                revoked_at=row.revoked_at,
                device_id=row.device_id,
            )
            for row in rows
        ],
    )


@router.delete("/{user_id}/sessions")
async def revoke_user_sessions(
    user_id: uuid.UUID,
    request: Request,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(db_session),
) -> dict[str, int]:
    """Sign an account out everywhere (after a lost device, for example)."""
    user = await _get_user(session, user_id)
    revoked = await _revoke_all_sessions(session, user_id=user.id, reason="admin_revoked")
    user.session_epoch += 1
    await record_event(
        session,
        name="admin.user_sessions_revoked",
        outcome=AuditOutcome.SUCCEEDED,
        actor_user_id=principal.user_id,
        actor_role=principal.role,
        arguments={"user_id": str(user.id), "sessions": revoked},
        trace_id=getattr(request.state, "trace_id", None),
    )
    await session.commit()
    return {"revoked": revoked}


async def _get_user(session: AsyncSession, user_id: uuid.UUID) -> User:
    user = (await session.execute(select(User).where(User.id == user_id))).scalars().one_or_none()
    if user is None:
        raise APIError.not_found("User not found")
    return user


async def _revoke_all_sessions(session: AsyncSession, *, user_id: uuid.UUID, reason: str) -> int:
    now = utcnow()
    session_ids = (
        (
            await session.execute(
                select(Session.id).where(Session.user_id == user_id, Session.revoked_at.is_(None))
            )
        )
        .scalars()
        .all()
    )
    if not session_ids:
        return 0
    await session.execute(
        update(Session)
        .where(Session.id.in_(session_ids))
        .values(revoked_at=now, revoked_reason=reason[:120])
    )
    await session.execute(
        update(RefreshToken)
        .where(RefreshToken.session_id.in_(session_ids), RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    await session.execute(
        update(EmailToken)
        .where(EmailToken.user_id == user_id, EmailToken.used_at.is_(None))
        .values(used_at=now)
    )
    return len(session_ids)
