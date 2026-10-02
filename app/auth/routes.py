# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import hmac
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any, cast

from fastapi import APIRouter, Depends, Header, Response
from sqlalchemy import select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import write_audit
from app.auth.dependencies import Principal, public_device_id, public_user_id, require_principal
from app.auth.schemas import (
    LoginRequest,
    LoginResponse,
    RefreshRequest,
    RefreshResponse,
    UserProfileResponse,
)
from app.config import Settings, get_settings
from app.core.errors import APIError, AuthenticationError
from app.core.security import (
    create_access_token,
    hash_device_key,
    issue_refresh_token,
    verify_password,
)
from app.db.models import AuthSession, Device, User
from app.db.session import get_session
from app.ws.manager import connection_manager

router = APIRouter(prefix="/auth", tags=["auth"])


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


@router.post("/login", response_model=LoginResponse)
async def login(
    body: LoginRequest,
    response: Response,
    x_armx_device_key: str | None = Header(default=None, alias="X-Armx-Device-Key"),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> LoginResponse:
    raw_device_key = body.device_key.get_secret_value()
    if x_armx_device_key is not None and not hmac.compare_digest(x_armx_device_key, raw_device_key):
        raise APIError("auth_pairing_rejected", "Device pairing was rejected", status_code=403)

    device_hash = hash_device_key(raw_device_key)
    device = await session.scalar(select(Device).where(Device.device_key_hash == device_hash))
    if device is None:
        raise APIError("auth_pairing_rejected", "Device pairing was rejected", status_code=403)
    if not device.is_active or device.revoked_at is not None:
        raise APIError(
            "auth_device_revoked", "This device is no longer authorized", status_code=403
        )

    username = body.username.strip().lower()
    user = await session.scalar(select(User).where(User.username == username))
    if user is None:
        raise AuthenticationError("auth_invalid_credentials", "Invalid username or password")

    now = datetime.now(UTC)
    if not user.is_active or (user.locked_until and _as_utc(user.locked_until) > now):
        raise APIError("auth_account_locked", "This account is locked", status_code=403)

    if device.owner_id != user.id or not verify_password(
        user.password_hash, body.password.get_secret_value()
    ):
        user.failed_login_count += 1
        if user.failed_login_count >= settings.auth_max_failures:
            user.locked_until = now + timedelta(seconds=settings.auth_lockout_seconds)
        await session.commit()
        raise AuthenticationError("auth_invalid_credentials", "Invalid username or password")

    user.failed_login_count = 0
    user.locked_until = None
    device.last_seen_at = now
    refresh_token, refresh_hash = issue_refresh_token()
    session_expiry = now + timedelta(seconds=settings.refresh_token_ttl_seconds)
    auth_session = AuthSession(
        user_id=user.id,
        device_id=device.id,
        refresh_token_hash=refresh_hash,
        expires_at=session_expiry,
    )
    session.add(auth_session)
    await session.flush()
    access_token, access_expiry = create_access_token(
        settings,
        user_id=str(user.id),
        device_id=str(device.id),
        session_id=str(auth_session.id),
        roles=list(user.roles),
    )
    await write_audit(
        session,
        actor_user_id=user.id,
        subject_user_id=user.id,
        device_id=device.id,
        action="auth.login",
        target=public_device_id(device),
        detail="User signed in.",
    )
    await session.commit()
    response.headers["Cache-Control"] = "no-store"
    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=access_expiry,
        device_id=public_device_id(device),
        user=UserProfileResponse(
            id=public_user_id(user),
            display_name=user.display_name,
            email=user.email,
            roles=list(user.roles),
        ),
    )


@router.post("/refresh", response_model=RefreshResponse)
async def refresh(
    body: RefreshRequest,
    response: Response,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> RefreshResponse:
    raw_token = body.refresh_token.get_secret_value()
    refresh_hash = sha256(raw_token.encode("utf-8")).hexdigest()
    auth_session = await session.scalar(
        select(AuthSession).where(AuthSession.refresh_token_hash == refresh_hash)
    )
    now = datetime.now(UTC)
    if (
        auth_session is None
        or auth_session.revoked_at is not None
        or _as_utc(auth_session.expires_at) <= now
    ):
        raise AuthenticationError("auth_refresh_rejected", "Refresh token was rejected")

    user = await session.get(User, auth_session.user_id)
    device = await session.get(Device, auth_session.device_id)
    if (
        user is None
        or not user.is_active
        or device is None
        or not device.is_active
        or device.revoked_at
    ):
        auth_session.revoked_at = now
        await session.commit()
        if user is not None:
            await connection_manager.close_user(user.id)
        elif device is not None:
            await connection_manager.close_device(device.id)
        raise AuthenticationError("auth_refresh_rejected", "Refresh token was rejected")

    # Compare-and-set prevents two concurrent refresh requests from both rotating the
    # same token; a replayed request observes rowcount=0 and receives a generic rejection.
    consumed = cast(
        CursorResult[Any],
        await session.execute(
            update(AuthSession)
            .where(
                AuthSession.id == auth_session.id,
                AuthSession.revoked_at.is_(None),
                AuthSession.expires_at > now,
            )
            .values(revoked_at=now)
            .execution_options(synchronize_session=False)
        ),
    )
    if consumed.rowcount != 1:
        await session.rollback()
        raise AuthenticationError("auth_refresh_rejected", "Refresh token was rejected")
    auth_session.revoked_at = now
    next_refresh, next_hash = issue_refresh_token()
    next_session = AuthSession(
        user_id=user.id,
        device_id=device.id,
        refresh_token_hash=next_hash,
        expires_at=now + timedelta(seconds=settings.refresh_token_ttl_seconds),
    )
    session.add(next_session)
    await session.flush()
    access_token, access_expiry = create_access_token(
        settings,
        user_id=str(user.id),
        device_id=str(device.id),
        session_id=str(next_session.id),
        roles=list(user.roles),
    )
    await session.commit()
    await connection_manager.close_device(device.id)
    response.headers["Cache-Control"] = "no-store"
    return RefreshResponse(
        access_token=access_token,
        refresh_token=next_refresh,
        expires_at=access_expiry,
    )


@router.post("/logout", status_code=204)
async def logout(
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
) -> Response:
    principal.auth_session.revoked_at = datetime.now(UTC)
    await write_audit(
        session,
        actor_user_id=principal.user.id,
        subject_user_id=principal.user.id,
        device_id=principal.device.id,
        action="auth.logout",
        target=public_device_id(principal.device),
        detail="User signed out.",
    )
    await session.commit()
    await connection_manager.close_device(principal.device.id)
    return Response(status_code=204)
