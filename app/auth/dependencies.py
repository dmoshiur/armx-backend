# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import Depends, Header
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.core.errors import AuthenticationError, AuthorizationError
from app.core.security import decode_access_token, verify_device_key
from app.db.models import AuthSession, Device, User
from app.db.session import get_session


@dataclass(frozen=True, slots=True)
class Principal:
    user: User
    device: Device
    auth_session: AuthSession


def public_user_id(user: User) -> str:
    return user.public_id


def public_device_id(device: Device) -> str:
    return device.public_id


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


async def authenticate_principal(
    authorization: str | None,
    device_key: str | None,
    session: AsyncSession,
    settings: Settings,
) -> Principal:
    """Validate the paired-device credentials for HTTP and WebSocket handshakes."""

    if not authorization or not authorization.startswith("Bearer "):
        raise AuthenticationError()
    if not device_key:
        raise AuthenticationError("auth_device_required", "A paired device is required")

    try:
        claims = decode_access_token(settings, authorization[7:].strip())
        session_id = uuid.UUID(str(claims["sid"]))
        user_id = uuid.UUID(str(claims["sub"]))
        device_id = uuid.UUID(str(claims["device_id"]))
    except Exception:
        raise AuthenticationError() from None

    auth_session = await session.get(AuthSession, session_id)
    now = datetime.now(UTC)
    if (
        auth_session is None
        or auth_session.user_id != user_id
        or auth_session.device_id != device_id
        or auth_session.revoked_at is not None
        or _as_utc(auth_session.expires_at) <= now
    ):
        raise AuthenticationError()

    user = await session.get(User, user_id)
    device = await session.get(Device, device_id)
    if user is None or not user.is_active or device is None or not device.is_active:
        raise AuthenticationError("auth_device_revoked", "This device is no longer authorized")
    if device.revoked_at is not None or device.owner_id != user.id:
        raise AuthenticationError("auth_device_revoked", "This device is no longer authorized")
    if not verify_device_key(device_key, device.device_key_hash):
        raise AuthenticationError("auth_device_revoked", "This device is no longer authorized")

    return Principal(user=user, device=device, auth_session=auth_session)


async def require_principal(
    authorization: str | None = Header(default=None),
    device_key: str | None = Header(default=None, alias="X-Armx-Device-Key"),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> Principal:
    return await authenticate_principal(authorization, device_key, session, settings)


async def require_admin(principal: Principal = Depends(require_principal)) -> Principal:
    roles = {role.lower() for role in principal.user.roles}
    if not roles.intersection({"admin", "owner"}):
        raise AuthorizationError()
    return principal
