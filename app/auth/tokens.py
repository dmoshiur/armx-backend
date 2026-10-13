# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Token issuance and verification.

* **Access tokens** are short-lived JWTs (hard-capped at 15 minutes by the settings model) carrying
  the user, session, device, role, scopes and a ``session_epoch``. Bumping a user's epoch - which
  password reset and "sign out everywhere" do - invalidates every access token that user holds,
  without storing a denylist.
* **Refresh tokens** are opaque, high-entropy strings stored only as a hash, rotated on every use,
  and single-use. Presenting an already-rotated token is treated as theft: the session is revoked.

Nothing here decides authorization; it only establishes who is calling, for
:mod:`app.security.gateway` to act on.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Final

import jwt
from jwt import ExpiredSignatureError, InvalidTokenError

from app.config import Settings
from app.core.crypto import hash_token, new_nonce, random_token
from app.core.enums import Role
from app.core.errors import APIError, ErrorCode
from app.core.time import utcnow
from app.db.models import Session, User

__all__ = [
    "AccessTokenClaims",
    "TokenError",
    "create_access_token",
    "decode_access_token",
    "hash_refresh_token",
    "new_refresh_token",
    "refresh_expiry",
]

_ALGORITHM: Final = "HS256"
_TOKEN_TYPE: Final = "access"  # noqa: S105 - a token *type* marker, not a credential


class TokenError(Exception):
    """Raised when a token is absent, malformed, expired, or of the wrong type."""

    def __init__(self, code: str, message: str, *, status_code: int = 401) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code

    def as_api_error(self) -> APIError:
        return APIError(self.code, self.message, status_code=self.status_code)


@dataclass(frozen=True, slots=True)
class AccessTokenClaims:
    """Verified claims of an access token."""

    subject: uuid.UUID
    role: Role
    scopes: frozenset[str]
    session_id: uuid.UUID | None
    device_id: uuid.UUID | None
    session_epoch: int
    jti: str
    issued_at: int
    expires_at: int

    @property
    def expires_in(self) -> int:
        return max(0, self.expires_at - int(utcnow().timestamp()))


def create_access_token(
    settings: Settings,
    *,
    user: User,
    scopes: frozenset[str],
    session_id: uuid.UUID | None = None,
    device_id: uuid.UUID | None = None,
) -> tuple[str, AccessTokenClaims]:
    """Mint a short-lived access token bound to a user, a role and (usually) a session."""
    issued_at = utcnow()
    expires_at = issued_at + timedelta(seconds=settings.access_token_ttl_seconds)
    jti = new_nonce()
    payload: dict[str, Any] = {
        "sub": str(user.id),
        "role": user.role.value,
        "scopes": sorted(scopes),
        "sid": str(session_id) if session_id else None,
        "did": str(device_id) if device_id else None,
        "epoch": user.session_epoch,
        "jti": jti,
        "typ": _TOKEN_TYPE,
        "iat": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
    }
    token = jwt.encode(payload, settings.jwt_key(), algorithm=_ALGORITHM)
    claims = AccessTokenClaims(
        subject=user.id,
        role=user.role,
        scopes=scopes,
        session_id=session_id,
        device_id=device_id,
        session_epoch=user.session_epoch,
        jti=jti,
        issued_at=int(issued_at.timestamp()),
        expires_at=int(expires_at.timestamp()),
    )
    return token, claims


def decode_access_token(settings: Settings, token: str) -> AccessTokenClaims:
    """
    Verify an access token.

    Signature, issuer, audience, algorithm and expiry are all checked; a token signed with a
    different algorithm (``alg: none`` or an asymmetric swap) is rejected rather than trusted.
    """
    if not token or token.count(".") != 2:
        raise TokenError(ErrorCode.TOKEN_INVALID, "Token is invalid or expired")
    try:
        payload = jwt.decode(
            token,
            settings.jwt_key(),
            algorithms=[_ALGORITHM],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={"require": ["exp", "iat", "sub", "jti"]},
        )
    except ExpiredSignatureError as exc:
        raise TokenError(
            ErrorCode.TOKEN_EXPIRED, "Token is invalid or expired", status_code=401
        ) from exc
    except InvalidTokenError as exc:
        raise TokenError(ErrorCode.TOKEN_INVALID, "Token is invalid or expired") from exc

    if payload.get("typ") != _TOKEN_TYPE:
        raise TokenError(ErrorCode.TOKEN_INVALID, "Token is invalid or expired")

    try:
        return AccessTokenClaims(
            subject=uuid.UUID(str(payload["sub"])),
            role=Role(str(payload.get("role", Role.USER.value))),
            scopes=frozenset(str(scope) for scope in payload.get("scopes", [])),
            session_id=_optional_uuid(payload.get("sid")),
            device_id=_optional_uuid(payload.get("did")),
            session_epoch=int(payload.get("epoch", 0)),
            jti=str(payload["jti"]),
            issued_at=int(payload["iat"]),
            expires_at=int(payload["exp"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise TokenError(ErrorCode.TOKEN_INVALID, "Token is invalid or expired") from exc


def _optional_uuid(value: object) -> uuid.UUID | None:
    if value in (None, ""):
        return None
    try:
        return uuid.UUID(str(value))
    except ValueError as exc:
        raise TokenError(ErrorCode.TOKEN_INVALID, "Token is invalid or expired") from exc


def new_refresh_token() -> str:
    """Opaque, high-entropy refresh token (never a JWT: it carries no claims by design)."""
    return random_token(48)


def hash_refresh_token(settings: Settings, token: str) -> str:
    """Store only this hash; the raw token never touches the database or a log."""
    return hash_token(token, settings.jwt_key())


def refresh_expiry(settings: Settings) -> Any:
    """Expiry for a newly issued refresh token."""
    return utcnow() + timedelta(seconds=settings.refresh_token_ttl_seconds)


def session_is_usable(session: Session) -> bool:
    """A session must be unrevoked and unexpired for its tokens to work."""
    now = utcnow()
    if session.revoked_at is not None:
        return False
    return session.expires_at > now
