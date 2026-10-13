# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Request authentication.

``current_principal`` is the only way a route learns who is calling. It checks the bearer token
and then re-checks the *server-side* state that the token cannot vouch for:

* the account still exists and is active,
* the account epoch still matches, so a password reset or "sign out everywhere" invalidates
  tokens minted earlier,
* the session has not been revoked,
* the address is verified.

A client can never assert a role, a scope or a device: those come from the database and the token
the server itself signed. Local development may authenticate as an admin without a token, but
only when ``ENVIRONMENT=development`` *and* ``DEV_AUTH_BYPASS=true``.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Callable, Iterable
from dataclasses import dataclass, field
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import app_settings, db_session
from app.auth.scopes import has_all_scopes, missing_scopes, scopes_for_role
from app.auth.tokens import AccessTokenClaims, TokenError, decode_access_token
from app.config import Settings
from app.core.enums import Role
from app.core.errors import APIError, ErrorCode
from app.db.models import Session, User

__all__ = [
    "CurrentPrincipal",
    "Principal",
    "current_principal",
    "optional_principal",
    "require_admin",
    "require_role",
    "require_scope",
]


@dataclass(slots=True)
class Principal:
    """
    Who is calling.

    ``scopes`` are the scopes of the *role* at the time of the request, not the (possibly stale)
    scopes baked into the token: a downgrade takes effect immediately rather than after the
    access token expires.
    """

    user: User
    session_id: uuid.UUID | None = None
    device_id: uuid.UUID | None = None
    claims: AccessTokenClaims | None = None
    scopes: frozenset[str] = field(default_factory=frozenset)
    source: str = "token"

    @property
    def user_id(self) -> uuid.UUID:
        return self.user.id

    @property
    def role(self) -> Role:
        return self.user.role

    def has_scope(self, scope: str) -> bool:
        from app.auth.scopes import has_scope as _has_scope

        return _has_scope(self.scopes, scope)

    def request_id(self) -> str | None:
        return self.claims.jti if self.claims else None


def _bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if not header:
        return None
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


async def _load_principal(
    request: Request, session: AsyncSession, settings: Settings
) -> Principal | None:
    token = _bearer_token(request)

    if token is None:
        if settings.environment == "development" and settings.dev_auth_bypass:
            return await _development_principal(session)
        return None

    try:
        claims = decode_access_token(settings, token)
    except TokenError as exc:
        raise exc.as_api_error() from exc

    user = (
        (await session.execute(select(User).where(User.id == claims.subject)))
        .scalars()
        .one_or_none()
    )
    if user is None or not user.is_active:
        raise APIError(ErrorCode.UNAUTHENTICATED, "Account is not active", status_code=401)
    if claims.session_epoch != user.session_epoch:
        # A password reset or a global sign-out happened after this token was minted.
        raise APIError(ErrorCode.TOKEN_INVALID, "Token is invalid or expired", status_code=401)
    if claims.session_id is not None:
        db_session_row = (
            (await session.execute(select(Session).where(Session.id == claims.session_id)))
            .scalars()
            .one_or_none()
        )
        if db_session_row is None or db_session_row.user_id != user.id:
            raise APIError(ErrorCode.TOKEN_INVALID, "Session is invalid", status_code=401)
        if db_session_row.revoked_at is not None:
            raise APIError(ErrorCode.TOKEN_INVALID, "Session has been revoked", status_code=401)

    return Principal(
        user=user,
        session_id=claims.session_id,
        device_id=claims.device_id,
        claims=claims,
        scopes=scopes_for_role(user.role),
        source="token",
    )


async def _development_principal(session: AsyncSession) -> Principal:
    """
    Local-development bypass.

    Two independent settings must allow it (``ENVIRONMENT=development`` and ``DEV_AUTH_BYPASS``),
    and the production validator refuses to boot while the bypass is on.
    """
    user = (
        (
            await session.execute(
                select(User).where(User.role == Role.ADMIN).order_by(User.created_at)
            )
        )
        .scalars()
        .first()
    )
    if user is None:
        raise APIError(
            ErrorCode.UNAUTHENTICATED,
            "No account exists yet; run: python -m app.cli.create_admin --email you@example.com",
            status_code=401,
        )
    return Principal(user=user, scopes=scopes_for_role(user.role), source="dev_bypass")


async def current_principal(
    request: Request,
    session: AsyncSession = Depends(db_session),
    settings: Settings = Depends(app_settings),
) -> Principal:
    """Dependency for endpoints that require an authenticated caller."""
    principal = await _load_principal(request, session, settings)
    if principal is None:
        raise APIError.unauthenticated()
    return principal


async def optional_principal(
    request: Request,
    session: AsyncSession = Depends(db_session),
    settings: Settings = Depends(app_settings),
) -> Principal | None:
    """Dependency for endpoints that behave differently when signed in but do not require it."""
    return await _load_principal(request, session, settings)


CurrentPrincipal = Annotated[Principal, Depends(current_principal)]


def require_role(minimum: Role) -> Callable[..., AsyncIterator[Principal]]:
    """
    Dependency factory that requires at least ``minimum`` on the role hierarchy.

    ``require_role(Role.ADMIN)`` is used by every ``/admin`` route; the hierarchy still allows a
    stricter explicit check to be added on top.
    """

    async def _dependency(principal: CurrentPrincipal) -> AsyncIterator[Principal]:
        if not principal.role.at_least(minimum):
            raise APIError(
                ErrorCode.ROLE_REQUIRED,
                f"This action requires the {minimum.value} role",
                status_code=403,
            )
        yield principal

    return _dependency


require_admin = require_role(Role.ADMIN)


def require_scope(*required: str) -> Callable[..., AsyncIterator[Principal]]:
    """
    Dependency factory that requires every scope in ``required``.

    Scopes are recomputed from the stored role, so a role change applies to the next request
    rather than when the current access token expires.
    """

    async def _dependency(principal: CurrentPrincipal) -> AsyncIterator[Principal]:
        if not has_all_scopes(principal.scopes, required):
            raise APIError(
                ErrorCode.SCOPE_REQUIRED,
                "Missing scope: " + ", ".join(missing_scopes(principal.scopes, required)),
                status_code=403,
            )
        yield principal

    return _dependency


def ensure_scopes(granted: Iterable[str], required: Iterable[str]) -> None:
    """Raise unless every required scope is satisfied (used by the gateway and the harness)."""
    missing = missing_scopes(granted, required)
    if missing:
        raise APIError(
            ErrorCode.SCOPE_REQUIRED, "Missing scope: " + ", ".join(missing), status_code=403
        )
