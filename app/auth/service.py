# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Account lifecycle: signup, verification, login, rotation, reset, session control.

Rules this module enforces, in one place:

* **Passwords** are argon2id hashes and only ever checked with a constant-time verifier. A login
  attempt for an address that does not exist still performs a dummy hash check, so response time
  does not reveal whether an account exists.
* **Enumeration resistance.** Signup, resend-verification and forgot-password return the same
  generic answer whether or not the address is registered.
* **Lockout is per account, rate limiting is per network.** Five failed logins lock the account
  for the configured window; the per-IP limit is applied by the route.
* **Refresh tokens rotate and are single-use.** Presenting a rotated token is treated as theft:
  the session is revoked and an audit row records it.
* **Every state change is audited** with the actor, the source and the request trace id.

Nothing here grants capability. Scopes come from the role and are attached to the token; the
Security Gateway decides what a call may do.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import record_event
from app.auth.schemas import AccountSummary, SessionSummary, TokenResponse
from app.auth.scopes import scopes_for_role
from app.auth.tokens import (
    TokenError,
    create_access_token,
    hash_refresh_token,
    new_refresh_token,
    refresh_expiry,
    session_is_usable,
)
from app.config import Settings
from app.core.crypto import constant_time_compare, hash_token, random_token
from app.core.enums import AuditOutcome, DeviceKind, DeviceStatus, EmailTokenPurpose, Role
from app.core.errors import APIError, ErrorCode
from app.core.logging import get_logger
from app.core.metrics import inc
from app.core.passwords import (
    dummy_verify,
    hash_password,
    needs_rehash,
    password_policy_error,
    verify_password,
)
from app.core.privacy import hash_ip
from app.core.time import utcnow
from app.db.models import Device, EmailToken, RefreshToken, Session, User

__all__ = ["AuthService", "LoginContext", "SessionBundle"]

logger = get_logger("auth.service")

_GENERIC_SIGNUP_MESSAGE = "Check your inbox to continue."
_GENERIC_RESET_MESSAGE = "If that address has an account, a reset link is on its way."


@dataclass(slots=True)
class SessionBundle:
    """What a successful authentication yields: the token payload and the rows behind it."""

    payload: TokenResponse
    session_id: uuid.UUID
    device_id: uuid.UUID


@dataclass(slots=True)
class LoginContext:
    """Request metadata recorded on the session and in audit rows."""

    ip_address: str | None = None
    user_agent: str = ""
    device_name: str = ""
    platform: str = ""
    trace_id: str | None = None


def _device_kind(platform: str, user_agent: str) -> DeviceKind:
    """Classify a client from its own declared platform and the request's user agent."""
    probe = f"{platform} {user_agent}".lower()
    if "kiosk" in probe or "dashboard" in probe:
        return DeviceKind.KIOSK
    if "esp" in probe or "espressif" in probe:
        return DeviceKind.ESP32
    if "tablet" in probe or "ipad" in probe:
        return DeviceKind.TABLET
    if any(token in probe for token in ("android", "iphone", "mobile", "ios")):
        return DeviceKind.MOBILE
    if any(
        token in probe for token in ("windows", "macintosh", "mac os", "linux", "x11", "darwin")
    ):
        return DeviceKind.DESKTOP
    if "bot" in probe or "curl" in probe or "python" in probe:
        return DeviceKind.SERVER
    return DeviceKind.UNKNOWN


class AuthService:
    """All account and session operations, backed by one database session per request."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    # ------------------------------------------------------------------ signup
    async def signup(
        self,
        session: AsyncSession,
        *,
        email: str,
        password: str,
        display_name: str,
        context: LoginContext,
    ) -> None:
        """
        Register an account and send a verification link.

        Deliberately returns nothing: the caller answers with a fixed message, so an attacker
        cannot tell a fresh address from one that is already registered.
        """
        await self._assert_password_acceptable(session, email=email, password=password)
        normalised = self.normalise_email(email)
        existing = await self._user_by_email(session, normalised)

        if existing is None:
            user = User(
                email=normalised,
                display_name=display_name or normalised.split("@")[0][:120],
                role=Role.USER,
                password_hash=hash_password(password),
                is_active=True,
                session_epoch=0,
            )
            session.add(user)
            await session.flush()
            await self._issue_email_token(
                session, user=user, purpose=EmailTokenPurpose.VERIFY_EMAIL
            )
            await record_event(
                session,
                name="auth.signup",
                outcome=AuditOutcome.SUCCEEDED,
                actor_user_id=user.id,
                actor_role=user.role,
                arguments={"email_domain": normalised.split("@")[-1]},
                ip_hash=self._ip_hash(context.ip_address),
                trace_id=context.trace_id,
            )
            inc("signups")
        else:
            # Existing account: do not create anything, do not reveal anything, but still tell the
            # owner that somebody tried (an unverified account gets a fresh link).
            await record_event(
                session,
                name="auth.signup_duplicate",
                outcome=AuditOutcome.DENIED,
                actor_user_id=existing.id,
                actor_role=existing.role,
                error_code=ErrorCode.CONFLICT,
                ip_hash=self._ip_hash(context.ip_address),
                trace_id=context.trace_id,
            )
            if existing.email_verified_at is None:
                await self._issue_email_token(
                    session, user=existing, purpose=EmailTokenPurpose.VERIFY_EMAIL
                )
        await session.commit()

    async def resend_verification(
        self, session: AsyncSession, *, email: str, context: LoginContext
    ) -> None:
        """Send another verification link, only if the account is still unverified."""
        user = await self._user_by_email(session, self.normalise_email(email))
        if user is not None and user.email_verified_at is None and user.is_active:
            await self._issue_email_token(
                session, user=user, purpose=EmailTokenPurpose.VERIFY_EMAIL
            )
            await record_event(
                session,
                name="auth.verification_resent",
                outcome=AuditOutcome.SUCCEEDED,
                actor_user_id=user.id,
                actor_role=user.role,
                ip_hash=self._ip_hash(context.ip_address),
                trace_id=context.trace_id,
            )
        await session.commit()

    async def verify_email(
        self, session: AsyncSession, *, token: str, context: LoginContext
    ) -> User:
        """Consume a verification token and mark the address verified."""
        email_token = await self._consume_email_token(
            session, token=token, purpose=EmailTokenPurpose.VERIFY_EMAIL
        )
        user = await self._require_user(session, email_token.user_id)
        if user.email_verified_at is None:
            user.email_verified_at = utcnow()
        await record_event(
            session,
            name="auth.email_verified",
            outcome=AuditOutcome.SUCCEEDED,
            actor_user_id=user.id,
            actor_role=user.role,
            ip_hash=self._ip_hash(context.ip_address),
            trace_id=context.trace_id,
        )
        await session.commit()
        return user

    # ------------------------------------------------------------------- login
    async def login(
        self,
        session: AsyncSession,
        *,
        email: str,
        password: str,
        context: LoginContext,
    ) -> TokenResponse:
        """Verify credentials, open a device session, and issue the first token pair."""
        normalised = self.normalise_email(email)
        user = await self._user_by_email(session, normalised)
        now = utcnow()

        if user is None:
            dummy_verify()  # equalise timing with the real path
            await self._record_login_failure(session, None, context, ErrorCode.INVALID_CREDENTIALS)
            await session.commit()
            raise APIError(
                ErrorCode.INVALID_CREDENTIALS, "Email or password is incorrect", status_code=401
            )

        if user.locked_until is not None and user.locked_until > now:
            retry_after = int((user.locked_until - now).total_seconds())
            await self._record_login_failure(session, user, context, ErrorCode.ACCOUNT_LOCKED)
            await session.commit()
            raise APIError(
                ErrorCode.ACCOUNT_LOCKED,
                "Too many failed attempts. Try again later.",
                status_code=423,
                headers={"Retry-After": str(max(1, retry_after))},
            )

        stored_hash = user.password_hash
        if stored_hash is None:
            # Google-only account: a password login cannot succeed, but say so generically.
            dummy_verify()
            await self._record_login_failure(session, user, context, ErrorCode.INVALID_CREDENTIALS)
            await session.commit()
            raise APIError(
                ErrorCode.INVALID_CREDENTIALS, "Email or password is incorrect", status_code=401
            )

        if not verify_password(password, stored_hash):
            await self._register_failed_login(session, user, context)
            await session.commit()
            raise APIError(
                ErrorCode.INVALID_CREDENTIALS, "Email or password is incorrect", status_code=401
            )

        if not user.is_active:
            await self._record_login_failure(session, user, context, ErrorCode.ACCOUNT_DISABLED)
            await session.commit()
            raise APIError(ErrorCode.ACCOUNT_DISABLED, "This account is disabled", status_code=403)

        if user.email_verified_at is None:
            await self._record_login_failure(session, user, context, ErrorCode.EMAIL_NOT_VERIFIED)
            await session.commit()
            raise APIError(
                ErrorCode.EMAIL_NOT_VERIFIED,
                "Verify your email address before signing in",
                status_code=403,
            )

        if needs_rehash(stored_hash):
            user.password_hash = hash_password(password)

        user.failed_login_count = 0
        user.locked_until = None
        user.last_login_at = now
        bundle = await self._open_session(session, user=user, context=context)
        await record_event(
            session,
            name="auth.login",
            outcome=AuditOutcome.SUCCEEDED,
            actor_user_id=user.id,
            actor_role=user.role,
            session_id=bundle.session_id,
            device_id=bundle.device_id,
            ip_hash=self._ip_hash(context.ip_address),
            trace_id=context.trace_id,
        )
        await session.commit()
        inc("logins")
        return bundle.payload

    async def _register_failed_login(
        self, session: AsyncSession, user: User, context: LoginContext
    ) -> None:
        user.failed_login_count += 1
        code = ErrorCode.INVALID_CREDENTIALS
        if user.failed_login_count >= self._settings.auth_max_failed_logins:
            user.locked_until = utcnow() + timedelta(seconds=self._settings.auth_lockout_seconds)
            user.failed_login_count = 0
            code = ErrorCode.ACCOUNT_LOCKED
            inc("account_lockouts")
            logger.warning("account locked after repeated failed logins")
        await self._record_login_failure(session, user, context, code)

    async def _record_login_failure(
        self,
        session: AsyncSession,
        user: User | None,
        context: LoginContext,
        code: str,
    ) -> None:
        await record_event(
            session,
            name="auth.login",
            outcome=AuditOutcome.DENIED,
            actor_user_id=user.id if user else None,
            actor_role=user.role if user else None,
            error_code=code,
            ip_hash=self._ip_hash(context.ip_address),
            trace_id=context.trace_id,
        )
        inc("login_failures")

    # ----------------------------------------------------------------- refresh
    async def refresh(
        self, session: AsyncSession, *, refresh_token: str, context: LoginContext
    ) -> TokenResponse:
        """
        Rotate a refresh token.

        Reuse of an already-used token means either a stolen token or a replayed request; both are
        handled the same way, by revoking the session and refusing.
        """
        token_hash = hash_refresh_token(self._settings, refresh_token)
        record = (
            (
                await session.execute(
                    select(RefreshToken).where(RefreshToken.token_hash == token_hash)
                )
            )
            .scalars()
            .one_or_none()
        )

        if record is None:
            await session.commit()
            raise APIError(ErrorCode.TOKEN_INVALID, "Refresh token is invalid", status_code=401)

        if record.used_at is not None or record.revoked_at is not None:
            await self._revoke_session(
                session, record.session_id, reason="refresh_token_reuse", commit=False
            )
            await record_event(
                session,
                name="auth.token_reuse",
                outcome=AuditOutcome.DENIED,
                actor_user_id=record.user_id,
                session_id=record.session_id,
                error_code=ErrorCode.TOKEN_REUSE_DETECTED,
                ip_hash=self._ip_hash(context.ip_address),
                trace_id=context.trace_id,
            )
            await session.commit()
            inc("refresh_token_reuse")
            logger.error("refresh token reuse detected; session revoked")
            raise APIError(
                ErrorCode.TOKEN_REUSE_DETECTED, "This session has been revoked", status_code=401
            )

        if record.expires_at <= utcnow():
            await session.commit()
            raise APIError(ErrorCode.TOKEN_EXPIRED, "Refresh token has expired", status_code=401)

        db_session_row = await self._require_session(session, record.session_id)
        if not session_is_usable(db_session_row):
            await session.commit()
            raise APIError(
                ErrorCode.TOKEN_INVALID, "This session is no longer active", status_code=401
            )

        user = await self._require_user(session, record.user_id)
        if not user.is_active:
            await session.commit()
            raise APIError(ErrorCode.ACCOUNT_DISABLED, "This account is disabled", status_code=403)

        record.used_at = utcnow()
        db_session_row.last_seen_at = utcnow()
        if context.user_agent:
            db_session_row.user_agent = context.user_agent[:400]
        new_token = await self._store_refresh_token(
            session, user=user, session_id=db_session_row.id, rotated_from_id=record.id
        )
        payload = self._token_response(user, db_session_row, new_token)
        await session.commit()
        inc("token_refreshes")
        return payload

    # ------------------------------------------------------------------ logout
    async def logout(
        self,
        session: AsyncSession,
        *,
        user: User,
        current_session_id: uuid.UUID | None,
        refresh_token: str | None = None,
        all_sessions: bool = False,
        context: LoginContext | None = None,
    ) -> int:
        """Revoke the current session, a session named by its refresh token, or all of them."""
        targets: list[uuid.UUID] = []
        if all_sessions:
            rows = (
                (
                    await session.execute(
                        select(Session.id).where(
                            Session.user_id == user.id, Session.revoked_at.is_(None)
                        )
                    )
                )
                .scalars()
                .all()
            )
            targets.extend(rows)
        elif refresh_token:
            record = (
                (
                    await session.execute(
                        select(RefreshToken).where(
                            RefreshToken.token_hash
                            == hash_refresh_token(self._settings, refresh_token)
                        )
                    )
                )
                .scalars()
                .one_or_none()
            )
            if record is not None and record.user_id == user.id:
                targets.append(record.session_id)
        elif current_session_id is not None:
            targets.append(current_session_id)

        for session_id in dict.fromkeys(targets):
            await self._revoke_session(session, session_id, reason="logout", commit=False)

        await record_event(
            session,
            name="auth.logout",
            outcome=AuditOutcome.SUCCEEDED,
            actor_user_id=user.id,
            actor_role=user.role,
            session_id=current_session_id,
            arguments={"sessions": len(set(targets)), "all": all_sessions},
            ip_hash=self._ip_hash(context.ip_address if context else None),
            trace_id=context.trace_id if context else None,
        )
        await session.commit()
        return len(set(targets))

    # ---------------------------------------------------------- password reset
    async def request_password_reset(
        self, session: AsyncSession, *, email: str, context: LoginContext
    ) -> None:
        """Send a reset link if the account exists; always answer the same way."""
        user = await self._user_by_email(session, self.normalise_email(email))
        if user is not None and user.is_active:
            await self._issue_email_token(
                session, user=user, purpose=EmailTokenPurpose.RESET_PASSWORD
            )
            await record_event(
                session,
                name="auth.password_reset_requested",
                outcome=AuditOutcome.SUCCEEDED,
                actor_user_id=user.id,
                actor_role=user.role,
                ip_hash=self._ip_hash(context.ip_address),
                trace_id=context.trace_id,
            )
            inc("password_reset_requests")
        await session.commit()

    async def reset_password(
        self, session: AsyncSession, *, token: str, password: str, context: LoginContext
    ) -> User:
        """
        Set a new password from a reset link.

        Every existing session is revoked and the user's session epoch is bumped, so tokens
        minted before the reset stop working immediately.
        """
        email_token = await self._consume_email_token(
            session, token=token, purpose=EmailTokenPurpose.RESET_PASSWORD
        )
        user = await self._require_user(session, email_token.user_id)
        await self._assert_password_acceptable(session, email=user.email, password=password)

        user.password_hash = hash_password(password)
        user.failed_login_count = 0
        user.locked_until = None
        user.session_epoch += 1

        rows = (
            (
                await session.execute(
                    select(Session.id).where(
                        Session.user_id == user.id, Session.revoked_at.is_(None)
                    )
                )
            )
            .scalars()
            .all()
        )
        for session_id in rows:
            await self._revoke_session(session, session_id, reason="password_reset", commit=False)

        await record_event(
            session,
            name="auth.password_reset",
            outcome=AuditOutcome.SUCCEEDED,
            actor_user_id=user.id,
            actor_role=user.role,
            arguments={"sessions_revoked": len(rows)},
            ip_hash=self._ip_hash(context.ip_address),
            trace_id=context.trace_id,
        )
        await session.commit()
        inc("password_resets")
        return user

    # ------------------------------------------------------------ google sign-in
    async def login_with_google(
        self,
        session: AsyncSession,
        *,
        google_sub: str,
        email: str,
        email_verified: bool,
        display_name: str,
        context: LoginContext,
    ) -> TokenResponse:
        """
        Sign in (or register) from a verified Google identity.

        The caller must have validated the ID token signature, issuer and audience; this method
        only maps the identity onto an account. A Google sign-in for an existing local account
        links the identities rather than creating a duplicate.
        """
        normalised = self.normalise_email(email)
        user = await self._user_by_email(session, normalised)

        if user is None:
            user = User(
                email=normalised,
                display_name=(display_name or normalised.split("@")[0])[:120],
                role=Role.USER,
                password_hash=None,
                google_sub=google_sub,
                email_verified_at=utcnow() if email_verified else None,
                is_active=True,
                session_epoch=0,
            )
            session.add(user)
            await session.flush()
            inc("signups")
        else:
            if user.google_sub is not None and not constant_time_compare(
                user.google_sub, google_sub
            ):
                await record_event(
                    session,
                    name="auth.google_identity_conflict",
                    outcome=AuditOutcome.DENIED,
                    actor_user_id=user.id,
                    actor_role=user.role,
                    error_code=ErrorCode.CONFLICT,
                    ip_hash=self._ip_hash(context.ip_address),
                    trace_id=context.trace_id,
                )
                await session.commit()
                raise APIError(
                    ErrorCode.CONFLICT,
                    "This email is already linked to a different Google account",
                    status_code=409,
                )
            if not user.is_active:
                await session.commit()
                raise APIError(
                    ErrorCode.ACCOUNT_DISABLED, "This account is disabled", status_code=403
                )
            user.google_sub = user.google_sub or google_sub
            if email_verified and user.email_verified_at is None:
                user.email_verified_at = utcnow()

        user.last_login_at = utcnow()
        bundle = await self._open_session(session, user=user, context=context)
        await record_event(
            session,
            name="auth.login_google",
            outcome=AuditOutcome.SUCCEEDED,
            actor_user_id=user.id,
            actor_role=user.role,
            session_id=bundle.session_id,
            device_id=bundle.device_id,
            ip_hash=self._ip_hash(context.ip_address),
            trace_id=context.trace_id,
        )
        await session.commit()
        return bundle.payload

    # --------------------------------------------------------------- internals
    async def _open_session(
        self, session: AsyncSession, *, user: User, context: LoginContext
    ) -> SessionBundle:
        """Create the device row, the session row and the first token pair."""
        now = utcnow()
        kind = _device_kind(context.platform, context.user_agent)
        device = Device(
            name=(context.device_name or _default_device_name(kind))[:120],
            kind=kind,
            platform=context.platform[:80],
            owner_user_id=user.id,
            status=DeviceStatus.ACTIVE,
            last_active_at=now,
        )
        session.add(device)
        await session.flush()

        db_session_row = Session(
            user_id=user.id,
            device_id=device.id,
            label=device.name,
            user_agent=context.user_agent[:400],
            ip_hash=self._ip_hash(context.ip_address),
            created_at=now,
            last_seen_at=now,
            expires_at=now + timedelta(seconds=self._settings.refresh_token_ttl_seconds),
        )
        session.add(db_session_row)
        await session.flush()

        refresh_token = await self._store_refresh_token(
            session, user=user, session_id=db_session_row.id, rotated_from_id=None
        )
        return SessionBundle(
            payload=self._token_response(user, db_session_row, refresh_token),
            session_id=db_session_row.id,
            device_id=device.id,
        )

    def _token_response(
        self, user: User, db_session_row: Session, refresh_token: str
    ) -> TokenResponse:
        access_token, claims = create_access_token(
            self._settings,
            user=user,
            scopes=scopes_for_role(user.role),
            session_id=db_session_row.id,
            device_id=db_session_row.device_id,
        )
        return TokenResponse(
            access_token=access_token,
            expires_in=claims.expires_in,
            refresh_token=refresh_token,
            refresh_expires_in=max(0, int((db_session_row.expires_at - utcnow()).total_seconds())),
            session_id=db_session_row.id,
            user=self.account_summary(user),
        )

    async def _store_refresh_token(
        self,
        session: AsyncSession,
        *,
        user: User,
        session_id: uuid.UUID,
        rotated_from_id: uuid.UUID | None,
    ) -> str:
        raw = new_refresh_token()
        session.add(
            RefreshToken(
                session_id=session_id,
                user_id=user.id,
                token_hash=hash_refresh_token(self._settings, raw),
                issued_at=utcnow(),
                expires_at=refresh_expiry(self._settings),
                rotated_from_id=rotated_from_id,
            )
        )
        await session.flush()
        return raw

    async def _revoke_session(
        self, session: AsyncSession, session_id: uuid.UUID, *, reason: str, commit: bool
    ) -> None:
        now = utcnow()
        await session.execute(
            update(Session)
            .where(Session.id == session_id, Session.revoked_at.is_(None))
            .values(revoked_at=now, revoked_reason=reason[:120])
        )
        await session.execute(
            update(RefreshToken)
            .where(RefreshToken.session_id == session_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        if commit:
            await session.commit()

    async def _issue_email_token(
        self, session: AsyncSession, *, user: User, purpose: EmailTokenPurpose
    ) -> str:
        """
        Create a single-use email token and hand it to the mailer.

        Invalidate any outstanding token for the same purpose first: only the newest link works,
        which bounds the number of live reset links for an account to one.
        """
        now = utcnow()
        await session.execute(
            update(EmailToken)
            .where(
                EmailToken.user_id == user.id,
                EmailToken.purpose == purpose,
                EmailToken.used_at.is_(None),
            )
            .values(used_at=now)
        )
        raw = random_token(32)
        session.add(
            EmailToken(
                user_id=user.id,
                purpose=purpose,
                token_hash=self._email_token_hash(raw),
                created_at=now,
                expires_at=now + timedelta(seconds=self._settings.email_token_ttl_seconds),
            )
        )
        await session.flush()

        template = "verification" if purpose == EmailTokenPurpose.VERIFY_EMAIL else "password_reset"
        expires_in_minutes = max(1, self._settings.email_token_ttl_seconds // 60)
        # Imported lazily: keeps auth importable in the CLI without the mailer's SMTP stack.
        from app.notifications.mailer import send_template_email

        await send_template_email(
            session,
            self._settings,
            to_address=user.email,
            template=template,
            token=raw,
            display_name=user.display_name,
            expires_in_minutes=expires_in_minutes,
        )
        return raw

    async def _consume_email_token(
        self, session: AsyncSession, *, token: str, purpose: EmailTokenPurpose
    ) -> EmailToken:
        """
        Atomically consume a single-use email token.

        The update is the check: two concurrent requests presenting the same link cannot both
        succeed, because only one ``UPDATE ... WHERE used_at IS NULL`` matches.
        """
        token_hash = self._email_token_hash(token)
        result = await session.execute(
            update(EmailToken)
            .where(
                EmailToken.token_hash == token_hash,
                EmailToken.purpose == purpose,
                EmailToken.used_at.is_(None),
                EmailToken.expires_at > utcnow(),
            )
            .values(used_at=utcnow())
            .returning(EmailToken.user_id, EmailToken.expires_at)
        )
        row = result.first()
        if row is None:
            existing = (
                (
                    await session.execute(
                        select(EmailToken).where(EmailToken.token_hash == token_hash)
                    )
                )
                .scalars()
                .one_or_none()
            )
            await session.commit()
            if existing is not None and existing.used_at is not None:
                raise APIError(
                    ErrorCode.TOKEN_INVALID, "This link has already been used", status_code=400
                )
            raise APIError(
                ErrorCode.TOKEN_EXPIRED, "This link is invalid or has expired", status_code=400
            )
        if row.expires_at <= utcnow():  # pragma: no cover - guarded by the statement above
            await session.commit()
            raise APIError(
                ErrorCode.TOKEN_EXPIRED, "This link is invalid or has expired", status_code=400
            )
        token_row = (
            (await session.execute(select(EmailToken).where(EmailToken.token_hash == token_hash)))
            .scalars()
            .one()
        )
        return token_row

    def _email_token_hash(self, token: str) -> str:
        return hash_token(token, self._settings.jwt_key())

    async def _assert_password_acceptable(
        self, session: AsyncSession, *, email: str, password: str
    ) -> None:
        error = password_policy_error(
            password, email=email, min_length=self._settings.password_min_length
        )
        if error:
            # Discard any partial work (a consumed reset link stays usable if the new password
            # is rejected, so the user is not forced to request a second link).
            await session.rollback()
            raise APIError(
                ErrorCode.INVALID_REQUEST, error, status_code=400, details={"field": "password"}
            )

    async def _user_by_email(self, session: AsyncSession, email: str) -> User | None:
        return (
            (await session.execute(select(User).where(User.email == email))).scalars().one_or_none()
        )

    async def _require_user(self, session: AsyncSession, user_id: uuid.UUID) -> User:
        user = (
            (await session.execute(select(User).where(User.id == user_id))).scalars().one_or_none()
        )
        if user is None:  # pragma: no cover - referential integrity makes this unreachable
            raise APIError(ErrorCode.UNAUTHENTICATED, "Account no longer exists", status_code=401)
        return user

    async def _require_session(self, session: AsyncSession, session_id: uuid.UUID) -> Session:
        row = (
            (await session.execute(select(Session).where(Session.id == session_id)))
            .scalars()
            .one_or_none()
        )
        if row is None:  # pragma: no cover - cascades make this unreachable
            raise TokenError(ErrorCode.TOKEN_INVALID, "Session is invalid").as_api_error()
        return row

    @staticmethod
    def normalise_email(email: str) -> str:
        """Lower-case and trim; the database stores one canonical form per address."""
        return email.strip().lower()

    @staticmethod
    def account_summary(user: User) -> AccountSummary:
        return AccountSummary(
            id=user.id,
            email=user.email,
            display_name=user.display_name,
            role=user.role.value,
            email_verified=user.email_verified_at is not None,
            is_active=user.is_active,
            created_at=user.created_at,
            last_login_at=user.last_login_at,
        )

    async def list_sessions(
        self, session: AsyncSession, *, user: User, current_session_id: uuid.UUID | None
    ) -> list[SessionSummary]:
        """Active sessions for the account, newest first, with the caller's own flagged."""
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
        return [
            SessionSummary(
                id=row.id,
                label=row.label or "Unnamed device",
                user_agent=row.user_agent,
                created_at=row.created_at,
                last_seen_at=row.last_seen_at,
                expires_at=row.expires_at,
                revoked_at=row.revoked_at,
                device_id=row.device_id,
                current=row.id == current_session_id,
            )
            for row in rows
        ]

    async def revoke_session(
        self,
        session: AsyncSession,
        *,
        user: User,
        session_id: uuid.UUID,
        context: LoginContext | None = None,
    ) -> None:
        """Revoke one of the caller's own sessions (never somebody else's)."""
        row = (
            (await session.execute(select(Session).where(Session.id == session_id)))
            .scalars()
            .one_or_none()
        )
        if row is None or row.user_id != user.id:
            raise APIError.not_found("Session not found")
        await self._revoke_session(session, row.id, reason="user_revoked", commit=False)
        await record_event(
            session,
            name="auth.session_revoked",
            outcome=AuditOutcome.SUCCEEDED,
            actor_user_id=user.id,
            actor_role=user.role,
            session_id=row.id,
            ip_hash=self._ip_hash(context.ip_address if context else None),
            trace_id=context.trace_id if context else None,
        )
        await session.commit()

    async def update_profile(
        self, session: AsyncSession, *, user: User, display_name: str
    ) -> AccountSummary:
        """Rename the account holder's display name."""
        user.display_name = display_name.strip()[:120]
        await record_event(
            session,
            name="auth.profile_updated",
            outcome=AuditOutcome.SUCCEEDED,
            actor_user_id=user.id,
            actor_role=user.role,
        )
        await session.commit()
        return self.account_summary(user)

    def _ip_hash(self, ip_address: str | None) -> str | None:
        return hash_ip(ip_address, salt=self._settings.jwt_key())


def _default_device_name(kind: DeviceKind) -> str:
    return {
        DeviceKind.MOBILE: "Mobile device",
        DeviceKind.TABLET: "Tablet",
        DeviceKind.DESKTOP: "Desktop",
        DeviceKind.ESP32: "ESP32 node",
        DeviceKind.KIOSK: "Kiosk",
        DeviceKind.SERVER: "Server client",
    }.get(kind, "New device")
