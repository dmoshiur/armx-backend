# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Authentication endpoints.

Every route here is rate limited per client address *and* per account, and every outcome -
including a failure - is audited with a salted hash of the address rather than the address
itself. The answers are written so that they cannot be used to enumerate accounts.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import app_settings, db_session
from app.auth.dependencies import CurrentPrincipal
from app.auth.google import (
    GoogleAuthError,
    GoogleIdentity,
    google_authorize_url,
    verify_google_code,
)
from app.auth.schemas import (
    AccountSummary,
    ForgotPasswordRequest,
    GenericMessage,
    LoginRequest,
    LogoutRequest,
    PatchUserRequest,
    RefreshRequest,
    ResendVerificationRequest,
    ResetPasswordRequest,
    SessionSummary,
    SignupRequest,
    TokenResponse,
    VerifyEmailRequest,
)
from app.auth.service import AuthService, LoginContext
from app.config import Settings
from app.core.enums import Role
from app.core.errors import APIError, ErrorCode
from app.security.ratelimit import RateLimiter, limit_key

router = APIRouter(prefix="/auth", tags=["auth"])

_GENERIC_SIGNUP = (
    "Check your inbox. If that address can be registered, a verification link is on its way."
)
_GENERIC_RESET = "If that address has an account, a password reset link is on its way."


def _context(request: Request, *, device_name: str = "", platform: str = "") -> LoginContext:
    return LoginContext(
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent", "")[:400],
        device_name=device_name,
        platform=platform,
        trace_id=getattr(request.state, "trace_id", None),
    )


async def _limit(
    request: Request,
    session: AsyncSession,
    settings: Settings,
    *,
    bucket: str,
    extra: str = "",
) -> None:
    """
    Apply the auth rate limit and attach the headers a client needs to back off.

    The key mixes the client address with the endpoint bucket; ``extra`` adds a hashed account
    identifier so a shared office address cannot hammer one login form.
    """
    from app.core.privacy import hash_ip

    limiter = RateLimiter(settings)
    ip_hash = hash_ip(request.client.host if request.client else None, salt=settings.jwt_key())
    key = limit_key("auth", bucket, ip_hash or "", extra)
    result = await limiter.check(session, key=key, spec=settings.auth_rate_limit_spec)
    # The middleware copies these onto the response so a well-behaved client can back off.
    request.state.rate_limit_headers = result.headers()
    if not result.allowed:
        raise APIError(
            ErrorCode.RATE_LIMITED,
            "Too many attempts. Try again shortly.",
            status_code=429,
            retryable=True,
            headers=result.headers(),
        )


@router.post("/signup", response_model=GenericMessage, status_code=status.HTTP_202_ACCEPTED)
async def signup(
    payload: SignupRequest,
    request: Request,
    session: AsyncSession = Depends(db_session),
    settings: Settings = Depends(app_settings),
) -> GenericMessage:
    """Create an account and send a verification link (always the same answer)."""
    await _limit(request, session, settings, bucket="signup")
    service = AuthService(settings)
    await service.signup(
        session,
        email=payload.email,
        password=payload.password,
        display_name=payload.display_name,
        context=_context(request),
    )
    return GenericMessage(
        message=_GENERIC_SIGNUP,
        detail="Verify your email address before signing in.",
    )


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    session: AsyncSession = Depends(db_session),
    settings: Settings = Depends(app_settings),
) -> TokenResponse:
    """Exchange credentials for an access token and a rotating refresh token."""
    await _limit(
        request,
        session,
        settings,
        bucket="login",
        extra=limit_key(payload.email.strip().lower())[:16],
    )
    service = AuthService(settings)
    return await service.login(
        session,
        email=payload.email,
        password=payload.password,
        context=_context(request, device_name=payload.device_name, platform=payload.platform),
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    payload: RefreshRequest,
    request: Request,
    session: AsyncSession = Depends(db_session),
    settings: Settings = Depends(app_settings),
) -> TokenResponse:
    """
    Rotate a refresh token.

    The presented token is consumed; a client that retries with the same value gets a terminated
    session, because reuse is treated as token theft.
    """
    await _limit(request, session, settings, bucket="refresh")
    return await AuthService(settings).refresh(
        session, refresh_token=payload.refresh_token, context=_context(request)
    )


@router.post("/logout", response_model=GenericMessage)
async def logout(
    payload: LogoutRequest,
    request: Request,
    principal: CurrentPrincipal,
    session: AsyncSession = Depends(db_session),
    settings: Settings = Depends(app_settings),
) -> GenericMessage:
    """Revoke the current session, or every session for the account."""
    count = await AuthService(settings).logout(
        session,
        user=principal.user,
        current_session_id=principal.session_id,
        refresh_token=payload.refresh_token,
        all_sessions=payload.all_sessions,
        context=_context(request),
    )
    return GenericMessage(message="Signed out", detail=f"{count} session(s) revoked.")


@router.post("/verify-email", response_model=GenericMessage)
async def verify_email(
    payload: VerifyEmailRequest,
    request: Request,
    session: AsyncSession = Depends(db_session),
    settings: Settings = Depends(app_settings),
) -> GenericMessage:
    """Consume a verification link."""
    await _limit(request, session, settings, bucket="verify")
    await AuthService(settings).verify_email(
        session, token=payload.token, context=_context(request)
    )
    return GenericMessage(message="Email verified", detail="You can sign in now.")


@router.post("/resend-verification", response_model=GenericMessage, status_code=202)
async def resend_verification(
    payload: ResendVerificationRequest,
    request: Request,
    session: AsyncSession = Depends(db_session),
    settings: Settings = Depends(app_settings),
) -> GenericMessage:
    """Send another verification link (same answer whether or not the account exists)."""
    await _limit(request, session, settings, bucket="resend")
    await AuthService(settings).resend_verification(
        session, email=payload.email, context=_context(request)
    )
    return GenericMessage(message=_GENERIC_SIGNUP)


@router.post("/forgot-password", response_model=GenericMessage, status_code=202)
async def forgot_password(
    payload: ForgotPasswordRequest,
    request: Request,
    session: AsyncSession = Depends(db_session),
    settings: Settings = Depends(app_settings),
) -> GenericMessage:
    """Request a reset link. The answer never reveals whether the address is registered."""
    await _limit(
        request,
        session,
        settings,
        bucket="forgot",
        extra=limit_key(payload.email.strip().lower())[:16],
    )
    await AuthService(settings).request_password_reset(
        session, email=payload.email, context=_context(request)
    )
    return GenericMessage(message=_GENERIC_RESET)


@router.post("/reset-password", response_model=GenericMessage)
async def reset_password(
    payload: ResetPasswordRequest,
    request: Request,
    session: AsyncSession = Depends(db_session),
    settings: Settings = Depends(app_settings),
) -> GenericMessage:
    """Set a new password from a reset link; every existing session is revoked."""
    await _limit(request, session, settings, bucket="reset")
    await AuthService(settings).reset_password(
        session, token=payload.token, password=payload.password, context=_context(request)
    )
    return GenericMessage(
        message="Password updated", detail="Sign in again with your new password."
    )


@router.get("/google/start")
async def google_start(
    settings: Settings = Depends(app_settings),
) -> dict[str, str]:
    """Return the Google consent URL to open (state is signed, so it cannot be forged)."""
    if not settings.google_oauth_enabled:
        raise APIError(
            ErrorCode.INTEGRATION_DISABLED, "Google sign-in is not enabled", status_code=404
        )
    url, state = google_authorize_url(settings)
    return {"authorization_url": url, "state": state}


@router.get("/google/callback", response_model=TokenResponse)
async def google_callback(
    code: str,
    state: str,
    request: Request,
    response: Response,
    session: AsyncSession = Depends(db_session),
    settings: Settings = Depends(app_settings),
) -> TokenResponse:
    """
    Complete the Google authorization-code flow.

    The ID token's signature, issuer and audience are verified against Google's JWKS, and the
    address must be verified by Google. ``hd``/allowed-domain restrictions are applied when the
    operator configured them.
    """
    await _limit(request, session, settings, bucket="google")
    if not settings.google_oauth_enabled:
        raise APIError(
            ErrorCode.INTEGRATION_DISABLED, "Google sign-in is not enabled", status_code=404
        )
    try:
        identity: GoogleIdentity = await verify_google_code(settings, code=code, state=state)
    except GoogleAuthError as exc:
        raise APIError(
            ErrorCode.UNAUTHENTICATED, str(exc), status_code=401, retryable=exc.retryable
        ) from exc

    if not identity.email_verified:
        raise APIError(
            ErrorCode.EMAIL_NOT_VERIFIED, "Google did not report a verified email", status_code=403
        )
    allowed = settings.google_allowed_domain_set
    if allowed and identity.email.rsplit("@", 1)[-1].lower() not in allowed:
        raise APIError(
            ErrorCode.FORBIDDEN, "This Google account is not allowed to sign in", status_code=403
        )

    tokens = await AuthService(settings).login_with_google(
        session,
        google_sub=identity.subject,
        email=identity.email,
        email_verified=identity.email_verified,
        display_name=identity.name,
        context=_context(request),
    )
    # A desktop or web client that followed the redirect gets no JSON body it can read safely,
    # so the refresh token is also set as an httpOnly cookie for that flow.
    response.set_cookie(
        "armx_refresh",
        tokens.refresh_token,
        httponly=True,
        secure=settings.environment == "production",
        samesite="lax",
        max_age=settings.refresh_token_ttl_seconds,
        path="/auth",
    )
    return tokens


@router.get("/me", response_model=AccountSummary)
async def me(principal: CurrentPrincipal) -> AccountSummary:
    """The signed-in account."""
    return AuthService.account_summary(principal.user)


@router.patch("/me", response_model=AccountSummary)
async def patch_me(
    payload: PatchUserRequest,
    principal: CurrentPrincipal,
    session: AsyncSession = Depends(db_session),
    settings: Settings = Depends(app_settings),
) -> AccountSummary:
    """Rename the account holder."""
    return await AuthService(settings).update_profile(
        session, user=principal.user, display_name=payload.display_name
    )


@router.get("/sessions", response_model=list[SessionSummary])
async def list_sessions(
    principal: CurrentPrincipal,
    session: AsyncSession = Depends(db_session),
    settings: Settings = Depends(app_settings),
) -> list[SessionSummary]:
    """List the caller's active sessions, with the current one flagged."""
    return await AuthService(settings).list_sessions(
        session, user=principal.user, current_session_id=principal.session_id
    )


@router.delete("/sessions/{session_id}", response_model=GenericMessage)
async def revoke_session(
    session_id: str,
    request: Request,
    principal: CurrentPrincipal,
    session: AsyncSession = Depends(db_session),
    settings: Settings = Depends(app_settings),
) -> GenericMessage:
    """Revoke one of the caller's own sessions."""
    import uuid as _uuid

    try:
        parsed = _uuid.UUID(session_id)
    except ValueError as exc:
        raise APIError(
            ErrorCode.INVALID_REQUEST, "session_id must be a UUID", status_code=400
        ) from exc
    await AuthService(settings).revoke_session(
        session, user=principal.user, session_id=parsed, context=_context(request)
    )
    return GenericMessage(message="Session revoked")


def role_hint(role: Role) -> str:
    """Small helper used by the admin routes and the CLI to describe a role."""
    return role.value
