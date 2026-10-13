# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Email templates.

Plain text on purpose: no HTML renderer, no remote images, no tracking pixel, and nothing that
could leak a token through a third-party asset. Every message states what happened, what to do,
and how long the link is valid for.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from app.config import Settings

__all__ = ["RenderedEmail", "render_reset_email", "render_verification_email"]

_SIGNATURE: Final = (
    "\n\n--\nA.R.M.X AI\n"
    "If you did not request this, you can ignore this message; nothing will change.\n"
)


@dataclass(frozen=True, slots=True)
class RenderedEmail:
    subject: str
    body_text: str


def _client_base_url(settings: Settings) -> str:
    """
    Base URL used to build user-facing links.

    Derived from the configured CORS origins - the operator has already declared the real client
    origins there - and falling back to the first API origin for local development.
    """
    origins = settings.cors_origin_list
    if origins:
        return origins[0].rstrip("/")
    return f"http://localhost:{settings.api_port}"


def render_verification_email(
    settings: Settings,
    *,
    token: str,
    display_name: str = "",
    expires_in_minutes: int = 30,
) -> RenderedEmail:
    greeting = f"Hello {display_name}," if display_name else "Hello,"
    link = f"{_client_base_url(settings)}/verify-email?token={token}"
    return RenderedEmail(
        subject="Verify your A.R.M.X AI email address",
        body_text=(
            f"{greeting}\n\n"
            "Confirm this email address to activate your A.R.M.X AI account.\n\n"
            f"Verification link (valid for {expires_in_minutes} minutes, single use):\n{link}\n\n"
            "You cannot sign in until the address is verified."
            f"{_SIGNATURE}"
        ),
    )


def render_reset_email(
    settings: Settings,
    *,
    token: str,
    display_name: str = "",
    expires_in_minutes: int = 30,
) -> RenderedEmail:
    greeting = f"Hello {display_name}," if display_name else "Hello,"
    link = f"{_client_base_url(settings)}/reset-password?token={token}"
    return RenderedEmail(
        subject="Reset your A.R.M.X AI password",
        body_text=(
            f"{greeting}\n\n"
            "A password reset was requested for your A.R.M.X AI account.\n\n"
            f"Reset link (valid for {expires_in_minutes} minutes, single use):\n{link}\n\n"
            "Resetting your password signs out every other device.\n"
            "If this was not you, change your password immediately and review your sessions."
            f"{_SIGNATURE}"
        ),
    )
