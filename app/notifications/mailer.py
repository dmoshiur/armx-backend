# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Transactional email.

Two delivery modes, chosen by ``EMAIL_DELIVERY_MODE``:

* ``outbox`` (default outside production) - the message is written to ``mail_outbox`` and never
  sent. Signup, verification and password reset are therefore testable end to end with no SMTP
  server, and an operator can read the queued mail through the admin API.
* ``smtp`` - a real message goes out over an authenticated, STARTTLS connection.

The single-use token appears only inside the link in the body. It is never logged, never included
in an audit row, and never stored anywhere except as a hash in ``email_tokens``.
"""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from typing import Final

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.core.crypto import random_token
from app.core.logging import get_logger
from app.core.metrics import inc
from app.core.time import utcnow
from app.db.models import MailOutboxMessage
from app.notifications.templates import RenderedEmail, render_reset_email, render_verification_email

__all__ = ["Mailer", "render_reset_email", "render_verification_email", "send_template_email"]

logger = get_logger("notifications.mailer")

_SMTP_TIMEOUT: Final = 15.0


class Mailer:
    """Renders, records and (optionally) delivers transactional email."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    @property
    def delivery_mode(self) -> str:
        return self._settings.email_delivery_mode

    async def send(
        self,
        session: AsyncSession,
        *,
        to_address: str,
        message: RenderedEmail,
        template: str = "generic",
        meta: dict[str, object] | None = None,
    ) -> MailOutboxMessage:
        """
        Send (or queue) one message and return its outbox row.

        A delivery failure with SMTP configured is recorded on the row and reported, never raised
        into the request: an unreachable mail server must not turn a successful signup into a 500.
        """
        record = MailOutboxMessage(
            to_address=to_address[:320],
            subject=message.subject[:200],
            body_text=message.body_text,
            template=template[:64],
            status="queued",
            attempts=0,
            meta=meta or {},
            created_at=utcnow(),
        )
        session.add(record)
        await session.flush()

        if self.delivery_mode == "smtp":
            delivered, error = self._deliver(to_address, message)
            record.attempts += 1
            if delivered:
                record.status = "sent"
                record.sent_at = utcnow()
                inc("emails_sent", {"template": template})
            else:
                record.status = "failed"
                record.error = (error or "unknown error")[:300]
                inc("emails_failed", {"template": template})
                logger.error("email delivery failed for template=%s", template)
            await session.flush()
        else:
            logger.info(
                "email queued in the outbox (template=%s, to=%s); "
                "set EMAIL_DELIVERY_MODE=smtp to deliver",
                template,
                _mask(to_address),
            )
        return record

    def _deliver(self, to_address: str, message: RenderedEmail) -> tuple[bool, str | None]:
        settings = self._settings
        composed = EmailMessage()
        composed["From"] = f"{settings.mail_from_name} <{settings.mail_from_address}>"
        composed["To"] = to_address
        composed["Subject"] = message.subject
        composed.set_content(message.body_text)
        try:
            context = ssl.create_default_context()
            with smtplib.SMTP(
                settings.smtp_host, settings.smtp_port, timeout=_SMTP_TIMEOUT
            ) as client:
                if settings.smtp_starttls:
                    client.starttls(context=context)
                username = settings.smtp_username
                password = (
                    settings.smtp_password.get_secret_value() if settings.smtp_password else ""
                )
                if username:
                    client.login(username, password)
                client.send_message(composed)
        except (smtplib.SMTPException, OSError, ValueError) as exc:
            # Log the exception type only: SMTP errors can echo the recipient and credentials.
            return False, f"{type(exc).__name__}"
        return True, None


def _mask(address: str) -> str:
    local, _, domain = address.partition("@")
    return f"{local[:1]}***@{domain}" if domain else "***"


async def send_template_email(
    session: AsyncSession,
    settings: Settings,
    *,
    to_address: str,
    template: str,
    token: str | None = None,
    display_name: str = "",
    expires_in_minutes: int = 30,
) -> MailOutboxMessage:
    """
    Render and send one of the known templates.

    ``token`` is passed through to the link only; the caller stores its hash.
    """
    if template == "verification":
        message = render_verification_email(
            settings,
            token=token or "",
            display_name=display_name,
            expires_in_minutes=expires_in_minutes,
        )
    elif template == "password_reset":
        message = render_reset_email(
            settings,
            token=token or "",
            display_name=display_name,
            expires_in_minutes=expires_in_minutes,
        )
    else:  # pragma: no cover - guarded by the callers
        raise ValueError(f"unknown email template: {template!r}")

    return await Mailer(settings).send(
        session,
        to_address=to_address,
        message=message,
        template=template,
        meta={"expires_in_minutes": expires_in_minutes},
    )


def new_email_token() -> str:
    """High-entropy single-use token for an email link."""
    return random_token(32)
