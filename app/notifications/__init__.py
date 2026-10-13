# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""Outbound notifications: transactional email (verification, password reset)."""

from app.notifications.mailer import Mailer, send_template_email

__all__ = ["Mailer", "send_template_email"]
