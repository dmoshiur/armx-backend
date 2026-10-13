# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Data-minimisation helpers.

The backend stores identifiers, not personal data, wherever the function still works:
client IPs are salted-hashed, emails are masked in admin listings, and memory content is
encrypted at rest. None of this weakens an authorization decision - it only limits what a
database dump or a log file exposes.
"""

from __future__ import annotations

from app.core.crypto import hmac_hex

__all__ = ["hash_ip", "mask_email", "mask_token"]


def hash_ip(ip_address: str | None, *, salt: str) -> str | None:
    """
    Salted hash of a client IP.

    Deterministic within a deployment (so abuse patterns remain visible to an operator) but
    not reversible without the server secret.
    """
    if not ip_address:
        return None
    return hmac_hex(salt, f"ip:{ip_address}")[:64]


def mask_email(email: str) -> str:
    """``someone@example.com`` -> ``s******@example.com`` for admin listings and logs."""
    local, _, domain = email.partition("@")
    if not domain:
        return "***"
    masked_local = "*" if len(local) <= 1 else f"{local[0]}{'*' * min(len(local) - 1, 6)}"
    return f"{masked_local}@{domain}"


def mask_token(token: str | None, *, keep: int = 4) -> str:
    """Show only the tail of a token, e.g. for support diagnostics."""
    if not token:
        return ""
    if len(token) <= keep:
        return "*" * len(token)
    return f"{'*' * 6}{token[-keep:]}"
