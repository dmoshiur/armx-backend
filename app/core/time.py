# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""Time helpers. Everything the backend stores or compares is timezone-aware UTC."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

__all__ = ["ensure_utc", "isoformat_z", "parse_isoformat", "utcnow"]


def utcnow() -> datetime:
    """Timezone-aware current UTC time (never ``datetime.utcnow``)."""
    return datetime.now(UTC)


def ensure_utc(value: datetime) -> datetime:
    """Coerce a datetime to aware UTC, rejecting naive values from clients."""
    if value.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    return value.astimezone(UTC)


def isoformat_z(value: datetime) -> str:
    """RFC 3339 with a ``Z`` suffix, which is what the clients parse."""
    return ensure_utc(value).isoformat().replace("+00:00", "Z")


def parse_isoformat(value: str) -> datetime:
    """Parse an RFC 3339 string, requiring an explicit offset."""
    text = value.strip()
    if text.endswith(("z", "Z")):
        text = f"{text[:-1]}+00:00"
    return ensure_utc(datetime.fromisoformat(text))


def expires_in(seconds: int) -> datetime:
    """Deadline helper: ``utcnow() + seconds``."""
    return utcnow() + timedelta(seconds=seconds)
