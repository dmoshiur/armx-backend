# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Redaction helpers.

Used by the logger, the audit writer, and the admin API. Two invariants:

* A value that *might* be a credential is replaced by ``"[redacted]"`` before it can be
  logged, stored in an audit row, or shown to an admin viewer.
* Untrusted text (tool output, web pages, email bodies) is truncated and stripped of
  control characters before it is stored or handed to the model.
"""

from __future__ import annotations

import re
from typing import Any, Final

__all__ = [
    "REDACTED",
    "redact_arguments",
    "redact_mapping",
    "redact_text",
    "sanitize_untrusted_text",
]

REDACTED: Final = "[redacted]"

#: Substring match (case-insensitive) against mapping keys.
_SECRET_KEY_MARKERS: Final = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "auth_header",
    "private_key",
    "client_secret",
    "access_key",
    "refresh",
    "credential",
    "signature",
    "cookie",
    "session_id",
    "pin",
    "otp",
    "totp",
    "recovery_code",
)

#: Patterns that look like credentials even when the key name does not.
_SECRET_VALUE_PATTERNS: Final = (
    re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}\b"),  # OpenAI-style keys
    re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{16,}\b"),  # Anthropic
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"),  # GitHub tokens
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}\b"),  # JWT
    re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{12,}", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b(?:EAA|IGQ)[A-Za-z0-9]{30,}\b"),  # Meta long-lived tokens
)

_CONTROL_CHARS: Final = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WHITESPACE_RUN: Final = re.compile(r"[ \t]{4,}")

_MAX_KEY_CHARS: Final = 128
_MAX_STRING_CHARS: Final = 2048


def redact_text(value: str) -> str:
    """Replace anything that looks like a credential inside free text."""
    redacted = value
    for pattern in _SECRET_VALUE_PATTERNS:
        redacted = pattern.sub(REDACTED, redacted)
    return redacted


def redact_mapping(value: Any, *, depth: int = 0) -> Any:
    """
    Recursively redact a JSON-like structure.

    Keys whose name suggests a credential are blanked regardless of content, values are
    pattern-redacted, and everything is length-capped so a hostile 10 MB tool result
    cannot be persisted or logged.
    """
    if depth > 6:
        return "[truncated:depth]"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for raw_key, raw_value in list(value.items())[:200]:
            key = str(raw_key)[:_MAX_KEY_CHARS]
            lowered = key.lower()
            if any(marker in lowered for marker in _SECRET_KEY_MARKERS):
                out[key] = REDACTED
            else:
                out[key] = redact_mapping(raw_value, depth=depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [redact_mapping(item, depth=depth + 1) for item in list(value)[:100]]
    if isinstance(value, str):
        text = redact_text(value)
        if len(text) > _MAX_STRING_CHARS:
            return f"{text[:_MAX_STRING_CHARS]}…[truncated]"
        return text
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact_text(str(value))[:_MAX_STRING_CHARS]


def redact_arguments(arguments: Any) -> dict[str, Any]:
    """Audit-safe copy of a tool's arguments (always a mapping)."""
    redacted = redact_mapping(arguments)
    if isinstance(redacted, dict):
        return redacted
    return {"value": redacted}


def sanitize_untrusted_text(value: str, *, max_chars: int = 8000) -> str:
    """
    Normalise external content before it is stored or passed to the model.

    Control characters are stripped, whitespace runs collapsed, and the result is
    truncated. The caller is still responsible for wrapping the text in data-only
    delimiters (see :mod:`app.harness.datasafe`).
    """
    text = _CONTROL_CHARS.sub("", value)
    text = _WHITESPACE_RUN.sub(" ", text)
    if len(text) > max_chars:
        return f"{text[:max_chars]}\n[truncated: original length {len(value)} characters]"
    return text
