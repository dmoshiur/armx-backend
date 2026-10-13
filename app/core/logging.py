# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Logging with mandatory redaction.

Two output formats are supported: ``console`` for humans and ``json`` for a log drain.
Both pass through the same :class:`RedactionFilter`, so a credential cannot reach a log
file just because the format changed.

Every record carries ``request_id`` and, inside a harness session, ``trace_id``.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from contextvars import ContextVar
from typing import Any, Final

from app.core.redaction import redact_text

__all__ = [
    "RedactionFilter",
    "bind_trace_context",
    "clear_trace_context",
    "configure_logging",
    "current_request_id",
    "current_trace_id",
    "get_logger",
]

request_id_var: ContextVar[str | None] = ContextVar("armx_request_id", default=None)
trace_id_var: ContextVar[str | None] = ContextVar("armx_trace_id", default=None)
actor_var: ContextVar[str | None] = ContextVar("armx_actor_id", default=None)

_KV_SECRET_RE: Final = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization|client_secret|"
    r"owner_password|refresh_token|access_token|signature|pin)\b\s*[=:]\s*([^\s,;\"']+)"
)
_LONG_OPAQUE_RE: Final = re.compile(r"\b[A-Za-z0-9_\-]{40,}\b")


class RedactionFilter(logging.Filter):
    """Scrub credentials out of the formatted message and the extra fields."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)
        message = _KV_SECRET_RE.sub(lambda m: f"{m.group(1)}=[redacted]", message)
        message = _LONG_OPAQUE_RE.sub("[redacted]", redact_text(message))
        record.msg = message
        record.args = ()
        for key in ("token", "secret", "password", "authorization", "api_key"):
            if hasattr(record, key):
                setattr(record, key, "[redacted]")
        return True


class JsonFormatter(logging.Formatter):
    """Single-line JSON records with the ambient request/trace/actor identifiers."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        request_id = request_id_var.get()
        if request_id:
            payload["request_id"] = request_id
        trace_id = trace_id_var.get()
        if trace_id:
            payload["trace_id"] = trace_id
        actor = actor_var.get()
        if actor:
            payload["actor_id"] = actor
        if record.exc_info:
            payload["exception"] = (
                record.exc_info[0].__name__ if record.exc_info[0] else "Exception"
            )
        return json.dumps(payload, ensure_ascii=False)


class ConsoleFormatter(logging.Formatter):
    """Human-readable format including whichever context identifiers are set."""

    def __init__(self) -> None:
        super().__init__("%(asctime)s %(levelname)-7s %(name)s: %(message)s", "%H:%M:%S")

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        suffixes = []
        for label, var in (("req", request_id_var), ("trace", trace_id_var), ("actor", actor_var)):
            value = var.get()
            if value:
                suffixes.append(f"{label}={value}")
        return f"{base} [{' '.join(suffixes)}]" if suffixes else base


def configure_logging(*, level: str = "INFO", fmt: str = "console") -> None:
    """Install handlers on the root logger. Safe to call more than once."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter() if fmt == "json" else ConsoleFormatter())
    handler.addFilter(RedactionFilter())

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level.upper())

    # Uvicorn installs its own handlers; route them through the same redacting handler.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uvicorn_logger = logging.getLogger(name)
        for existing in list(uvicorn_logger.handlers):
            uvicorn_logger.removeHandler(existing)
        uvicorn_logger.propagate = True

    # SQLAlchemy is noisy at INFO; echo only when explicitly enabled.
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("aiomqtt").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Package logger factory (``armx.<name>``)."""
    return logging.getLogger(name if name.startswith("armx") else f"armx.{name}")


def bind_trace_context(
    *,
    request_id: str | None = None,
    trace_id: str | None = None,
    actor_id: str | None = None,
) -> None:
    """Attach correlation identifiers to every log record emitted in this context."""
    if request_id is not None:
        request_id_var.set(request_id)
    if trace_id is not None:
        trace_id_var.set(trace_id)
    if actor_id is not None:
        actor_var.set(actor_id)


def clear_trace_context() -> None:
    request_id_var.set(None)
    trace_id_var.set(None)
    actor_var.set(None)


def current_request_id() -> str | None:
    return request_id_var.get()


def current_trace_id() -> str | None:
    return trace_id_var.get()
