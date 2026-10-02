# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""Database URL helpers shared by settings, the engine, and Alembic.

Turso hands out credentials as ``libsql://<database>.<org>.turso.io`` (or an ``https://``
URL for the HTTP API), while SQLAlchemy needs a dialect-qualified URL.  These helpers
normalize what an operator pastes into ``DATABASE_URL`` without ever rewriting the
credentials themselves - auth tokens stay in ``TURSO_AUTH_TOKEN`` and never enter the URL.
"""

from __future__ import annotations

from enum import StrEnum
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_TURSO_SCHEMES = {"libsql", "libsqls", "http", "https"}
_SECURE_SCHEMES = {"libsql", "libsqls", "https"}


class DatabaseBackend(StrEnum):
    """Supported persistence backends."""

    AIOSQLITE = "aiosqlite"
    LIBSQL = "libsql"
    UNSUPPORTED = "unsupported"


def normalize_database_url(raw: str) -> str:
    """Return a SQLAlchemy-qualified URL for the configured database.

    ``libsql://``, ``https://`` and ``http://`` Turso URLs are rewritten to
    ``sqlite+libsql://`` so an operator can paste the value printed by the Turso CLI.
    """

    value = raw.strip()
    scheme = value.split("://", 1)[0].lower() if "://" in value else ""
    if scheme not in _TURSO_SCHEMES:
        return value
    parts = urlsplit(value)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query.setdefault("secure", "true" if parts.scheme in _SECURE_SCHEMES else "false")
    return urlunsplit(
        ("sqlite+libsql", parts.netloc, parts.path, urlencode(sorted(query.items())), "")
    )


def database_backend(raw: str) -> DatabaseBackend:
    """Classify a database URL without connecting to it."""

    scheme = raw.split("://", 1)[0].lower() if "://" in raw else ""
    if scheme == "sqlite+libsql":
        return DatabaseBackend.LIBSQL
    if scheme in {"sqlite+aiosqlite", "sqlite"}:
        return DatabaseBackend.AIOSQLITE
    return DatabaseBackend.UNSUPPORTED


def libsql_target_is_remote(raw: str) -> bool:
    """Return True when a libSQL URL points at a server rather than a local file."""

    return database_backend(raw) is DatabaseBackend.LIBSQL and bool(
        urlsplit(normalize_database_url(raw)).netloc
    )


def _remote_secure_flag(raw: str) -> str | None:
    parts = urlsplit(normalize_database_url(raw))
    if not parts.netloc:
        return None
    return dict(parse_qsl(parts.query, keep_blank_values=True)).get("secure")


def libsql_requests_plaintext(raw: str) -> bool:
    """Return True when a remote libSQL URL explicitly disables TLS (``secure=false``)."""

    secure = _remote_secure_flag(raw)
    return secure is not None and secure.strip().lower() in {"false", "0", "no"}


def libsql_requests_tls(raw: str) -> bool:
    """Return True when a remote libSQL URL states TLS explicitly (``secure=true``)."""

    secure = _remote_secure_flag(raw)
    return secure is not None and secure.strip().lower() in {"true", "1", "yes"}
