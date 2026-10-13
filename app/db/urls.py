# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Database URL handling.

The application always speaks to the database through SQLAlchemy's async engine. In
production that is PostgreSQL - self-hosted or Supabase, whose connection string is a
plain PostgreSQL URL (``...pooler.supabase.com:6543/postgres`` for the transaction
pooler, ``:5432`` for a direct connection). Locally it is SQLite so the stack boots with
zero external services.

The security policy does not vary by dialect: risk tiers, approvals and audit rows are
identical either way.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

__all__ = [
    "async_database_url",
    "ensure_sqlite_directory",
    "is_postgres",
    "is_sqlite",
    "redacted_database_url",
    "sync_database_url",
]

_POSTGRES_SCHEMES = {"postgres", "postgresql"}
_SQLITE_SCHEMES = {"sqlite", "sqlite+aiosqlite", "sqlite+pysqlite"}


def async_database_url(raw_url: str) -> str:
    """Normalise an operator-supplied URL to the async driver this app uses."""
    url = (raw_url or "").strip()
    if not url:
        raise ValueError("DATABASE_URL is required")
    scheme, _, rest = url.partition("://")
    if not rest:
        raise ValueError("DATABASE_URL must include a scheme separator, e.g. postgresql://...")
    normalised = scheme.lower()
    if normalised in _POSTGRES_SCHEMES:
        return f"postgresql+psycopg://{rest}"
    if normalised == "sqlite":  # sqlite:///relative/path.db
        return f"sqlite+aiosqlite://{rest}"
    if normalised in _SQLITE_SCHEMES:
        return url
    raise ValueError(
        f"unsupported DATABASE_URL scheme {scheme!r}: expected postgresql:// or sqlite"
    )


def sync_database_url(raw_url: str) -> str:
    """Synchronous equivalent, used by Alembic's offline mode and by ``pg_dump``."""
    url = async_database_url(raw_url)
    scheme, _, rest = url.partition("://")
    if scheme.startswith("postgresql"):
        return f"postgresql+psycopg://{rest}"
    return f"sqlite://{rest}"


def is_postgres(raw_url: str) -> bool:
    return async_database_url(raw_url).startswith("postgresql")


def is_sqlite(raw_url: str) -> bool:
    return async_database_url(raw_url).startswith("sqlite")


def redacted_database_url(raw_url: str) -> str:
    """Safe-to-log form: password replaced, query parameters dropped."""
    try:
        url = async_database_url(raw_url)
    except ValueError:
        return "[invalid database url]"
    scheme, _, rest = url.partition("://")
    if scheme.startswith("sqlite"):
        return f"{scheme}://{rest.split('?', 1)[0]}"
    parts = urlsplit(url)
    netloc = parts.netloc
    if "@" in netloc:
        credentials, _, host = netloc.rpartition("@")
        user, _, _password = credentials.partition(":")
        netloc = f"{user}:***@{host}"
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def sqlite_file_path(raw_url: str) -> Path | None:
    """
    Filesystem path for a file-backed SQLite URL, or ``None`` for an in-memory database.

    ``sqlite+aiosqlite:///./data/armx.db`` is relative to the working directory;
    ``sqlite+aiosqlite:////srv/armx/armx.db`` (four slashes) is absolute.
    """
    url = async_database_url(raw_url)
    if not url.startswith("sqlite"):
        return None
    rest = url.partition("://")[2].split("?", 1)[0]
    if not rest or rest.startswith(":memory:") or "mode=memory" in rest:
        return None
    if rest.startswith("//"):
        return Path("/" + rest.lstrip("/"))
    return Path(rest.lstrip("/"))


def ensure_sqlite_directory(raw_url: str) -> None:
    """Create the parent directory of a file-backed SQLite database."""
    path = sqlite_file_path(raw_url)
    if path is None:
        return
    target = path if path.is_absolute() else Path.cwd() / path
    target.parent.mkdir(parents=True, exist_ok=True)
