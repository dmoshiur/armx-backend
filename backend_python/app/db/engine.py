# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""Database engine construction shared by the app, Alembic, and tests."""

from __future__ import annotations

from typing import Any

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import Pool

from app.db.urls import DatabaseBackend, database_backend, normalize_database_url

_SQLITE_FAMILY = {DatabaseBackend.AIOSQLITE, DatabaseBackend.LIBSQL}


def create_database_engine(
    database_url: str,
    *,
    echo: bool = False,
    pool_pre_ping: bool = True,
    auth_token: str | None = None,
    timeout_seconds: float | None = None,
    poolclass: type[Pool] | None = None,
) -> AsyncEngine:
    """Create the async engine for a supported ``DATABASE_URL``.

    * ``sqlite+libsql`` (Turso) runs through the asyncio dialect in :mod:`app.db.libsql_async`,
      which offloads every blocking driver call to a dedicated worker thread.
    * Foreign-key enforcement is switched on for every SQLite-family connection so local
      development matches libSQL/Turso instead of silently accepting dangling rows.
    """

    url = normalize_database_url(database_url)
    backend = database_backend(url)
    kwargs: dict[str, Any] = {"echo": echo, "pool_pre_ping": pool_pre_ping}
    if poolclass is not None:
        kwargs["poolclass"] = poolclass
    if backend is DatabaseBackend.LIBSQL:
        from app.db import libsql_async  # noqa: F401 - registers the sqlite+libsql dialect

        connect_args: dict[str, Any] = {}
        if auth_token:
            connect_args["auth_token"] = auth_token
        if timeout_seconds is not None:
            connect_args["timeout"] = timeout_seconds
        if connect_args:
            kwargs["connect_args"] = connect_args
        # Remote libSQL speaks HTTP(S): recycle pooled connections so a stale one is never
        # reused after a Turso failover, and keep the pool small since every statement is a
        # round trip.
        kwargs["pool_recycle"] = 900

    engine = create_async_engine(url, **kwargs)

    if backend in _SQLITE_FAMILY:

        @event.listens_for(engine.sync_engine, "connect")
        def _enable_foreign_keys(dbapi_connection: Any, connection_record: Any) -> None:
            del connection_record
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute("PRAGMA foreign_keys=ON")
            finally:
                cursor.close()

    return engine
