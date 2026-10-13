# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Engine and session management.

* One async engine per database URL, cached for the process, with production-appropriate
  pooling (pre-ping, recycle, bounded overflow). Transaction-mode poolers - Supabase's
  ``:6543`` endpoint, PgBouncer - get ``prepare_threshold=None`` so server-side prepared
  statements cannot be shared across pooled backends, which is the usual cause of
  "prepared statement already exists" failures.
* SQLite (local development only) gets ``foreign_keys=ON`` and WAL, so the schema behaves
  the way the production schema does and cascades actually fire in tests.
* Sessions are handed out per request. Nothing in this module decides policy: the Security
  Gateway does that, using the same session object.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import Settings, get_settings
from app.core.logging import get_logger
from app.db.urls import (
    async_database_url,
    ensure_sqlite_directory,
    is_postgres,
    redacted_database_url,
)

__all__ = [
    "check_database",
    "create_engine_for",
    "dispose_engines",
    "get_engine",
    "get_session",
    "get_sessionmaker",
    "session_scope",
]

logger = get_logger("db")

_ENGINES: dict[str, AsyncEngine] = {}
_SESSIONMAKERS: dict[str, async_sessionmaker[AsyncSession]] = {}
_LOCK = asyncio.Lock()


def _looks_like_transaction_pooler(url: str) -> bool:
    lowered = url.lower()
    if "pooler" in lowered:
        return True
    return ":6543/" in lowered or ":6543?" in lowered


def _connect_args(settings: Settings, url: str) -> dict[str, Any]:
    if is_postgres(url):
        options = [f"-c statement_timeout={settings.database_statement_timeout_ms}"]
        args: dict[str, Any] = {
            "application_name": "armx-api",
            "options": " ".join(options),
        }
        if _looks_like_transaction_pooler(url):
            # Transaction pooling cannot reuse server-side prepared statements.
            args["prepare_threshold"] = None
        return args
    return {"check_same_thread": False}


def create_engine_for(settings: Settings | None = None, *, echo: bool | None = None) -> AsyncEngine:
    """Build a new engine for the configured URL (not cached)."""
    configured = settings or get_settings()
    url = async_database_url(configured.database_url)
    if url.startswith("sqlite"):
        ensure_sqlite_directory(url)

    kwargs: dict[str, Any] = {
        "echo": configured.database_echo if echo is None else echo,
        "future": True,
        "pool_pre_ping": True,
        "connect_args": _connect_args(configured, url),
    }
    if is_postgres(url):
        kwargs.update(
            pool_size=configured.database_pool_size,
            max_overflow=configured.database_max_overflow,
            pool_timeout=configured.database_pool_timeout_seconds,
            pool_recycle=configured.database_pool_recycle_seconds,
        )

    engine = create_async_engine(url, **kwargs)

    if url.startswith("sqlite"):

        @event.listens_for(engine.sync_engine, "connect")
        def _sqlite_pragmas(dbapi_connection: Any, _record: Any) -> None:
            cursor = dbapi_connection.cursor()
            try:
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.execute("PRAGMA busy_timeout=5000")
            finally:
                cursor.close()

    logger.info(
        "database engine ready",
        extra={"dialect": "postgresql" if is_postgres(url) else "sqlite"},
    )
    return engine


async def get_engine(settings: Settings | None = None) -> AsyncEngine:
    """Process-wide engine for the configured URL."""
    configured = settings or get_settings()
    url = async_database_url(configured.database_url)
    engine = _ENGINES.get(url)
    if engine is not None:
        return engine
    # The lock protects creation only; it is never held across another locking call
    # (asyncio.Lock is not reentrant, and get_sessionmaker needs the engine).
    async with _LOCK:
        engine = _ENGINES.get(url)
        if engine is None:
            engine = create_engine_for(configured)
            _ENGINES[url] = engine
            logger.info("connected to %s", redacted_database_url(url))
        return engine


async def get_sessionmaker(
    settings: Settings | None = None,
) -> async_sessionmaker[AsyncSession]:
    """Session factory bound to the cached engine."""
    configured = settings or get_settings()
    url = async_database_url(configured.database_url)
    factory = _SESSIONMAKERS.get(url)
    if factory is not None:
        return factory
    engine = await get_engine(configured)
    factory = _SESSIONMAKERS.get(url)
    if factory is None:
        # Two concurrent first-callers may each build a factory; both are valid and one wins
        # the assignment, which is cheaper than serialising every request behind a lock.
        factory = async_sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
        _SESSIONMAKERS[url] = factory
    return factory


async def get_session(settings: Settings | None = None) -> AsyncIterator[AsyncSession]:
    """
    Open a session for the configured database.

    Request handlers use the ``db_session`` dependency in :mod:`app.api.deps` instead of this
    function directly, because that one resolves the settings the running application was built
    with - which is what makes an isolated test database actually isolated.
    """
    factory = await get_sessionmaker(settings)
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


@asynccontextmanager
async def session_scope(settings: Settings | None = None) -> AsyncIterator[AsyncSession]:
    """Session scope for background tasks, the worker, and CLI commands."""
    factory = await get_sessionmaker(settings)
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def check_database(
    session: AsyncSession | None = None, settings: Settings | None = None
) -> tuple[bool, str | None]:
    """``SELECT 1`` health probe. Returns ``(ok, error_message)`` without leaking details."""
    try:
        if session is not None:
            await session.execute(text("SELECT 1"))
        else:
            async with session_scope(settings) as own_session:
                await own_session.execute(text("SELECT 1"))
        return True, None
    except Exception as exc:
        logger.warning("database health probe failed: %s", type(exc).__name__)
        return False, "database unavailable"


async def dispose_engines() -> None:
    """Close every cached engine (shutdown and tests)."""
    async with _LOCK:
        engines = list(_ENGINES.values())
        _ENGINES.clear()
        _SESSIONMAKERS.clear()
    for engine in engines:
        await engine.dispose()
