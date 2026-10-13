# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""Alembic environment. Reads DATABASE_URL from the validated settings object."""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import create_async_engine

# Importing the models module registers every table on Base.metadata.
import app.db.models  # noqa: F401  (imported for its side effect)
from app.config import get_settings
from app.db.base import Base
from app.db.urls import async_database_url, sync_database_url

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def render_item(type_: object, obj: object, autogen_context: object) -> str | bool:
    """
    Render the application's TypeDecorators as their underlying SQL types.

    Without this, autogenerate would emit ``app.db.base.UtcDateTime()`` in a migration, coupling
    every historical revision to the current application code. The underlying types
    (``VARCHAR(n)``, ``TIMESTAMP WITH TIME ZONE``) are what the database actually stores.
    """
    name = type(type_).__name__
    if name == "UtcDateTime":
        return "sa.DateTime(timezone=True)"
    if name == "EnumStr":
        length = getattr(type_, "length", 32)
        return f"sa.String(length={length})"
    return False


# SQLite requires batch mode for any future ALTER that adds or drops a constraint.
_RENDER_AS_BATCH = True


def _database_url() -> str:
    return async_database_url(get_settings().database_url)


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting (``alembic upgrade head --sql``)."""
    context.configure(
        url=sync_database_url(get_settings().database_url),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
        render_as_batch=_RENDER_AS_BATCH,
        render_item=render_item,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: object) -> None:
    context.configure(
        connection=connection,  # type: ignore[arg-type]
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
        render_as_batch=_RENDER_AS_BATCH,
        render_item=render_item,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    engine = create_async_engine(_database_url(), poolclass=pool.NullPool, future=True)
    try:
        async with engine.connect() as connection:
            await connection.run_sync(do_run_migrations)
    finally:
        await engine.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
