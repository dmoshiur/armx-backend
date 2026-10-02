# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection

from app.config import get_settings
from app.db import models  # noqa: F401 - registers model metadata for Alembic.
from app.db.base import Base
from app.db.engine import create_database_engine
from app.db.urls import DatabaseBackend, database_backend

config = context.config
settings = get_settings()
config.set_main_option("sqlalchemy.url", settings.database_url.replace("%", "%%"))

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata
_is_sqlite_family = database_backend(settings.database_url) in {
    DatabaseBackend.AIOSQLITE,
    DatabaseBackend.LIBSQL,
}


def run_migrations_offline() -> None:
    """Run migrations without creating an Engine."""

    context.configure(
        url=settings.database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        # SQLite/libSQL do not support most ALTER TABLE forms; batch mode rewrites tables.
        render_as_batch=_is_sqlite_family,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        render_as_batch=_is_sqlite_family,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations through the application's asynchronous engine factory."""

    connectable = create_database_engine(
        settings.database_url,
        echo=settings.database_echo,
        pool_pre_ping=settings.database_pool_pre_ping,
        auth_token=(
            settings.turso_auth_token.get_secret_value()
            if settings.turso_auth_token is not None
            else None
        ),
        timeout_seconds=settings.database_timeout_seconds,
        poolclass=pool.NullPool,
    )
    try:
        async with connectable.connect() as connection:
            await connection.run_sync(do_run_migrations)
    finally:
        await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
