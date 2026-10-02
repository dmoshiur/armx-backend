# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import get_settings
from app.db.engine import create_database_engine

_settings = get_settings()

engine = create_database_engine(
    _settings.database_url,
    echo=_settings.database_echo,
    pool_pre_ping=_settings.database_pool_pre_ping,
    auth_token=(
        _settings.turso_auth_token.get_secret_value()
        if _settings.turso_auth_token is not None
        else None
    ),
    timeout_seconds=_settings.database_timeout_seconds,
)
SessionFactory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_session() -> AsyncIterator[AsyncSession]:
    """Yield a request-scoped asynchronous database session."""

    async with SessionFactory() as session:
        yield session


async def dispose_engine() -> None:
    """Dispose the process-wide database connection pool."""

    await engine.dispose()
