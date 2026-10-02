# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import get_settings

_settings = get_settings()
engine = create_async_engine(
    _settings.database_url,
    echo=_settings.database_echo,
    pool_pre_ping=True,
)
SessionFactory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_session() -> AsyncIterator[AsyncSession]:
    """Yield a request-scoped asynchronous database session."""

    async with SessionFactory() as session:
        yield session


async def dispose_engine() -> None:
    """Dispose the process-wide database connection pool."""

    await engine.dispose()
