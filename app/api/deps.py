# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Shared FastAPI dependencies.

``app_settings`` reads the settings object the application was *built* with
(``create_app(settings)``) and only falls back to the process singleton when the app was
constructed from the environment. That keeps tests honest: a test that builds an app with an
isolated database and mock LLM sees those settings reflected in every endpoint, including
``/ready`` and ``/metrics``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.db.session import get_sessionmaker
from app.registry.core import ToolRegistry, registry

__all__ = ["app_registry", "app_settings", "db_session"]


def app_settings(request: Request) -> Settings:
    """The settings the running application was constructed with."""
    configured = getattr(request.app.state, "settings", None)
    if isinstance(configured, Settings):
        return configured
    return get_settings()


def app_registry(request: Request) -> ToolRegistry:
    """The tool registry discovered at startup for this application."""
    discovered = getattr(request.app.state, "registry", None)
    if isinstance(discovered, ToolRegistry):
        return discovered
    return registry


async def db_session(request: Request) -> AsyncIterator[AsyncSession]:
    """
    Request-scoped database session.

    Bound to the settings the application was built with, so the app in a test talks to the
    test database. The session is rolled back on any exception: a failed tool call must not
    leave a half-written transaction for the next request to commit.
    """
    factory = await get_sessionmaker(app_settings(request))
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
