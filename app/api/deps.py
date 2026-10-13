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
from typing import TYPE_CHECKING

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.db.session import get_sessionmaker
from app.llm.base import LLMProvider
from app.llm.factory import build_provider
from app.registry.core import ToolRegistry, registry
from app.security.gateway import ActorRef, SecurityGateway

if TYPE_CHECKING:  # pragma: no cover - typing only; avoids an import cycle with app.auth.deps
    from app.auth.dependencies import Principal

__all__ = [
    "actor_for",
    "app_gateway",
    "app_llm",
    "app_registry",
    "app_settings",
    "db_session",
]


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


def app_gateway(
    settings: Settings = Depends(app_settings),
    tools: ToolRegistry = Depends(app_registry),
) -> SecurityGateway:
    """The Security Gateway for this application, bound to the discovered registry."""
    return SecurityGateway(settings, tools)


def app_llm(
    request: Request,
    settings: Settings = Depends(app_settings),
) -> LLMProvider:
    """
    The configured model provider, created once per application.

    Built lazily and cached on the application state: constructing it per request would open an
    HTTP client (and a TLS handshake) for every message. A test can override the provider by
    setting ``app.state.llm_provider`` before the first call, which is how the harness tests pin
    a scripted model without touching the network.
    """
    existing = getattr(request.app.state, "llm_provider", None)
    if existing is not None and callable(getattr(existing, "complete", None)):
        provider: LLMProvider = existing
        return provider
    provider = build_provider(settings)
    request.app.state.llm_provider = provider
    return provider


def actor_for(principal: Principal) -> ActorRef:
    """Translate an authenticated principal into the gateway's view of the caller."""
    return ActorRef(
        user_id=principal.user_id,
        role=principal.role,
        scopes=principal.scopes,
        label=principal.user.display_name or principal.user.email,
    )


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
