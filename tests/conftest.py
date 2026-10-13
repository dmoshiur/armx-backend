# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Shared test fixtures.

Every test runs against its own SQLite file, so tests are order-independent and parallel-safe,
and the schema is created from the models. ``tests/test_migrations.py`` separately proves that
the Alembic migration produces the same schema, which is what keeps local SQLite honest about
production PostgreSQL.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.config import Settings
from app.core.enums import Role
from app.core.passwords import hash_password
from app.core.time import utcnow
from app.db.base import Base
from app.db.models import Session, User
from app.db.session import dispose_engines, get_engine
from app.main import create_app
from app.registry.core import ToolRegistry
from app.registry.discovery import discover_tools


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def tmp_settings(tmp_path: Path) -> Settings:
    """
    An isolated, fully-configured development profile.

    Secrets are explicit (not generated) so a test can prove that no ephemeral secret path is
    involved, and the worker is off so background loops never race a test.
    """
    return Settings(
        environment="development",
        demo_insecure=True,
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'armx-test.db'}",
        jwt_secret_key="test-jwt-secret-key-long-enough-for-hs256-signing",
        encryption_key=Fernet.generate_key().decode(),
        llm_provider="mock",
        email_delivery_mode="outbox",
        rate_limit_enabled=True,
        worker_enabled=False,
        worker_in_api=False,
        password_min_length=12,
        auth_max_failed_logins=5,
        auth_lockout_seconds=900,
        approval_ttl_seconds=300,
        pairing_code_ttl_seconds=600,
        access_token_ttl_seconds=900,
    )


@pytest_asyncio.fixture
async def engine(tmp_settings: Settings) -> AsyncIterator[AsyncEngine]:
    """Engine with the full schema created, disposed at the end of the test."""
    engine = await get_engine(tmp_settings)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
        # A real database is created by Alembic, and /ready refuses traffic until the schema is
        # migrated. The fixture mimics that state so readiness means the same thing in tests.
        await connection.execute(
            text("CREATE TABLE IF NOT EXISTS alembic_version (version_num VARCHAR(32) NOT NULL)")
        )
        await connection.execute(text("INSERT INTO alembic_version (version_num) VALUES ('0001')"))
    yield engine
    await engine.dispose()
    await dispose_engines()


@pytest_asyncio.fixture
async def session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)


@pytest_asyncio.fixture
async def db(session_factory: async_sessionmaker[AsyncSession]) -> AsyncIterator[AsyncSession]:
    """A session for arranging test state directly in the database."""
    async with session_factory() as session:
        yield session
        await session.rollback()


@pytest.fixture
def registry(tmp_settings: Settings) -> ToolRegistry:
    """A registry discovered into an isolated instance (never the process-wide one)."""
    return discover_tools(tmp_settings, target=ToolRegistry())


@pytest.fixture
def app(tmp_settings: Settings, engine: AsyncEngine, registry: ToolRegistry):
    """The ASGI app bound to the isolated settings and registry."""
    application = create_app(tmp_settings)
    return application


@pytest.fixture
def app_factory(engine: AsyncEngine, registry: ToolRegistry, tmp_settings: Settings):
    """
    Build additional app instances (with settings overrides) against the same migrated
    database, for tests that need a different profile - hardened TLS, metrics off, and so on.
    """
    from app.main import create_app as build_app

    def build(**overrides: object):
        configured = tmp_settings.model_copy(update=overrides) if overrides else tmp_settings
        return build_app(configured)

    return build


@pytest_asyncio.fixture
async def client(app) -> AsyncIterator[AsyncClient]:
    """HTTP client wired to the app with its lifespan (startup/shutdown) running."""
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as http:
            yield http


# --------------------------------------------------------------------- factories
@pytest_asyncio.fixture
async def user_factory(db: AsyncSession):
    """Create users with a known password. Returns an async factory function."""

    async def create(
        *,
        email: str | None = None,
        password: str = "correct-horse-battery-staple",  # noqa: S107 - a test fixture, not a real credential
        role: Role = Role.USER,
        verified: bool = True,
        active: bool = True,
    ) -> User:
        user = User(
            email=email or f"user-{uuid.uuid4().hex[:10]}@example.com",
            display_name="Test User",
            role=role,
            password_hash=hash_password(password),
            email_verified_at=utcnow() if verified else None,
            is_active=active,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user

    return create


@pytest_asyncio.fixture
async def admin_user(user_factory):
    return await user_factory(role=Role.ADMIN, email="admin@example.com")


@pytest_asyncio.fixture
async def vip_user(user_factory):
    return await user_factory(role=Role.VIP, email="vip@example.com")


@pytest_asyncio.fixture
async def regular_user(user_factory):
    return await user_factory(role=Role.USER, email="user@example.com")


@pytest_asyncio.fixture
async def session_row_factory(db: AsyncSession):
    """Create a session row (one per signed-in device) for a user."""

    async def create(user: User, *, label: str = "test device") -> Session:
        session = Session(
            user_id=user.id,
            label=label,
            user_agent="pytest",
            created_at=utcnow(),
            expires_at=utcnow() + timedelta(days=30),
        )
        db.add(session)
        await db.commit()
        await db.refresh(session)
        return session

    return create


def pytest_configure(config: pytest.Config) -> None:
    del config


@pytest.fixture(autouse=True)
def _clear_metrics() -> Iterator[None]:
    from app.core.metrics import reset_metrics

    reset_metrics()
    yield
    reset_metrics()
