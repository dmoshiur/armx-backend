# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import base64
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from secrets import token_urlsafe
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.config import Settings, get_settings
from app.core.security import hash_device_key, hash_password
from app.db.base import Base
from app.db.engine import create_database_engine
from app.db.models import Device, SystemState, User
from app.db.session import get_session
from app.db.urls import DatabaseBackend, database_backend, normalize_database_url
from app.main import create_app

# The suite runs on aiosqlite by default and can be pointed at the libSQL dialect with
# ``ARMX_TEST_DATABASE_URL`` (``sqlite+libsql:////tmp/armx-test.db``) to exercise the code path
# used against Turso.  In-memory databases are excluded because each pooled libSQL connection
# would otherwise get its own empty database.
_TEST_DATABASE_URL = os.environ.get("ARMX_TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")


def database_url_for_tests() -> str:
    """Return a per-run database URL, creating a scratch file for libSQL runs."""

    url = normalize_database_url(_TEST_DATABASE_URL)
    if database_backend(url) is DatabaseBackend.LIBSQL:
        if ":memory:" in url:
            raise RuntimeError(
                "ARMX_TEST_DATABASE_URL must point at a file for libSQL runs; "
                "use sqlite+libsql:////tmp/armx-test.db"
            )
        return url
    return _TEST_DATABASE_URL


@dataclass
class Harness:
    engine: object
    factory: async_sessionmaker
    app: object
    settings: Settings
    device_key: str
    private_key: Ed25519PrivateKey
    public_key: str


async def _harness() -> Harness:
    url = database_url_for_tests()
    if database_backend(url) is DatabaseBackend.LIBSQL:
        path = url.split("///", 1)[-1]
        Path(path).unlink(missing_ok=True)
    settings = Settings(
        _env_file=None,
        environment="demo",
        demo_insecure=True,
        jwt_secret_key="test-signing-key-that-is-long-enough-012345",
        access_token_ttl_seconds=600,
        refresh_token_ttl_seconds=3600,
        # The default provider is Groq (requires GROQ_API_KEY). Tests that do not
        # exercise the LLM pin the offline local fallback instead; provider-specific tests
        # override these settings explicitly.
        llm_provider="ollama",
    )
    engine = create_database_engine(url)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    private_key = Ed25519PrivateKey.generate()
    public_key = base64.b64encode(
        private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    ).decode("ascii")
    device_key = f"arx.device.{token_urlsafe(32)}"
    user = User(
        id=uuid4(),
        public_id="user-owner",
        username="owner",
        email="owner@example.test",
        display_name="Owner",
        password_hash=hash_password("Correct horse battery staple!"),
        roles=["owner", "admin"],
    )
    device = Device(
        id=uuid4(),
        public_id="device-owner",
        owner_id=user.id,
        name="Owner phone",
        platform="android",
        public_key=public_key,
        device_key_hash=hash_device_key(device_key),
        last_seen_at=datetime.now(UTC),
    )
    async with factory() as session:
        # Foreign keys are enforced on every supported backend, so the owner is flushed
        # before the device that references it.
        session.add(user)
        await session.flush()
        session.add(device)
        await session.commit()

    application = create_app(settings)

    async def override_session():
        async with factory() as session:
            yield session

    application.dependency_overrides[get_session] = override_session
    application.dependency_overrides[get_settings] = lambda: settings
    return Harness(engine, factory, application, settings, device_key, private_key, public_key)


async def _empty_harness() -> Harness:
    """Create a fresh database for first-account/admin-election smoke tests."""
    settings = Settings(
        _env_file=None,
        environment="demo",
        demo_insecure=True,
        jwt_secret_key="test-signing-key-that-is-long-enough-012345",
        llm_provider="ollama",
    )
    engine = create_database_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        session.add(SystemState(id=1, assistant_enabled=True, kill_switch_engaged=False))
        await session.commit()
    private_key = Ed25519PrivateKey.generate()
    public_key = base64.b64encode(
        private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    ).decode("ascii")
    application = create_app(settings)

    async def override_session():
        async with factory() as session:
            yield session

    application.dependency_overrides[get_session] = override_session
    application.dependency_overrides[get_settings] = lambda: settings
    return Harness(engine, factory, application, settings, "", private_key, public_key)


async def _login(client: AsyncClient, harness: Harness, *, header_key: str | None = None):
    return await client.post(
        "/auth/login",
        headers={"X-Armx-Device-Key": header_key} if header_key is not None else {},
        json={
            "username": "owner",
            "password": "Correct horse battery staple!",
            "device_key": harness.device_key,
            "public_key": base64.b64encode(
                harness.private_key.public_key().public_bytes(
                    Encoding.DER, PublicFormat.SubjectPublicKeyInfo
                )
            ).decode("ascii"),
            "device_name": "Test phone",
            "platform": "android",
            "client_version": "0.1.0+1",
        },
    )
