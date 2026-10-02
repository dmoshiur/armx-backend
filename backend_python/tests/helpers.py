# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import base64
from dataclasses import dataclass
from datetime import UTC, datetime
from secrets import token_urlsafe
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.config import Settings, get_settings
from app.core.security import hash_device_key, hash_password
from app.db.base import Base
from app.db.models import Device, User
from app.db.session import get_session
from app.main import create_app


@dataclass
class Harness:
    engine: object
    factory: async_sessionmaker
    app: object
    settings: Settings
    device_key: str
    private_key: Ed25519PrivateKey


async def _harness() -> Harness:
    settings = Settings(
        _env_file=None,
        environment="demo",
        demo_insecure=True,
        jwt_secret_key="test-signing-key-that-is-long-enough-012345",
        access_token_ttl_seconds=600,
        refresh_token_ttl_seconds=3600,
    )
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
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
        session.add_all([user, device])
        await session.commit()

    application = create_app(settings)

    async def override_session():
        async with factory() as session:
            yield session

    application.dependency_overrides[get_session] = override_session
    application.dependency_overrides[get_settings] = lambda: settings
    return Harness(engine, factory, application, settings, device_key, private_key)


async def _login(client: AsyncClient, harness: Harness, *, header_key: str | None = None):
    return await client.post(
        "/auth/login",
        headers={"X-Armx-Device-Key": header_key} if header_key is not None else {},
        json={
            "username": "owner",
            "password": "Correct horse battery staple!",
            "device_key": harness.device_key,
            "platform": "android",
            "client_version": "0.1.0+1",
        },
    )
