# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import base64
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.auth.dependencies import Principal
from app.core.errors import APIError
from app.core.risk_policy import RiskTier
from app.core.verification import OwnerAssertionInput, consume_owner_assertion
from app.db.base import Base
from app.db.models import AuthSession, Device, UsedNonce, User


def _keys() -> tuple[Ed25519PrivateKey, str]:
    private_key = Ed25519PrivateKey.generate()
    der = private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return private_key, base64.b64encode(der).decode("ascii")


def _assertion(
    private_key: Ed25519PrivateKey, device_id: str, factors: list[str]
) -> OwnerAssertionInput:
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=30)).timestamp()),
            "jti": "assertion-01",
            "nonce": "nonce-assertion-01",
            "device_id": device_id,
            "scope": "owner_verified",
            "single_use": True,
            "factors": factors,
        },
        private_key,
        algorithm="EdDSA",
    )
    return OwnerAssertionInput(token=token)


@pytest.mark.asyncio
async def test_owner_assertion_is_signed_scoped_fresh_and_single_use() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    private_key, public_key = _keys()
    user = User(
        id=uuid4(),
        public_id="user-owner",
        username="owner",
        email="owner@example.test",
        display_name="Owner",
        password_hash="not-used",
        roles=["owner", "admin"],
    )
    device = Device(
        id=uuid4(),
        public_id="device-owner",
        owner_id=user.id,
        name="Test device",
        platform="test",
        public_key=public_key,
        device_key_hash="not-used",
    )
    auth_session = AuthSession(
        user_id=user.id,
        device_id=device.id,
        refresh_token_hash="refresh-hash",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    principal = Principal(user=user, device=device, auth_session=auth_session)

    async with factory() as session:
        session.add_all([user, device, auth_session])
        await session.flush()
        assertion = _assertion(private_key, device.public_id, ["face", "voice"])
        factors = await consume_owner_assertion(
            session,
            principal,
            assertion,
            tier=RiskTier.MEDIUM,
            max_ttl_seconds=60,
        )
        assert factors == frozenset({"face", "voice"})
        with pytest.raises(APIError) as error:
            await consume_owner_assertion(
                session,
                principal,
                assertion,
                tier=RiskTier.MEDIUM,
                max_ttl_seconds=60,
            )
        assert error.value.code == "owner_assertion_replayed"
        await session.commit()
        nonces = list((await session.scalars(select(UsedNonce))).all())
        assert len(nonces) == 1

    await engine.dispose()


@pytest.mark.asyncio
async def test_owner_assertion_voice_only_is_rejected_at_low_tier() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    private_key, public_key = _keys()
    user = User(
        id=uuid4(),
        public_id="user-owner",
        username="owner",
        email="owner@example.test",
        display_name="Owner",
        password_hash="not-used",
        roles=["owner", "admin"],
    )
    device = Device(
        id=uuid4(),
        public_id="device-owner",
        owner_id=user.id,
        name="Test device",
        platform="test",
        public_key=public_key,
        device_key_hash="not-used",
    )
    auth_session = AuthSession(
        user_id=user.id,
        device_id=device.id,
        refresh_token_hash="refresh-hash",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    principal = Principal(user=user, device=device, auth_session=auth_session)

    async with factory() as session:
        session.add_all([user, device, auth_session])
        await session.flush()
        assertion = _assertion(private_key, device.public_id, ["voice"])
        with pytest.raises(APIError) as error:
            await consume_owner_assertion(
                session,
                principal,
                assertion,
                tier=RiskTier.LOW,
                max_ttl_seconds=60,
            )
        assert error.value.code == "policy_verification_required"
        await session.rollback()

    await engine.dispose()
