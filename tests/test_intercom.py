# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import base64
import json
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.core.security import hash_device_key, hash_password
from app.db.models import AuditLog, Device, IntercomConsent, IntercomDelivery, User
from tests.helpers import Harness, _harness, _login


def _public_key(private_key: Ed25519PrivateKey) -> str:
    der = private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode("ascii")


def _owner_verified(harness: Harness) -> str:
    issued_at = int(datetime.now(UTC).timestamp())
    expires_at = issued_at + 30
    token = jwt.encode(
        {
            "iat": issued_at,
            "exp": expires_at,
            "jti": token_urlsafe(16),
            "nonce": token_urlsafe(16),
            "device_id": "device-owner",
            "scope": "owner_verified",
            "single_use": True,
            "factors": ["face"],
        },
        harness.private_key,
        algorithm="EdDSA",
    )
    return json.dumps(
        {
            "token": token,
            "scope": "owner_verified",
            "single_use": True,
            "iat": datetime.fromtimestamp(issued_at, UTC).isoformat(),
            "exp": datetime.fromtimestamp(expires_at, UTC).isoformat(),
        }
    )


async def _add_recipient(harness: Harness, *, consented: bool) -> tuple[str, str]:
    private_key = Ed25519PrivateKey.generate()
    device_key = f"arx.device.{token_urlsafe(32)}"
    user = User(
        id=uuid4(),
        public_id="user-recipient",
        username="recipient",
        email="recipient@example.test",
        display_name="Recipient",
        password_hash=hash_password("Recipient passphrase 2026!"),
        roles=["user"],
    )
    device = Device(
        id=uuid4(),
        public_id="device-recipient",
        owner_id=user.id,
        name="Living room tablet",
        platform="android",
        public_key=_public_key(private_key),
        device_key_hash=hash_device_key(device_key),
        last_seen_at=datetime.now(UTC) - timedelta(minutes=5),
    )
    async with harness.factory() as session:
        # Foreign keys are enforced, so parent rows are flushed before their dependents.
        session.add(user)
        await session.flush()
        session.add(device)
        await session.flush()
        session.add(
            IntercomConsent(
                device_id=device.id,
                enabled=consented,
                allow_while_locked=False,
            )
        )
        await session.commit()
    return device_key, device.public_id


@pytest.mark.asyncio
async def test_intercom_refuses_and_audits_a_nonconsented_target() -> None:
    harness = await _harness()
    recipient_key, _ = await _add_recipient(harness, consented=False)
    del recipient_key

    async with AsyncClient(
        transport=ASGITransport(app=harness.app), base_url="http://testserver"
    ) as client:
        login = await _login(client, harness)
        headers = {
            "Authorization": f"Bearer {login.json()['access_token']}",
            "X-Armx-Device-Key": harness.device_key,
        }
        response = await client.post(
            "/v1/intercom/announcements",
            headers=headers,
            data={
                "duration_ms": "400",
                "target_user_id": "user-recipient",
                "mime_type": "audio/mp4",
                "owner_verified": "{}",
            },
            files={"audio": ("voice.m4a", b"recorded audio bytes", "audio/mp4")},
        )
        assert response.status_code == 403
        assert response.json()["code"] == "intercom_consent_required"

    async with harness.factory() as session:
        logs = list((await session.scalars(select(AuditLog))).all())
        assert any(
            row.action == "intercom.announcement.rejected"
            and row.outcome == "DENIED"
            and row.subject_user_id is not None
            for row in logs
        )
        assert list((await session.scalars(select(IntercomDelivery))).all()) == []
    await harness.engine.dispose()


@pytest.mark.asyncio
async def test_intercom_missed_delivery_is_not_queued_and_both_sides_see_same_row() -> None:
    harness = await _harness()
    recipient_key, _ = await _add_recipient(harness, consented=True)

    async with AsyncClient(
        transport=ASGITransport(app=harness.app), base_url="http://testserver"
    ) as client:
        sender_login = await _login(client, harness)
        sender_headers = {
            "Authorization": f"Bearer {sender_login.json()['access_token']}",
            "X-Armx-Device-Key": harness.device_key,
        }
        response = await client.post(
            "/v1/intercom/announcements",
            headers=sender_headers,
            data={
                "duration_ms": "400",
                "target_user_id": "user-recipient",
                "mime_type": "audio/mp4",
                "owner_verified": _owner_verified(harness),
            },
            files={"audio": ("voice.m4a", b"recorded audio bytes", "audio/mp4")},
        )
        assert response.status_code == 200, response.text
        announcement = response.json()
        assert announcement["status"] == "MISSED"
        assert announcement["scope"] == "USER"

        recipient_login = await client.post(
            "/auth/login",
            json={
                "username": "recipient",
                "password": "Recipient passphrase 2026!",
                "device_key": recipient_key,
                "platform": "android",
                "client_version": "0.1.0+1",
            },
        )
        assert recipient_login.status_code == 200
        recipient_headers = {
            "Authorization": f"Bearer {recipient_login.json()['access_token']}",
            "X-Armx-Device-Key": recipient_key,
        }
        sender_log = await client.get("/v1/intercom/announcements", headers=sender_headers)
        recipient_log = await client.get("/v1/intercom/announcements", headers=recipient_headers)
        assert sender_log.status_code == recipient_log.status_code == 200
        assert sender_log.json()[0]["id"] == recipient_log.json()[0]["id"] == announcement["id"]
        assert sender_log.json()[0]["status"] == recipient_log.json()[0]["status"] == "MISSED"

        audio = await client.get(
            f"/v1/intercom/announcements/{announcement['id']}/audio",
            headers=recipient_headers,
        )
        assert audio.status_code == 403
        assert audio.json()["code"] == "permission_denied"

    async with harness.factory() as session:
        deliveries = list((await session.scalars(select(IntercomDelivery))).all())
        assert len(deliveries) == 1
        assert deliveries[0].status == "MISSED"
        logs = list((await session.scalars(select(AuditLog))).all())
        assert any(row.action == "intercom.announcement.delivery" for row in logs)
        assert all("recorded audio bytes" not in row.detail for row in logs)
    await harness.engine.dispose()
