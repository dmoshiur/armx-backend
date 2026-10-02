# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import base64
from datetime import UTC, datetime
from secrets import token_urlsafe
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.core.security import (
    canonical_json_bytes,
    encrypt_pairing_secret,
    hash_device_key,
)
from app.db.models import Device, PairingRequest
from tests.helpers import _harness, _login


def _public_key(private_key: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    ).decode("ascii")


def _signature(private_key: Ed25519PrivateKey, device_id: str, challenge: str) -> str:
    data = canonical_json_bytes({"device_id": device_id, "challenge": challenge})
    return base64.b64encode(private_key.sign(data)).decode("ascii")


@pytest.mark.asyncio
async def test_pairing_challenge_proves_private_key_and_rejects_replay() -> None:
    harness = await _harness()
    pair_private_key = Ed25519PrivateKey.generate()
    public_key = _public_key(pair_private_key)
    request_body = {
        "public_key": public_key,
        "device_name": "New phone",
        "platform": "android",
    }

    async with AsyncClient(
        transport=ASGITransport(app=harness.app), base_url="http://testserver"
    ) as client:
        first = await client.post("/devices/pair", json=request_body)
        assert first.status_code == 202
        device_id = first.json()["device_id"]
        challenge_one = first.json()["challenge"]

        pending = await client.post(
            "/devices/pair",
            json={
                **request_body,
                "challenge": challenge_one,
                "challenge_signature": _signature(pair_private_key, device_id, challenge_one),
            },
        )
        assert pending.status_code == 202
        challenge_two = pending.json()["challenge"]
        assert challenge_two != challenge_one

        device_key = f"arx.device.{token_urlsafe(32)}"
        async with harness.factory() as session:
            pairing = await session.scalar(
                select(PairingRequest).where(PairingRequest.device_public_id == device_id)
            )
            assert pairing is not None
            owner_id = pairing.owner_id
            assert owner_id is not None
            device = Device(
                id=uuid4(),
                public_id=device_id,
                owner_id=owner_id,
                name="New phone",
                platform="android",
                public_key=public_key,
                device_key_hash=hash_device_key(device_key),
                paired_at=datetime.now(UTC),
            )
            session.add(device)
            await session.flush()
            pairing.device_id = device.id
            pairing.device_key_ciphertext = encrypt_pairing_secret(harness.settings, device_key)
            pairing.status = "approved"
            pairing.resolved_at = datetime.now(UTC)
            await session.commit()

        approved_body = {
            **request_body,
            "challenge": challenge_two,
            "challenge_signature": _signature(pair_private_key, device_id, challenge_two),
        }
        approved = await client.post("/devices/pair", json=approved_body)
        assert approved.status_code == 200
        assert approved.json()["device_key"] == device_key

        replay = await client.post("/devices/pair", json=approved_body)
        assert replay.status_code == 409
        assert replay.json()["code"] == "pairing_completed"

        async with harness.factory() as session:
            pairing = await session.scalar(
                select(PairingRequest).where(PairingRequest.device_public_id == device_id)
            )
            assert pairing is not None
            next_challenge = pairing.poll_challenge
        second_credential_request = await client.post(
            "/devices/pair",
            json={
                **request_body,
                "challenge": next_challenge,
                "challenge_signature": _signature(pair_private_key, device_id, next_challenge),
            },
        )
        assert second_credential_request.status_code == 409
        assert second_credential_request.json()["code"] == "pairing_completed"

    await harness.engine.dispose()


@pytest.mark.asyncio
async def test_admin_pairing_decision_endpoint_approves_pending_request() -> None:
    harness = await _harness()
    pair_private_key = Ed25519PrivateKey.generate()
    request_body = {
        "public_key": _public_key(pair_private_key),
        "device_name": "Windows desktop",
        "platform": "windows",
    }

    async with AsyncClient(
        transport=ASGITransport(app=harness.app), base_url="http://testserver"
    ) as client:
        first = await client.post("/devices/pair", json=request_body)
        assert first.status_code == 202
        device_id = first.json()["device_id"]
        challenge = first.json()["challenge"]

        login = await _login(client, harness)
        headers = {
            "Authorization": f"Bearer {login.json()['access_token']}",
            "X-Armx-Device-Key": harness.device_key,
        }
        listed = await client.get("/admin/pairing", headers=headers)
        assert listed.status_code == 200
        assert any(item["device_id"] == device_id for item in listed.json())

        decided = await client.post(
            f"/admin/pairing/{device_id}/decision",
            headers=headers,
            json={"approved": True},
        )
        assert decided.status_code == 200
        assert decided.json()["status"] == "approved"

        completed = await client.post(
            "/devices/pair",
            json={
                **request_body,
                "challenge": challenge,
                "challenge_signature": _signature(pair_private_key, device_id, challenge),
            },
        )
        assert completed.status_code == 200
        assert completed.json()["device_key"].startswith("arx.device.")

    await harness.engine.dispose()


@pytest.mark.asyncio
async def test_pairing_auto_approve_still_requires_signed_challenge_proof() -> None:
    harness = await _harness()
    harness.settings.pairing_auto_approve = True
    pair_private_key = Ed25519PrivateKey.generate()
    request_body = {
        "public_key": _public_key(pair_private_key),
        "device_name": "Auto-approved Android",
        "platform": "android",
    }

    async with AsyncClient(
        transport=ASGITransport(app=harness.app), base_url="http://testserver"
    ) as client:
        first = await client.post("/devices/pair", json=request_body)
        assert first.status_code == 202
        assert "device_key" not in first.json()
        device_id = first.json()["device_id"]
        challenge = first.json()["challenge"]

        completed = await client.post(
            "/devices/pair",
            json={
                **request_body,
                "challenge": challenge,
                "challenge_signature": _signature(pair_private_key, device_id, challenge),
            },
        )
        assert completed.status_code == 200
        assert completed.json()["device_key"].startswith("arx.device.")

    await harness.engine.dispose()
