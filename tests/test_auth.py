# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import ASGITransport, AsyncClient

from tests.helpers import _empty_harness, _harness, _login


@pytest.mark.asyncio
async def test_first_registration_is_admin_and_later_registration_is_regular_user() -> None:
    harness = await _empty_harness()
    async with AsyncClient(
        transport=ASGITransport(app=harness.app), base_url="http://testserver"
    ) as client:
        payload = {
            "username": "first-admin",
            "email": "first@example.test",
            "display_name": "First Admin",
            "password": "A strong password 123!",
            "public_key": harness.public_key,
            "device_name": "Test PC",
            "platform": "windows",
            "client_version": "0.1.0+1",
        }
        first = await client.post("/auth/register", json=payload)
        assert first.status_code == 201
        assert set(first.json()["user"]["roles"]) == {"user", "owner", "admin"}
        assert first.json()["device_key"].startswith("arx.device.")

        second = await client.post(
            "/auth/register",
            json={
                **payload,
                "username": "second-user",
                "email": "second@example.test",
                "display_name": "Second User",
            },
        )
        assert second.status_code == 201
        assert second.json()["user"]["roles"] == ["user"]
        # Device public keys are account-scoped; a shared PC can register both accounts.
        assert second.json()["device_id"] != first.json()["device_id"]
    await harness.engine.dispose()


@pytest.mark.asyncio
async def test_login_with_new_install_enrolls_it_without_admin_approval() -> None:
    harness = await _harness()
    new_private_key = Ed25519PrivateKey.generate()
    new_public_key = base64.b64encode(
        new_private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    ).decode("ascii")
    async with AsyncClient(
        transport=ASGITransport(app=harness.app), base_url="http://testserver"
    ) as client:
        response = await client.post(
            "/auth/login",
            json={
                "username": "owner",
                "password": "Correct horse battery staple!",
                "public_key": new_public_key,
                "device_name": "New phone",
                "platform": "android",
                "client_version": "0.1.0+1",
            },
        )
        assert response.status_code == 200
        assert response.json()["device_key"].startswith("arx.device.")
        assert response.json()["device_id"] != "device-owner"
    await harness.engine.dispose()


@pytest.mark.asyncio
async def test_account_login_enrolls_install_and_rotates_refresh_tokens() -> None:
    harness = await _harness()
    async with AsyncClient(
        transport=ASGITransport(app=harness.app), base_url="http://testserver"
    ) as client:
        login = await _login(client, harness, header_key="unused-header-value")
        assert login.status_code == 200
        assert login.json()["user"]["id"] == "user-owner"
        assert login.json()["device_key"].startswith("arx.device.")
        original_refresh = login.json()["refresh_token"]

        refreshed = await client.post("/auth/refresh", json={"refresh_token": original_refresh})
        assert refreshed.status_code == 200
        rotated_refresh = refreshed.json()["refresh_token"]
        assert rotated_refresh != original_refresh

        replay = await client.post("/auth/refresh", json={"refresh_token": original_refresh})
        assert replay.status_code == 401
        assert replay.json()["code"] == "auth_refresh_rejected"

        headers = {
            "Authorization": f"Bearer {refreshed.json()['access_token']}",
            "X-Armx-Device-Key": harness.device_key,
        }
        logout = await client.post("/auth/logout", headers=headers)
        assert logout.status_code == 204
    await harness.engine.dispose()
