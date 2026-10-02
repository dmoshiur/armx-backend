# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import pytest
from httpx import ASGITransport, AsyncClient

from tests.helpers import _harness, _login


@pytest.mark.asyncio
async def test_login_binds_the_device_key_header_and_rotates_refresh_tokens() -> None:
    harness = await _harness()
    async with AsyncClient(
        transport=ASGITransport(app=harness.app), base_url="http://testserver"
    ) as client:
        mismatch = await _login(client, harness, header_key="wrong-device-key-123456")
        assert mismatch.status_code == 403
        assert mismatch.json()["code"] == "auth_pairing_rejected"

        login = await _login(client, harness, header_key=harness.device_key)
        assert login.status_code == 200
        assert login.json()["user"]["id"] == "user-owner"
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
