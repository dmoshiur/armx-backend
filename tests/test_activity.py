# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import pytest
from httpx import ASGITransport, AsyncClient

from tests.helpers import _harness, _login


@pytest.mark.asyncio
async def test_activity_rules_are_owner_scoped_and_risk_is_server_derived() -> None:
    harness = await _harness()
    body = {
        "id": "rule-night-light",
        "name": "Night light",
        "trigger_type": "TIME_WINDOW",
        "action_type": "DEVICE_COMMAND",
        "enabled": True,
        "dry_run": False,
        "risk_tier": "LOW",
        "trigger_params": {"start": "22:00", "end": "06:00"},
        "action_params": {"command": "lamp:ON"},
    }
    async with AsyncClient(
        transport=ASGITransport(app=harness.app), base_url="http://testserver"
    ) as client:
        login = await _login(client, harness, header_key=harness.device_key)
        assert login.status_code == 200
        headers = {
            "Authorization": f"Bearer {login.json()['access_token']}",
            "X-Armx-Device-Key": harness.device_key,
        }

        saved = await client.post("/rules", headers=headers, json=body)
        assert saved.status_code == 200
        assert saved.json()["risk_tier"] == "HIGH"
        assert saved.json()["run_count"] == 0

        listed = await client.get("/rules", headers=headers)
        assert [rule["id"] for rule in listed.json()] == ["rule-night-light"]

        preview = await client.post("/rules/dry-run", headers=headers, json=body)
        assert preview.status_code == 200
        assert preview.json()["would_fire"] is True
        assert any("will not execute" in item for item in preview.json()["steps"])

        deleted = await client.delete("/rules/rule-night-light", headers=headers)
        assert deleted.status_code == 204
        assert (await client.get("/rules", headers=headers)).json() == []

    await harness.engine.dispose()
