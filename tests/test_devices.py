# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import ssl
from datetime import UTC, datetime
from secrets import token_urlsafe

import jwt
import pytest
from httpx import ASGITransport, AsyncClient

from app.config import Settings
from app.devices.cli import _parse_relays
from app.devices.mqtt import _tls_context
from app.devices.state_listener import _normalize_relays, _normalize_sensors, _normalize_tags
from tests.helpers import _harness, _login


def test_device_state_uses_registered_relay_policy_and_discards_raw_biometrics() -> None:
    now = datetime.now(UTC)
    relay = _normalize_relays(
        [
            {"id": "lamp", "state": "ON", "risk_tier": "LOW"},
            {"id": "unknown", "state": "ON"},
            {"id": "lamp", "state": "INVALID"},
            {"id": "lamp", "state": "OFF", "face_template": "not stored"},
        ],
        now,
        [
            {
                "id": "lamp",
                "label": "Lamp",
                "state": "UNKNOWN",
                "risk_tier": "HIGH",
                "is_momentary": False,
            }
        ],
        "MEDIUM",
    )
    assert relay[0]["risk_tier"] == "HIGH"
    assert relay[0]["state"] == "ON"
    assert "face_template" not in relay[0]

    sensors = _normalize_sensors(
        [
            {"id": "temperature", "kind": "temperature", "value": 21.5, "unit": "C"},
            {"id": "custom", "kind": "unmapped_sensor", "value": 1.0, "unit": ""},
            {"id": "camera", "value": "data:image/jpeg;base64,AAAA"},
            {"id": "broken", "value": float("nan")},
        ],
        now,
    )
    assert len(sensors) == 2
    assert sensors[0]["value"] == 21.5
    assert sensors[0]["kind"] == "TEMPERATURE"
    assert sensors[1]["kind"] == "OTHER"
    assert _normalize_tags({"floor": "first", "voice": "private payload"}) == {"floor": "first"}


def test_resource_provisioning_rejects_duplicate_or_invalid_relay_policy() -> None:
    relays = _parse_relays(["light,Hall light,MEDIUM,false"])
    assert relays[0]["risk_tier"] == "MEDIUM"
    assert relays[0]["is_momentary"] is False

    for invalid in (
        ["light,Hall light,LOW,false", "light,Duplicate,HIGH,true"],
        ["light,Hall light,UNKNOWN,false"],
        ["light,Hall light,LOW,maybe"],
    ):
        try:
            _parse_relays(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid relay configuration was accepted")


def test_mqtt_client_always_validates_tls_certificates() -> None:
    settings = Settings(
        _env_file=None,
        environment="demo",
        demo_insecure=True,
        jwt_secret_key="mqtt-test-signing-key-that-is-long-enough",
    )
    context = _tls_context(settings)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


@pytest.mark.asyncio
async def test_scene_activation_requires_medium_verification_assertion() -> None:
    harness = await _harness()
    async with AsyncClient(
        transport=ASGITransport(app=harness.app), base_url="http://testserver"
    ) as client:
        login = await _login(client, harness)
        headers = {
            "Authorization": f"Bearer {login.json()['access_token']}",
            "X-Armx-Device-Key": harness.device_key,
        }
        denied = await client.post("/devices/scenes/scene-focus/activate", headers=headers, json={})
        assert denied.status_code == 428
        assert denied.json()["code"] == "policy_verification_required"

        now_ts = int(datetime.now(UTC).timestamp())
        token = jwt.encode(
            {
                "iat": now_ts,
                "exp": now_ts + 30,
                "jti": token_urlsafe(12),
                "nonce": token_urlsafe(18),
                "device_id": "device-owner",
                "scope": "owner_verified",
                "single_use": True,
                "factors": ["face", "voice"],
            },
            harness.private_key,
            algorithm="EdDSA",
        )
        allowed = await client.post(
            "/devices/scenes/scene-focus/activate",
            headers=headers,
            json={"owner_verified": {"token": token}},
        )
        assert allowed.status_code == 204
    await harness.engine.dispose()
