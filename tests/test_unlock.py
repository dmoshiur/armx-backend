# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import base64
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.auth.dependencies import Principal
from app.core.errors import APIError
from app.core.security import canonical_json_bytes, hash_password
from app.db.models import AuthSession, Device, SystemState, UnlockTarget, User
from app.unlock.routes import request_unlock
from app.unlock.schemas import UnlockRequest
from tests.helpers import Harness, _harness, _login


def _public_key(harness: Harness) -> str:
    return base64.b64encode(
        harness.private_key.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
    ).decode("ascii")


def _owner_assertion(harness: Harness, now: datetime | None = None) -> dict[str, str]:
    issued = now or datetime.now(UTC)
    assertion_iat = int(issued.timestamp())
    token = jwt.encode(
        {
            "iat": assertion_iat,
            "exp": assertion_iat + 20,
            "jti": token_urlsafe(12),
            "nonce": token_urlsafe(18),
            "device_id": "device-owner",
            "scope": "owner_verified",
            "single_use": True,
            "factors": ["face", "voice", "pin"],
        },
        harness.private_key,
        algorithm="EdDSA",
    )
    return {"token": token}


def _unlock_request(
    harness: Harness,
    *,
    target_id: str = "door-1",
    issued_at: datetime | None = None,
    exp: datetime | None = None,
    assertion: bool = True,
) -> dict[str, object]:
    now = datetime.now(UTC).replace(microsecond=0)
    issue_time = issued_at or now
    expiration = exp or (issue_time + timedelta(seconds=20))
    unsigned: dict[str, object] = {
        "action": "unlock",
        "algorithm": "Ed25519",
        "device_id": target_id,
        "exp": expiration.isoformat().replace("+00:00", "Z"),
        "issued_at": issue_time.isoformat().replace("+00:00", "Z"),
        "nonce": token_urlsafe(18),
        "public_key": _public_key(harness),
    }
    signed = {name: unsigned[name] for name in ("device_id", "nonce", "exp", "action")}
    signature = base64.b64encode(harness.private_key.sign(canonical_json_bytes(signed))).decode(
        "ascii"
    )
    body: dict[str, object] = {**unsigned, "signature": signature}
    if assertion:
        body["assertion"] = _owner_assertion(harness, now)
    return body


def _resign(harness: Harness, body: dict[str, object]) -> dict[str, object]:
    signed = {name: body[name] for name in ("device_id", "nonce", "exp", "action")}
    return {
        **body,
        "signature": base64.b64encode(
            harness.private_key.sign(canonical_json_bytes(signed))
        ).decode("ascii"),
    }


async def _headers(client: AsyncClient, harness: Harness) -> dict[str, str]:
    login = await _login(client, harness)
    assert login.status_code == 200
    return {
        "Authorization": f"Bearer {login.json()['access_token']}",
        "X-Armx-Device-Key": harness.device_key,
    }


def _target(
    *,
    target_id: str,
    owner_id: object,
    now: datetime,
    online: bool = True,
    paired: bool = True,
) -> UnlockTarget:
    return UnlockTarget(
        id=target_id,
        owner_id=owner_id,
        name=target_id,
        kind="DOOR",
        public_key="unused-target-agent-key",
        online=online,
        last_seen_at=now,
        risk_tier="HIGH",
        paired=paired,
    )


@pytest.mark.asyncio
async def test_unlock_uses_documented_signature_fields_and_consumes_nonce() -> None:
    harness = await _harness()
    async with harness.factory() as session:
        owner = await session.scalar(select(User).where(User.username == "owner"))
        assert owner is not None
        session.add(_target(target_id="door-1", owner_id=owner.id, now=datetime.now(UTC)))
        await session.commit()

    async with AsyncClient(
        transport=ASGITransport(app=harness.app), base_url="http://testserver"
    ) as client:
        headers = await _headers(client, harness)
        body = _unlock_request(harness)
        tampered = {
            **body,
            "exp": (datetime.now(UTC) + timedelta(seconds=21)).isoformat().replace("+00:00", "Z"),
        }
        mismatch = await client.post("/unlock/request", headers=headers, json=tampered)
        assert mismatch.status_code == 400
        assert mismatch.json()["code"] == "bad_signature"

        outcome = await client.post("/unlock/request", headers=headers, json=body)
        assert outcome.status_code == 200
        assert outcome.json()["status"] == "FAILED"
        assert outcome.json()["at"]
        assert "not connected" in outcome.json()["message"].lower()

        replay_body = {**body, "assertion": _owner_assertion(harness)}
        replay = await client.post("/unlock/request", headers=headers, json=replay_body)
        assert replay.status_code == 400
        assert replay.json()["code"] == "bad_signature"

    await harness.engine.dispose()


@pytest.mark.asyncio
async def test_unlock_target_listing_and_revocation_are_owner_scoped() -> None:
    harness = await _harness()
    now = datetime.now(UTC)
    async with harness.factory() as session:
        owner = await session.scalar(select(User).where(User.username == "owner"))
        assert owner is not None
        other = User(
            id=uuid4(),
            public_id="user-other",
            username="other",
            email="other@example.test",
            display_name="Other",
            password_hash=hash_password("Another safe password!"),
            roles=["user"],
        )
        session.add(other)
        # Foreign keys are enforced, so the new owner is flushed before its targets.
        await session.flush()
        session.add_all(
            [
                _target(target_id="fresh", owner_id=owner.id, now=now),
                _target(target_id="stale", owner_id=owner.id, now=now - timedelta(seconds=120)),
                _target(target_id="unpaired", owner_id=owner.id, now=now, paired=False),
                _target(target_id="other-target", owner_id=other.id, now=now),
            ]
        )
        await session.commit()

    async with AsyncClient(
        transport=ASGITransport(app=harness.app), base_url="http://testserver"
    ) as client:
        headers = await _headers(client, harness)
        listed = await client.get("/unlock/paired-targets", headers=headers)
        assert listed.status_code == 200
        targets = {target["id"]: target for target in listed.json()}
        assert set(targets) == {"fresh", "stale"}
        assert targets["fresh"]["online"] is True
        assert targets["stale"]["online"] is False

        revoked = await client.post("/unlock/revoke", headers=headers, json={"target_id": "fresh"})
        assert revoked.status_code == 200
        assert [target["id"] for target in revoked.json()] == ["stale"]

        cross_user = await client.post(
            "/unlock/revoke", headers=headers, json={"target_id": "other-target"}
        )
        assert cross_user.status_code == 200
        async with harness.factory() as session:
            other_target = await session.get(UnlockTarget, "other-target")
            assert other_target is not None and other_target.paired is True

    await harness.engine.dispose()


@pytest.mark.asyncio
async def test_unlock_rejects_invalid_target_timestamps_ttl_and_missing_evidence() -> None:
    harness = await _harness()
    now = datetime.now(UTC).replace(microsecond=0)
    async with harness.factory() as session:
        owner = await session.scalar(select(User).where(User.username == "owner"))
        assert owner is not None
        session.add(_target(target_id="door-1", owner_id=owner.id, now=now, online=False))
        session.add(_target(target_id="unpaired", owner_id=owner.id, now=now, paired=False))
        await session.commit()

    async with AsyncClient(
        transport=ASGITransport(app=harness.app), base_url="http://testserver"
    ) as client:
        headers = await _headers(client, harness)

        missing = _resign(harness, _unlock_request(harness, target_id="missing"))
        response = await client.post("/unlock/request", headers=headers, json=missing)
        assert response.status_code == 409
        assert response.json()["code"] == "target_offline"

        unpaired = _unlock_request(harness, target_id="unpaired")
        response = await client.post("/unlock/request", headers=headers, json=unpaired)
        assert response.status_code == 409

        wrong_key = {
            **_unlock_request(harness),
            "public_key": "a-different-public-key-with-sufficient-length-1234567890",
        }
        response = await client.post("/unlock/request", headers=headers, json=wrong_key)
        assert response.status_code == 400
        assert response.json()["code"] == "bad_signature"

        too_long = _unlock_request(harness, issued_at=now, exp=now + timedelta(seconds=31))
        response = await client.post("/unlock/request", headers=headers, json=too_long)
        assert response.status_code == 400
        assert response.json()["code"] == "token_ttl_too_long"

        future = _unlock_request(
            harness, issued_at=now + timedelta(seconds=10), exp=now + timedelta(seconds=20)
        )
        response = await client.post("/unlock/request", headers=headers, json=future)
        assert response.status_code == 400
        assert response.json()["code"] == "bad_signature"

        malformed = {**_unlock_request(harness), "issued_at": "not-a-timestamp-value"}
        malformed = _resign(harness, malformed)
        response = await client.post("/unlock/request", headers=headers, json=malformed)
        assert response.status_code == 400
        assert response.json()["code"] == "bad_signature"

        naive_time = now.replace(tzinfo=None).isoformat(timespec="microseconds")
        naive = _unlock_request(harness, issued_at=now)
        naive["issued_at"] = naive_time
        naive = _resign(harness, naive)
        response = await client.post("/unlock/request", headers=headers, json=naive)
        assert response.status_code == 400
        assert response.json()["code"] == "bad_signature"

        expired = _unlock_request(
            harness,
            issued_at=now - timedelta(seconds=30),
            exp=now - timedelta(seconds=1),
        )
        response = await client.post("/unlock/request", headers=headers, json=expired)
        assert response.status_code == 200
        assert response.json()["status"] == "EXPIRED"

        no_assertion = _unlock_request(harness, assertion=False)
        response = await client.post("/unlock/request", headers=headers, json=no_assertion)
        assert response.status_code == 428
        assert response.json()["code"] == "policy_verification_required"

        offline = _unlock_request(harness)
        response = await client.post("/unlock/request", headers=headers, json=offline)
        assert response.status_code == 409
        assert response.json()["code"] == "target_offline"

    await harness.engine.dispose()


@pytest.mark.asyncio
async def test_unlock_is_blocked_by_kill_switch_without_risk_evidence() -> None:
    harness = await _harness()
    async with harness.factory() as session:
        session.add(SystemState(id=1, kill_switch_engaged=True))
        await session.commit()

    async with AsyncClient(
        transport=ASGITransport(app=harness.app), base_url="http://testserver"
    ) as client:
        headers = await _headers(client, harness)
        response = await client.post(
            "/unlock/request", headers=headers, json=_unlock_request(harness)
        )
        assert response.status_code == 423
        assert response.json()["code"] == "kill_switch_active"

    await harness.engine.dispose()


@pytest.mark.asyncio
async def test_direct_unlock_service_path() -> None:
    harness = await _harness()
    now = datetime.now(UTC)
    async with harness.factory() as session:
        user = await session.scalar(select(User).where(User.username == "owner"))
        device = await session.scalar(select(Device).where(Device.public_id == "device-owner"))
        assert user is not None and device is not None
        session.add(_target(target_id="door-1", owner_id=user.id, now=now))
        await session.flush()
        principal = Principal(
            user=user,
            device=device,
            auth_session=AuthSession(
                id=uuid4(),
                user_id=user.id,
                device_id=device.id,
                refresh_token_hash="f" * 64,
                expires_at=now + timedelta(hours=1),
            ),
        )
        response = await request_unlock(
            UnlockRequest.model_validate(_unlock_request(harness)),
            principal,
            session,
            harness.settings,
        )
        assert response.status == "FAILED"

        state = SystemState(id=1, kill_switch_engaged=True)
        session.add(state)
        await session.commit()
        with pytest.raises(APIError) as blocked:
            await request_unlock(
                UnlockRequest.model_validate(_unlock_request(harness)),
                principal,
                session,
                harness.settings,
            )
        assert blocked.value.code == "kill_switch_active"

        await session.delete(state)
        await session.commit()
        with pytest.raises(APIError) as missing_target:
            await request_unlock(
                UnlockRequest.model_validate(_unlock_request(harness, target_id="missing")),
                principal,
                session,
                harness.settings,
            )
        assert missing_target.value.code == "target_offline"
    await harness.engine.dispose()
