# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

from datetime import UTC, datetime

import jwt
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import Principal
from app.core.errors import APIError, PolicyError
from app.core.risk_policy import RiskTier, evaluate
from app.core.security import hash_nonce, verify_owner_assertion
from app.db.models import UsedNonce


class OwnerAssertionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=40, max_length=4096)
    scope: str = Field(default="owner_verified", min_length=1, max_length=80)
    single_use: bool = True
    iat: datetime | None = None
    exp: datetime | None = None


async def consume_owner_assertion(
    session: AsyncSession,
    principal: Principal,
    assertion: OwnerAssertionInput | None,
    *,
    tier: RiskTier,
    max_ttl_seconds: int,
) -> frozenset[str]:
    if assertion is None or not assertion.token:
        raise PolicyError()
    now = datetime.now(UTC)
    try:
        verified = verify_owner_assertion(
            assertion.token,
            device_public_key_b64=principal.device.public_key,
            expected_device_id=principal.device.public_id,
            expected_scope="owner_verified",
            now=now,
            max_ttl_seconds=max_ttl_seconds,
        )
    except (jwt.InvalidTokenError, ValueError, TypeError):
        raise APIError(
            "policy_verification_required",
            "A valid owner verification is required",
            status_code=428,
        ) from None
    if assertion.scope != verified.scope or not assertion.single_use:
        raise APIError(
            "policy_verification_required",
            "A valid owner verification is required",
            status_code=428,
        )
    if assertion.iat is not None and int(assertion.iat.timestamp()) != int(
        verified.issued_at.timestamp()
    ):
        raise APIError(
            "policy_verification_required",
            "A valid owner verification is required",
            status_code=428,
        )
    if assertion.exp is not None and int(assertion.exp.timestamp()) != int(
        verified.expires_at.timestamp()
    ):
        raise APIError(
            "policy_verification_required",
            "A valid owner verification is required",
            status_code=428,
        )

    decision = evaluate(
        tier,
        verified.factors,
        signature_valid=True,
        unexpired=verified.expires_at > now,
    )
    if not decision.allowed:
        raise PolicyError()

    nonce = UsedNonce(
        nonce_hash=hash_nonce(verified.nonce),
        device_id=principal.device.id,
        scope=verified.scope,
        expires_at=verified.expires_at,
    )
    try:
        async with session.begin_nested():
            session.add(nonce)
            await session.flush()
    except IntegrityError:
        raise APIError(
            "owner_assertion_replayed", "This verification was already used", status_code=409
        ) from None
    return verified.factors
