# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

from datetime import UTC, datetime, timedelta
from secrets import token_hex

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import write_audit
from app.auth.dependencies import Principal, require_principal
from app.config import Settings, get_settings
from app.core.errors import APIError
from app.core.risk_policy import RiskTier
from app.core.security import canonical_json_bytes, hash_nonce, verify_ed25519_signature
from app.core.system_state import is_kill_switch_engaged
from app.core.verification import consume_owner_assertion
from app.db.models import UnlockTarget, UsedNonce
from app.db.session import get_session
from app.unlock.schemas import UnlockOutcomeResponse, UnlockRequest, UnlockTargetResponse

router = APIRouter(prefix="/unlock", tags=["unlock"])


def _target_online(target: UnlockTarget, now: datetime) -> bool:
    last_seen = target.last_seen_at
    last_seen_utc = (
        last_seen.replace(tzinfo=UTC) if last_seen.tzinfo is None else last_seen.astimezone(UTC)
    )
    return target.online and last_seen_utc >= now - timedelta(seconds=90)


class UnlockRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_id: str = Field(min_length=1, max_length=96)


def _parse_datetime(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise APIError(
            "bad_signature", "Unlock token timestamp is invalid", status_code=400
        ) from None
    if parsed.tzinfo is None:
        raise APIError(
            "bad_signature", "Unlock token timestamp must include a timezone", status_code=400
        )
    return parsed.astimezone(UTC)


@router.get("/paired-targets", response_model=list[UnlockTargetResponse])
async def paired_targets(
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
) -> list[UnlockTargetResponse]:
    # The client ArmxApi and original backend prompt expect this route, but docs/api.md
    # does not enumerate it; it is documented as a proposed addition in API_GAPS.md.
    now = datetime.now(UTC)
    rows = (
        await session.scalars(
            select(UnlockTarget)
            .where(UnlockTarget.owner_id == principal.user.id, UnlockTarget.paired.is_(True))
            .order_by(UnlockTarget.name)
        )
    ).all()
    return [
        UnlockTargetResponse(
            id=row.id,
            name=row.name,
            kind=row.kind,
            online=_target_online(row, now),
            last_seen_at=row.last_seen_at,
            risk_tier=RiskTier.from_wire(row.risk_tier).value,
            paired=row.paired,
            agent_version=row.agent_version,
        )
        for row in rows
    ]


@router.post("/request", response_model=UnlockOutcomeResponse)
async def request_unlock(
    body: UnlockRequest,
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> UnlockOutcomeResponse:
    if await is_kill_switch_engaged(session):
        raise APIError("kill_switch_active", "The global kill-switch is engaged", status_code=423)

    target = await session.get(UnlockTarget, body.device_id)
    if target is None or target.owner_id != principal.user.id or not target.paired:
        raise APIError(
            "target_offline", "Unlock target is unavailable", status_code=409, retryable=True
        )
    if body.public_key != principal.device.public_key:
        raise APIError("bad_signature", "Unlock signature is invalid", status_code=400)

    issued_at = _parse_datetime(body.issued_at)
    expires_at = _parse_datetime(body.exp)
    now = datetime.now(UTC)
    max_ttl = timedelta(seconds=settings.unlock_token_ttl_seconds)
    if expires_at <= issued_at or expires_at - issued_at > max_ttl:
        raise APIError(
            "token_ttl_too_long", "Unlock token TTL must not exceed 30 seconds", status_code=400
        )
    if expires_at > now + max_ttl + timedelta(seconds=5):
        raise APIError(
            "token_ttl_too_long", "Unlock token expiry is too far in the future", status_code=400
        )
    if issued_at > now.replace(microsecond=0) + timedelta(seconds=5):
        raise APIError("bad_signature", "Unlock token issue time is invalid", status_code=400)

    # docs/api.md defines the canonical signature object; timestamps, algorithm, and key
    # are validated separately, while device binding ensures only the paired key is accepted.
    signed_data = canonical_json_bytes(
        {
            "device_id": body.device_id,
            "nonce": body.nonce,
            "exp": body.exp,
            "action": body.action,
        }
    )
    if not verify_ed25519_signature(body.public_key, body.signature, signed_data):
        raise APIError("bad_signature", "Unlock signature is invalid", status_code=400)
    if expires_at <= now:
        await write_audit(
            session,
            actor_user_id=principal.user.id,
            subject_user_id=principal.user.id,
            device_id=principal.device.id,
            action="unlock.request",
            target=target.id,
            risk_tier="HIGH",
            outcome="DENIED",
            detail="Unlock request expired before processing.",
        )
        await session.commit()
        return UnlockOutcomeResponse(
            status="EXPIRED",
            request_id=f"unlock-{token_hex(4)}",
            target_id=target.id,
            message="Token expired before it reached the target.",
        )

    if body.assertion is None:
        raise APIError(
            "policy_verification_required",
            "HIGH-tier unlock verification is required",
            status_code=428,
        )
    await consume_owner_assertion(
        session,
        principal,
        body.assertion,
        tier=RiskTier.HIGH,
        max_ttl_seconds=settings.unlock_token_ttl_seconds,
    )

    request_nonce = UsedNonce(
        nonce_hash=hash_nonce(body.nonce),
        device_id=principal.device.id,
        scope="unlock.request",
        expires_at=expires_at,
    )
    try:
        async with session.begin_nested():
            session.add(request_nonce)
            await session.flush()
    except IntegrityError:
        raise APIError("bad_signature", "Unlock nonce was already used", status_code=400) from None

    request_id = f"unlock-{token_hex(4)}"
    if not _target_online(target, now):
        await write_audit(
            session,
            actor_user_id=principal.user.id,
            subject_user_id=principal.user.id,
            device_id=principal.device.id,
            action="unlock.request",
            target=target.id,
            risk_tier="HIGH",
            outcome="FAILURE",
            detail="Unlock target is offline.",
        )
        await session.commit()
        raise APIError(
            "target_offline", "Unlock target is offline", status_code=409, retryable=True
        )

    # Unlock agents are a separate component and this contract does not define their
    # delivery/acknowledgement transport. Never claim a machine was unlocked here.
    await write_audit(
        session,
        actor_user_id=principal.user.id,
        subject_user_id=principal.user.id,
        device_id=principal.device.id,
        action="unlock.request",
        target=target.id,
        risk_tier="HIGH",
        outcome="FAILURE",
        detail="Signed unlock token verified; no unlock agent transport is configured.",
    )
    await session.commit()
    return UnlockOutcomeResponse(
        status="FAILED",
        request_id=request_id,
        target_id=target.id,
        message="Unlock agent transport is not connected.",
    )


@router.post("/revoke", response_model=list[UnlockTargetResponse])
async def revoke_target(
    body: UnlockRevokeRequest,
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
) -> list[UnlockTargetResponse]:
    target = await session.get(UnlockTarget, body.target_id)
    if target is not None and target.owner_id == principal.user.id:
        target.paired = False
        await write_audit(
            session,
            actor_user_id=principal.user.id,
            subject_user_id=principal.user.id,
            device_id=principal.device.id,
            action="unlock.revoke",
            target=target.id,
            risk_tier="HIGH",
            detail="Unlock target unpaired.",
        )
        await session.commit()
    now = datetime.now(UTC)
    rows = (
        await session.scalars(
            select(UnlockTarget)
            .where(UnlockTarget.owner_id == principal.user.id, UnlockTarget.paired.is_(True))
            .order_by(UnlockTarget.name)
        )
    ).all()
    return [
        UnlockTargetResponse(
            id=row.id,
            name=row.name,
            kind=row.kind,
            online=_target_online(row, now),
            last_seen_at=row.last_seen_at,
            risk_tier=RiskTier.from_wire(row.risk_tier).value,
            paired=row.paired,
            agent_version=row.agent_version,
        )
        for row in rows
    ]
