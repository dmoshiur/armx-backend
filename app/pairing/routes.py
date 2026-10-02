# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import base64
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from secrets import token_urlsafe

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.schemas import PairApprovedResponse, PairPendingResponse, PairRequest
from app.config import Settings, get_settings
from app.core.errors import APIError
from app.core.security import (
    canonical_json_bytes,
    decode_ed25519_spki,
    decrypt_pairing_secret,
    hash_nonce,
    verify_ed25519_signature,
)
from app.db.models import PairingRequest as PairingRequestRow
from app.db.models import UsedNonce, User
from app.db.session import get_session

router = APIRouter(prefix="/devices", tags=["pairing"])
PAIRING_TTL = timedelta(minutes=15)


def _poll_signed(pairing_request: PairingRequestRow, body: PairRequest) -> bool:
    if not body.challenge or not body.challenge_signature:
        return False
    if body.challenge != pairing_request.poll_challenge:
        return False
    signed = canonical_json_bytes(
        {
            "device_id": pairing_request.device_public_id,
            "challenge": body.challenge,
        }
    )
    return verify_ed25519_signature(
        pairing_request.public_key,
        body.challenge_signature,
        signed,
    )


async def _new_request(
    body: PairRequest, public_key_bytes: bytes, session: AsyncSession
) -> PairingRequestRow:
    owner_id = None
    for candidate in (await session.scalars(select(User).order_by(User.created_at))).all():
        if "owner" in {role.lower() for role in candidate.roles}:
            owner_id = candidate.id
            break
    device_public_id = f"device-{token_urlsafe(6).replace('-', '').replace('_', '')[:8]}"
    now = datetime.now(UTC)
    pairing_request = PairingRequestRow(
        owner_id=owner_id,
        device_name=body.device_name,
        platform=body.platform,
        device_public_id=device_public_id,
        poll_challenge=token_urlsafe(32),
        public_key=body.public_key,
        fingerprint=sha256(public_key_bytes).hexdigest(),
        status="pending",
        created_at=now,
        expires_at=now + PAIRING_TTL,
    )
    session.add(pairing_request)
    await session.flush()
    return pairing_request


@router.post("/pair", response_model=PairApprovedResponse | PairPendingResponse)
async def pair_device(
    body: PairRequest,
    response: Response,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> PairApprovedResponse | PairPendingResponse:
    try:
        der_bytes = base64.b64decode(body.public_key, validate=True)
        decode_ed25519_spki(body.public_key)
    except (ValueError, TypeError):
        raise APIError(
            "auth_pairing_rejected", "Invalid Ed25519 public key", status_code=403
        ) from None

    pairing_request = await session.scalar(
        select(PairingRequestRow)
        .where(PairingRequestRow.public_key == body.public_key)
        .order_by(PairingRequestRow.created_at.desc())
        .with_for_update()
    )
    now = datetime.now(UTC)
    if pairing_request is not None and pairing_request.status == "pending":
        expires_at = pairing_request.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at <= now:
            pairing_request.status = "expired"
            pairing_request.resolved_at = now
            await session.commit()
            if body.challenge is not None or body.challenge_signature is not None:
                raise APIError(
                    "pairing_expired",
                    "Pairing request expired; start a new pairing request",
                    status_code=409,
                )
            pairing_request = None
    if pairing_request is not None and pairing_request.status == "rejected":
        # Polling a rejected challenge must not silently create another request.
        # A new initial request (with no challenge proof) is the explicit retry.
        if body.challenge is not None or body.challenge_signature is not None:
            raise APIError(
                "auth_pairing_rejected",
                "The owner rejected this device pairing request",
                status_code=403,
            )
        pairing_request = None
    if pairing_request is not None and pairing_request.status == "expired":
        pairing_request = None
    if pairing_request is not None and pairing_request.status == "completed":
        raise APIError(
            "pairing_completed",
            "Pairing is already complete; use a new key to pair again",
            status_code=409,
        )
    if pairing_request is None:
        pairing_request = await _new_request(body, der_bytes, session)
        await session.commit()

    if pairing_request.status == "rejected":
        raise APIError(
            "auth_pairing_rejected",
            "The owner rejected this device pairing request",
            status_code=403,
        )
    if pairing_request.status not in {"approved", "pending"}:
        raise APIError("pairing_invalid_state", "Pairing request is unavailable", status_code=409)

    # API contract addition: the client receives this one-time challenge and must
    # sign it with the Ed25519 private key before polling again. This proves possession
    # of the key before a long-lived device credential is returned.
    if not body.challenge and not body.challenge_signature:
        response.status_code = status.HTTP_202_ACCEPTED
        message = (
            "Pairing approved; sign the polling challenge to retrieve credentials"
            if pairing_request.status == "approved"
            else "Awaiting owner approval"
        )
        return PairPendingResponse(
            device_id=pairing_request.device_public_id,
            challenge=pairing_request.poll_challenge,
            message=message,
        )
    if not _poll_signed(pairing_request, body):
        raise APIError(
            "auth_pairing_rejected", "Pairing challenge signature is invalid", status_code=403
        )

    if pairing_request.status == "approved":
        if pairing_request.device_id is None:
            raise APIError(
                "pairing_invalid_state", "Pairing approval is incomplete", status_code=500
            )
        replay_marker = UsedNonce(
            nonce_hash=hash_nonce(f"pairing:{pairing_request.device_public_id}:{body.challenge}"),
            device_id=pairing_request.device_id,
            scope="pairing.poll",
            expires_at=now + PAIRING_TTL,
        )
        try:
            async with session.begin_nested():
                session.add(replay_marker)
                await session.flush()
        except IntegrityError:
            raise APIError(
                "auth_pairing_rejected", "Pairing challenge was already used", status_code=403
            ) from None

    # Rotate the challenge on every valid poll to reject replayed signed requests.
    pairing_request.poll_challenge = token_urlsafe(32)
    if pairing_request.status == "pending":
        await session.commit()
        response.status_code = status.HTTP_202_ACCEPTED
        return PairPendingResponse(
            device_id=pairing_request.device_public_id,
            challenge=pairing_request.poll_challenge,
            message="Awaiting owner approval",
        )

    if not pairing_request.device_key_ciphertext or not pairing_request.device_id:
        raise APIError("pairing_invalid_state", "Pairing approval is incomplete", status_code=500)
    device_key = decrypt_pairing_secret(settings, pairing_request.device_key_ciphertext)
    paired_at = pairing_request.resolved_at or pairing_request.created_at
    # The pairing credential is an irretrievable one-time delivery. Completion is
    # persisted before it is returned so fresh challenges cannot retrieve it again.
    pairing_request.status = "completed"
    await session.commit()
    return PairApprovedResponse(
        device_id=pairing_request.device_public_id,
        device_key=device_key,
        site="home",
        paired_at=paired_at,
    )
