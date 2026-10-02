# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import argparse
import asyncio
from datetime import UTC, datetime
from secrets import token_urlsafe

from sqlalchemy import select

from app.audit.service import write_audit
from app.config import get_settings
from app.core.security import encrypt_pairing_secret, hash_device_key
from app.db.models import Device, PairingRequest, User
from app.db.session import SessionFactory


async def decide_pairing(device_public_id: str, *, approved: bool) -> None:
    settings = get_settings()
    async with SessionFactory() as session:
        request = await session.scalar(
            select(PairingRequest)
            .where(PairingRequest.device_public_id == device_public_id)
            .with_for_update()
        )
        if request is None or request.status != "pending":
            raise SystemExit("No pending pairing request for that device id.")
        now = datetime.now(UTC)
        expires_at = request.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at <= now:
            request.status = "expired"
            request.resolved_at = now
            await session.commit()
            raise SystemExit("Pairing request expired.")

        if not approved:
            request.status = "rejected"
            request.resolved_at = now
            await write_audit(
                session,
                actor_user_id=request.owner_id,
                subject_user_id=request.owner_id,
                action="pairing.reject",
                target=device_public_id,
                outcome="DENIED",
                detail="Local operator rejected a pending device pairing request.",
            )
            await session.commit()
            print(f"Rejected {device_public_id}.")
            return

        owner_id = request.owner_id
        if owner_id is None:
            candidates = (await session.scalars(select(User).order_by(User.created_at))).all()
            owner_id = next(
                (candidate.id for candidate in candidates if "owner" in candidate.roles), None
            )
        if owner_id is None:
            raise SystemExit("No owner account exists. Set BOOTSTRAP_ADMIN_PASSWORD first.")

        device_key = f"arx.device.{token_urlsafe(36)}"
        device = Device(
            public_id=device_public_id,
            owner_id=owner_id,
            name=request.device_name,
            platform=request.platform,
            public_key=request.public_key,
            device_key_hash=hash_device_key(device_key),
            site="home",
            kind="OTHER",
            state_json={
                "id": device_public_id,
                "name": request.device_name,
                "site": "home",
                "kind": "OTHER",
                "online": False,
                "risk_tier": "MEDIUM",
                "firmware": "unknown",
                "last_seen_at": now.isoformat(),
                "relays": [],
                "sensors": [],
                "tags": {},
            },
            paired_at=now,
        )
        session.add(device)
        await session.flush()
        request.device_id = device.id
        request.owner_id = owner_id
        request.device_key_ciphertext = encrypt_pairing_secret(settings, device_key)
        request.status = "approved"
        request.resolved_at = now
        await write_audit(
            session,
            actor_user_id=owner_id,
            subject_user_id=owner_id,
            device_id=device.id,
            action="pairing.approve",
            target=device_public_id,
            outcome="SUCCESS",
            detail="Local operator approved a device pairing request.",
        )
        await session.commit()
        # Never print or log the newly issued credential. The approved polling response
        # returns it once the client repeats POST /devices/pair with the same public key.
        print(f"Approved {device_public_id}; the paired client may poll for completion.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Approve or reject a pending A.R.M.X device pair.")
    parser.add_argument("decision", choices=("approve", "reject"))
    parser.add_argument("device_id")
    args = parser.parse_args()
    asyncio.run(decide_pairing(args.device_id, approved=args.decision == "approve"))


if __name__ == "__main__":
    main()
