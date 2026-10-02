# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import argparse
import asyncio
import re
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select

from app.audit.service import write_audit
from app.core.security import decode_ed25519_spki
from app.db.models import ResourceDevice, UnlockTarget, User
from app.db.session import SessionFactory

_ID_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,96}")


def _parse_relays(values: list[str]) -> list[dict[str, object]]:
    relays: list[dict[str, object]] = []
    seen: set[str] = set()
    for value in values:
        parts = [part.strip() for part in value.split(",")]
        if len(parts) != 4:
            raise ValueError("Relay must be ID,LABEL,RISK_TIER,MOMENTARY")
        relay_id, label, risk_tier, momentary = parts
        if not _ID_PATTERN.fullmatch(relay_id) or relay_id in seen:
            raise ValueError("Relay IDs must be valid and unique")
        if not label or len(label) > 120:
            raise ValueError("Relay labels must be 1–120 characters")
        if risk_tier.upper() not in {"LOW", "MEDIUM", "HIGH"}:
            raise ValueError("Relay risk must be LOW, MEDIUM, or HIGH")
        if momentary.lower() not in {"true", "false"}:
            raise ValueError("Relay momentary flag must be true or false")
        seen.add(relay_id)
        relays.append(
            {
                "id": relay_id,
                "label": label,
                "state": "UNKNOWN",
                "last_changed_at": datetime.now(UTC).isoformat(),
                "risk_tier": risk_tier.upper(),
                "is_momentary": momentary.lower() == "true",
            }
        )
    return relays


async def _owner_id(public_id: str) -> UUID:
    async with SessionFactory() as session:
        user = await session.scalar(select(User).where(User.public_id == public_id))
        if user is None or not user.is_active:
            raise ValueError("Active owner account was not found")
        return user.id


async def provision_resource(args: argparse.Namespace) -> None:
    if (
        not _ID_PATTERN.fullmatch(args.id)
        or not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", args.site)
        or not args.name.strip()
        or len(args.name) > 120
        or not args.kind.strip()
        or len(args.kind) > 24
    ):
        raise SystemExit("Device ID, site, name, or kind is invalid")
    try:
        relays = _parse_relays(args.relay)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
    owner_id = await _owner_id(args.owner)
    now = datetime.now(UTC)
    async with SessionFactory() as session:
        if await session.get(ResourceDevice, args.id) is not None:
            raise SystemExit("A resource device with that ID already exists")
        device = ResourceDevice(
            id=args.id,
            owner_id=owner_id,
            name=args.name,
            site=args.site,
            kind=args.kind,
            online=False,
            risk_tier=args.risk_tier,
            firmware="unknown",
            last_seen_at=now,
            relays=relays,
            sensors=[],
            tags={},
        )
        session.add(device)
        await write_audit(
            session,
            actor_user_id=None,
            subject_user_id=owner_id,
            action="device.provision",
            target=args.id,
            risk_tier=args.risk_tier,
            outcome="SUCCESS",
            detail="Resource device was provisioned by the local operator.",
            metadata={"relay_count": len(relays), "site": args.site},
        )
        await session.commit()
    print(f"Provisioned resource device {args.id}; waiting for MQTT state telemetry.")


async def provision_unlock_target(args: argparse.Namespace) -> None:
    if (
        not _ID_PATTERN.fullmatch(args.id)
        or not args.name.strip()
        or len(args.name) > 160
        or not args.kind.strip()
        or len(args.kind) > 24
        or len(args.agent_version) > 48
    ):
        raise SystemExit("Unlock target ID, name, kind, or version is invalid")
    try:
        decode_ed25519_spki(args.public_key)
    except ValueError:
        raise SystemExit("Unlock target public key must be base64 Ed25519 SPKI DER") from None
    owner_id = await _owner_id(args.owner)
    now = datetime.now(UTC)
    async with SessionFactory() as session:
        if await session.get(UnlockTarget, args.id) is not None:
            raise SystemExit("An unlock target with that ID already exists")
        target = UnlockTarget(
            id=args.id,
            owner_id=owner_id,
            name=args.name,
            kind=args.kind,
            public_key=args.public_key,
            online=False,
            last_seen_at=now,
            risk_tier=args.risk_tier,
            paired=True,
            agent_version=args.agent_version,
        )
        session.add(target)
        await write_audit(
            session,
            actor_user_id=None,
            subject_user_id=owner_id,
            action="unlock.target.provision",
            target=args.id,
            risk_tier="HIGH",
            outcome="SUCCESS",
            detail=("Unlock target was registered; no unlock-agent transport is configured."),
        )
        await session.commit()
    print(f"Registered unlock target {args.id}; actuation remains unavailable without an agent.")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Provision A.R.M.X resource devices and unlock targets from a trusted operator host."
        )
    )
    commands = parser.add_subparsers(dest="command", required=True)

    resource = commands.add_parser("resource", help="register an MQTT resource device")
    resource.add_argument("--id", required=True)
    resource.add_argument("--owner", required=True, help="owner's public user ID")
    resource.add_argument("--name", required=True)
    resource.add_argument("--site", default="home")
    resource.add_argument("--kind", default="OTHER")
    resource.add_argument("--risk-tier", choices=("LOW", "MEDIUM", "HIGH"), default="MEDIUM")
    resource.add_argument(
        "--relay",
        action="append",
        default=[],
        metavar="ID,LABEL,RISK_TIER,MOMENTARY",
        help="repeat for each relay; momentary is true or false",
    )

    unlock = commands.add_parser("unlock-target", help="register a future unlock agent target")
    unlock.add_argument("--id", required=True)
    unlock.add_argument("--owner", required=True, help="owner's public user ID")
    unlock.add_argument("--name", required=True)
    unlock.add_argument("--kind", default="OTHER")
    unlock.add_argument("--public-key", required=True, help="base64 Ed25519 SPKI DER")
    unlock.add_argument("--risk-tier", choices=("LOW", "MEDIUM", "HIGH"), default="HIGH")
    unlock.add_argument("--agent-version", default="", help="informational only")
    return parser


async def _run(args: argparse.Namespace) -> None:
    if args.command == "resource":
        await provision_resource(args)
    else:
        await provision_unlock_target(args)


def main() -> None:
    asyncio.run(_run(_parser().parse_args()))


if __name__ == "__main__":
    main()
