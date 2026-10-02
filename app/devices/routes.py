# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import asyncio
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import write_audit
from app.auth.dependencies import Principal, public_device_id, require_principal
from app.config import Settings, get_settings
from app.core.errors import APIError
from app.core.execution import execution_registry
from app.core.risk_policy import RiskTier
from app.core.system_state import is_kill_switch_engaged
from app.core.verification import consume_owner_assertion
from app.db.models import AuthSession, Device, ResourceDevice
from app.db.session import get_session
from app.devices.mqtt import publish_device_command
from app.devices.schemas import (
    DeviceCommandRequest,
    DeviceCommandResponse,
    DeviceResponse,
    SceneActivateRequest,
    UnpairRequest,
)
from app.ws.manager import connection_manager

router = APIRouter(prefix="/devices", tags=["devices"])


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _is_online(device: ResourceDevice, now: datetime) -> bool:
    return device.online and _utc(device.last_seen_at) >= now - timedelta(seconds=90)


def _relay_risk(device: ResourceDevice, relay_id: str) -> RiskTier:
    relay = next((item for item in device.relays if item.get("id") == relay_id), None)
    candidate = relay.get("risk_tier") if relay else device.risk_tier
    return RiskTier.from_wire(candidate)


@router.get("", response_model=list[DeviceResponse])
async def list_devices(
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
) -> list[DeviceResponse]:
    now = datetime.now(UTC)
    rows = (
        await session.scalars(
            select(ResourceDevice)
            .where(ResourceDevice.owner_id == principal.user.id)
            .order_by(ResourceDevice.name)
        )
    ).all()
    return [
        DeviceResponse(
            id=row.id,
            name=row.name,
            site=row.site,
            kind=row.kind,
            online=_is_online(row, now),
            risk_tier=RiskTier.from_wire(row.risk_tier).value,
            firmware=row.firmware,
            last_seen_at=_utc(row.last_seen_at),
            relays=row.relays,
            sensors=row.sensors,
            tags=row.tags,
        )
        for row in rows
    ]


@router.post("/{device_id}/command", response_model=DeviceCommandResponse)
async def send_command(
    device_id: str,
    body: DeviceCommandRequest,
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> DeviceCommandResponse:
    if await is_kill_switch_engaged(session):
        raise APIError("kill_switch_active", "The global kill-switch is engaged", status_code=423)

    device = await session.get(ResourceDevice, device_id)
    if device is None or device.owner_id != principal.user.id:
        raise APIError("device_not_found", "Device was not found", status_code=404)
    if not _is_online(device, datetime.now(UTC)):
        await write_audit(
            session,
            actor_user_id=principal.user.id,
            subject_user_id=principal.user.id,
            device_id=principal.device.id,
            action="device.command",
            target=device_id,
            risk_tier=RiskTier.from_wire(device.risk_tier).value,
            outcome="FAILURE",
            detail="Command refused because the device is offline or stale.",
        )
        await session.commit()
        raise APIError("device_offline", "Device is offline", status_code=409, retryable=True)

    parts = body.command.split(":", maxsplit=1)
    if len(parts) != 2 or parts[1].upper() not in {"ON", "OFF", "PULSE"}:
        raise APIError("invalid_command", "Unsupported device command", status_code=400)
    relay_id, desired_state = parts[0], parts[1].upper()
    relay = next((item for item in device.relays if item.get("id") == relay_id), None)
    if relay is None:
        raise APIError("device_not_found", "Relay was not found", status_code=404)

    # Client risk_tier is intentionally ignored. The server derives the requirement
    # from the relay policy provisioned by the operator.
    actual_tier = _relay_risk(device, relay_id)
    try:
        await consume_owner_assertion(
            session,
            principal,
            body.owner_verified,
            tier=actual_tier,
            max_ttl_seconds=settings.owner_assertion_ttl_seconds,
        )
    except APIError:
        await write_audit(
            session,
            actor_user_id=principal.user.id,
            subject_user_id=principal.user.id,
            device_id=principal.device.id,
            action="device.command",
            target=device_id,
            risk_tier=actual_tier.value,
            outcome="DENIED",
            detail="Command refused by server-side verification policy.",
        )
        await session.commit()
        raise

    command_id = f"cmd-{secrets.token_hex(4)}"
    task = asyncio.current_task()
    if task is not None:
        await execution_registry.register(task)
    try:
        await write_audit(
            session,
            actor_user_id=principal.user.id,
            subject_user_id=principal.user.id,
            device_id=principal.device.id,
            action="device.command",
            target=device_id,
            risk_tier=actual_tier.value,
            outcome="SUCCESS",
            detail="Verified command submission started; physical state is not confirmed.",
            metadata={"command_id": command_id, "relay_id": relay_id},
        )
        await session.commit()

        if await is_kill_switch_engaged(session):
            raise APIError(
                "kill_switch_active", "The global kill-switch is engaged", status_code=423
            )

        await publish_device_command(
            settings,
            site=device.site,
            device_id=device.id,
            command_id=command_id,
            command=f"{relay_id}:{desired_state}",
            parameters=body.parameters,
        )
        await write_audit(
            session,
            actor_user_id=principal.user.id,
            subject_user_id=principal.user.id,
            device_id=principal.device.id,
            action="device.command",
            target=device_id,
            risk_tier=actual_tier.value,
            outcome="SUCCESS",
            detail="Command accepted by secure MQTT transport; physical state is unconfirmed.",
            metadata={"command_id": command_id, "relay_id": relay_id},
        )
        await session.commit()
    except asyncio.CancelledError:

        async def record_cancellation() -> None:
            await session.rollback()
            await write_audit(
                session,
                actor_user_id=principal.user.id,
                subject_user_id=principal.user.id,
                device_id=principal.device.id,
                action="device.command.cancelled",
                target=device_id,
                risk_tier=actual_tier.value,
                outcome="DENIED",
                detail="Command task canceled by the kill-switch; physical outcome is unknown.",
                metadata={"command_id": command_id, "relay_id": relay_id},
            )
            await session.commit()

        try:
            await asyncio.shield(record_cancellation())
        except Exception:
            pass
        raise
    except APIError as exc:
        await session.rollback()
        await write_audit(
            session,
            actor_user_id=principal.user.id,
            subject_user_id=principal.user.id,
            device_id=principal.device.id,
            action="device.command",
            target=device_id,
            risk_tier=actual_tier.value,
            outcome="DENIED" if exc.code == "kill_switch_active" else "FAILURE",
            detail=(
                "Command interrupted by the kill-switch."
                if exc.code == "kill_switch_active"
                else "Secure MQTT command publish failed."
            ),
            metadata={"command_id": command_id, "relay_id": relay_id},
        )
        await session.commit()
        raise
    except Exception:
        await session.rollback()
        await write_audit(
            session,
            actor_user_id=principal.user.id,
            subject_user_id=principal.user.id,
            device_id=principal.device.id,
            action="device.command",
            target=device_id,
            risk_tier=actual_tier.value,
            outcome="FAILURE",
            detail="Unexpected secure device transport failure; details were omitted.",
            metadata={"command_id": command_id, "relay_id": relay_id},
        )
        await session.commit()
        raise APIError(
            "device_transport_failed",
            "Secure device transport failed",
            status_code=503,
            retryable=True,
        ) from None
    finally:
        if task is not None:
            await execution_registry.unregister(task)

    return DeviceCommandResponse(
        device_id=device_id,
        accepted=True,
        command_id=command_id,
        at=datetime.now(UTC),
        message=(
            f"Command {command_id} accepted by secure MQTT transport; "
            "physical state is not confirmed."
        ),
    )


@router.post("/scenes/{scene_id}/activate", status_code=204)
async def activate_scene(
    scene_id: str,
    body: SceneActivateRequest,
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> Response:
    if await is_kill_switch_engaged(session):
        raise APIError("kill_switch_active", "The global kill-switch is engaged", status_code=423)

    clean_scene_id = scene_id.strip()[:96]
    if not clean_scene_id:
        raise APIError("invalid_scene", "Scene identifier is required", status_code=400)

    try:
        await consume_owner_assertion(
            session,
            principal,
            body.owner_verified,
            tier=RiskTier.MEDIUM,
            max_ttl_seconds=settings.owner_assertion_ttl_seconds,
        )
    except APIError:
        await write_audit(
            session,
            actor_user_id=principal.user.id,
            subject_user_id=principal.user.id,
            device_id=principal.device.id,
            action="scene.activate",
            target=clean_scene_id,
            risk_tier=RiskTier.MEDIUM.value,
            outcome="DENIED",
            detail="Scene activation refused by server-side verification policy.",
        )
        await session.commit()
        raise

    await write_audit(
        session,
        actor_user_id=principal.user.id,
        subject_user_id=principal.user.id,
        device_id=principal.device.id,
        action="scene.activate",
        target=clean_scene_id,
        risk_tier=RiskTier.MEDIUM.value,
        outcome="SUCCESS",
        detail="Verified scene activation request recorded.",
    )
    await session.commit()
    return Response(status_code=204)


@router.post("/unpair", status_code=204)
async def unpair_device(
    body: UnpairRequest,
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
) -> Response:
    target = await session.scalar(
        select(Device).where(
            Device.public_id == body.device_id,
            Device.owner_id == principal.user.id,
        )
    )
    if target is not None and target.is_active:
        now = datetime.now(UTC)
        target.is_active = False
        target.revoked_at = now
        sessions = (
            await session.scalars(
                select(AuthSession).where(
                    AuthSession.device_id == target.id,
                    AuthSession.revoked_at.is_(None),
                )
            )
        ).all()
        for auth_session in sessions:
            auth_session.revoked_at = now
        await write_audit(
            session,
            actor_user_id=principal.user.id,
            subject_user_id=principal.user.id,
            device_id=target.id,
            action="device.unpair",
            target=public_device_id(target),
            outcome="SUCCESS",
            detail="Paired device was unregistered.",
        )
        await session.commit()
        await connection_manager.close_device(target.id)
    return Response(status_code=204)
