# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.admin.schemas import (
    AdminStateResponse,
    KillSwitchRequest,
    KillSwitchResponse,
    RevokeDeviceRequest,
    ToolToggleRequest,
    ToolToggleResponse,
)
from app.audit.service import write_audit
from app.auth.dependencies import Principal, public_device_id, require_admin
from app.config import Settings, get_settings
from app.core.errors import APIError
from app.core.execution import execution_registry
from app.db.models import AuthSession, Device, PendingToolCall, SystemState, ToolToggle
from app.db.session import get_session
from app.ws.manager import connection_manager

router = APIRouter(prefix="/admin", tags=["admin"])
_TOOL_INFO = {
    "GITHUB": ("GitHub", "Repository read actions and confirmed write actions", "MEDIUM"),
    "MAIL": (
        "Email",
        "Disabled until per-message and one-time recipient-consent support exists",
        "MEDIUM",
    ),
    "MQTT": ("MQTT", "Publish commands to registered devices", "HIGH"),
    "DB": ("Notes", "Search and manage the owner's local notes", "MEDIUM"),
    "SYSTEM": ("System", "Privileged operating-system actions are unavailable", "HIGH"),
    "VISION": ("Vision", "Only signed verification assertions; no biometric uploads", "HIGH"),
}


def _tool_response(row: ToolToggle, settings: Settings) -> ToolToggleResponse:
    label, description, tier = _TOOL_INFO.get(row.name, (row.name, "", "HIGH"))
    connected = {
        "GITHUB": bool(
            settings.github_enabled and settings.github_token and settings.github_repository
        ),
        # Email content/contact access is deliberately unavailable until its explicit,
        # revocable, per-recipient consent flow is specified and implemented.
        "MAIL": False,
        "MQTT": settings.mqtt_enabled,
        "DB": settings.notes_enabled,
        "SYSTEM": False,
        "VISION": False,
    }.get(row.name, False)
    return ToolToggleResponse(
        id=row.name,
        label=label,
        description=description,
        enabled=row.enabled and connected,
        connected=connected,
        max_risk_tier=tier,
        requires_approval=True,
    )


async def _admin_state(
    session: AsyncSession,
    principal: Principal,
    settings: Settings,
) -> AdminStateResponse:
    state = await session.get(SystemState, 1)
    if state is None:
        state = SystemState(id=1, assistant_enabled=True, kill_switch_engaged=False)
        session.add(state)
        await session.flush()
    tools = (await session.scalars(select(ToolToggle).order_by(ToolToggle.name))).all()
    revoked_count = await session.scalar(
        select(func.count()).select_from(Device).where(Device.revoked_at.is_not(None))
    )
    roles = {role.lower() for role in principal.user.roles}
    actor = "owner" if "owner" in roles else "admin"
    return AdminStateResponse(
        assistant_enabled=state.assistant_enabled,
        kill_switch_engaged=state.kill_switch_engaged,
        tools=[_tool_response(tool, settings) for tool in tools],
        updated_at=state.updated_at,
        engaged_by=actor if state.kill_switch_engaged else "",
        engaged_reason=state.reason if state.kill_switch_engaged else "",
        revoked_devices=int(revoked_count or 0),
    )


@router.get("/state", response_model=AdminStateResponse)
async def get_admin_state(
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> AdminStateResponse:
    # The Flutter ArmxApi interface calls GET /admin/state, but docs/api.md does not
    # currently list it. Its shape follows the existing AdminState model and is flagged
    # as a contract addition in API_GAPS.md.
    return await _admin_state(session, principal, settings)


@router.post("/kill", response_model=KillSwitchResponse)
async def set_kill_switch(
    body: KillSwitchRequest,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> KillSwitchResponse:
    now = datetime.now(UTC)
    state = await session.get(SystemState, 1)
    if state is None:
        state = SystemState(id=1, assistant_enabled=True, kill_switch_engaged=False)
        session.add(state)
        await session.flush()

    state.kill_switch_engaged = body.engaged
    state.updated_at = now
    state.updated_by = principal.user.id
    state.reason = body.reason or (
        "Owner engaged the kill-switch" if body.engaged else "Re-enabled by owner"
    )
    if body.engaged:
        pending = (
            await session.scalars(
                select(PendingToolCall).where(PendingToolCall.status.in_(["PENDING", "EXECUTING"]))
            )
        ).all()
        for call in pending:
            was_executing = call.status == "EXECUTING"
            call.status = "EXPIRED"
            call.decided_at = now
            call.result_summary = (
                "Kill-switch stopped the action; external completion may be uncertain."
                if was_executing
                else "Kill-switch expired this pending request before execution."
            )
            await write_audit(
                session,
                actor_user_id=principal.user.id,
                subject_user_id=call.user_id,
                device_id=call.device_id,
                action="tool.cancelled",
                target=call.id,
                risk_tier=call.risk_tier,
                outcome="DENIED",
                detail=(
                    "Kill-switch canceled in-flight tool work; outcome may be uncertain."
                    if was_executing
                    else "Kill-switch expired an unexecuted pending tool request."
                ),
            )
        await write_audit(
            session,
            actor_user_id=principal.user.id,
            subject_user_id=principal.user.id,
            device_id=principal.device.id,
            action="admin.kill",
            target="global",
            risk_tier="HIGH",
            detail="Global kill-switch engaged.",
        )
    else:
        await write_audit(
            session,
            actor_user_id=principal.user.id,
            subject_user_id=principal.user.id,
            device_id=principal.device.id,
            action="admin.revive",
            target="global",
            risk_tier="HIGH",
            detail="Global kill-switch explicitly re-enabled.",
        )
    await session.commit()

    if body.engaged:
        await execution_registry.cancel_all()
        closed = await connection_manager.kill_all(
            reason=state.reason,
            actor="owner" if "owner" in principal.user.roles else "admin",
        )
    else:
        closed = 0
        await connection_manager.broadcast(
            {
                "type": "system.killed",
                "engaged": False,
                "reason": state.reason,
                "actor": "owner" if "owner" in principal.user.roles else "admin",
            }
        )
    return KillSwitchResponse(
        engaged=body.engaged,
        at=now,
        reason=state.reason,
        actor="owner" if "owner" in principal.user.roles else "admin",
        sockets_closed=closed,
    )


@router.post("/tools", response_model=list[ToolToggleResponse])
async def set_tool_enabled(
    body: ToolToggleRequest,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> list[ToolToggleResponse]:
    row = await session.get(ToolToggle, body.tool)
    if row is None:
        row = ToolToggle(name=body.tool, enabled=False)
        session.add(row)
    row.enabled = body.enabled
    row.updated_by = principal.user.id
    row.updated_at = datetime.now(UTC)
    await write_audit(
        session,
        actor_user_id=principal.user.id,
        subject_user_id=principal.user.id,
        device_id=principal.device.id,
        action="admin.tool.toggle",
        target=body.tool,
        risk_tier="MEDIUM",
        detail="Tool configuration changed.",
        metadata={"tool": body.tool, "enabled": body.enabled},
    )
    await session.commit()
    rows = (await session.scalars(select(ToolToggle).order_by(ToolToggle.name))).all()
    return [_tool_response(tool, settings) for tool in rows]


@router.post("/revoke", response_model=AdminStateResponse)
async def revoke_device(
    body: RevokeDeviceRequest,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> AdminStateResponse:
    target = await session.scalar(select(Device).where(Device.public_id == body.device_id))
    if target is None:
        raise APIError("device_not_found", "Device was not found", status_code=404)
    now = datetime.now(UTC)
    target.is_active = False
    target.revoked_at = now
    auth_sessions = (
        await session.scalars(
            select(AuthSession).where(
                AuthSession.device_id == target.id,
                AuthSession.revoked_at.is_(None),
            )
        )
    ).all()
    for auth_session in auth_sessions:
        auth_session.revoked_at = now
    await write_audit(
        session,
        actor_user_id=principal.user.id,
        subject_user_id=target.owner_id,
        device_id=target.id,
        action="admin.revoke",
        target=public_device_id(target),
        risk_tier="HIGH",
        detail="Device credential revoked by an administrator.",
    )
    await session.commit()
    await connection_manager.close_device(target.id)
    return await _admin_state(session, principal, settings)
