# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from io import BytesIO

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import write_audit
from app.auth.dependencies import (
    Principal,
    public_device_id,
    public_user_id,
    require_admin,
    require_principal,
)
from app.config import Settings, get_settings
from app.core.errors import APIError
from app.core.execution import execution_registry
from app.core.risk_policy import RiskTier
from app.core.system_state import is_kill_switch_engaged
from app.core.verification import OwnerAssertionInput, consume_owner_assertion
from app.db.models import (
    Device,
    IntercomAnnouncement,
    IntercomConsent,
    IntercomDelivery,
    User,
)
from app.db.session import get_session
from app.intercom.schemas import (
    AnnouncementResponse,
    ConsentResponse,
    ConsentUpdate,
    OutcomeRequest,
    RecipientResponse,
)
from app.ws.manager import connection_manager

router = APIRouter(prefix="/v1/intercom", tags=["intercom"])
_MAX_AUDIO_BYTES = 10 * 1024 * 1024
_MAX_DURATION_MS = 30_000
_ALLOWED_AUDIO_TYPES = {
    "audio/aac",
    "audio/mpeg",
    "audio/mp4",
    "audio/ogg",
    "audio/wav",
    "audio/webm",
    "audio/x-m4a",
}


def _is_admin(user: User) -> bool:
    return bool({role.lower() for role in user.roles}.intersection({"owner", "admin"}))


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _audio_url(request: Request, announcement_id: str, settings: Settings) -> str:
    path = f"/v1/intercom/announcements/{announcement_id}/audio"
    configured_base = settings.public_api_base_url
    if configured_base:
        return f"{configured_base.rstrip('/')}{path}"
    # This request-derived fallback is only available in local/demo profiles;
    # deployed profiles require a trusted PUBLIC_API_BASE_URL.
    return f"{request.url.scheme}://{request.url.netloc}{path}"


def _aggregate_status(deliveries: list[IntercomDelivery]) -> str:
    statuses = {row.status.upper() for row in deliveries}
    if not statuses:
        return "MISSED"
    if "PLAYED" in statuses:
        return "PLAYED"
    if "DELIVERED" in statuses:
        return "DELIVERED"
    if "QUEUED" in statuses:
        return "QUEUED"
    if statuses == {"REVOKED"}:
        return "REVOKED"
    return "MISSED"


def _aggregate_datetime(values: list[datetime | None]) -> datetime | None:
    timestamps = [value for value in values if value is not None]
    return min(timestamps) if timestamps else None


def _serialize(
    row: IntercomAnnouncement,
    sender: User | None,
    deliveries: list[IntercomDelivery],
    request: Request,
    settings: Settings,
    *,
    target_user_id: str | None,
) -> AnnouncementResponse:
    return AnnouncementResponse(
        id=row.id,
        from_user_id=public_user_id(sender) if sender else "",
        from_name=(sender.display_name or sender.username) if sender else "Unknown sender",
        scope=row.scope,
        target_user_id=target_user_id or "",
        target_label=row.target_label,
        audio_url=_audio_url(request, row.id, settings),
        duration_ms=row.duration_ms,
        status=_aggregate_status(deliveries),
        created_at=row.created_at,
        delivered_at=_aggregate_datetime([delivery.delivered_at for delivery in deliveries]),
        played_at=_aggregate_datetime([delivery.played_at for delivery in deliveries]),
    )


async def _load_deliveries(
    session: AsyncSession,
    announcement_id: str,
    *,
    user_id: uuid.UUID | None = None,
) -> list[IntercomDelivery]:
    statement = select(IntercomDelivery).where(IntercomDelivery.announcement_id == announcement_id)
    if user_id is not None:
        statement = statement.where(IntercomDelivery.target_user_id == user_id)
    return list((await session.scalars(statement.order_by(IntercomDelivery.id))).all())


async def _recalculate_parent(
    session: AsyncSession,
    announcement: IntercomAnnouncement,
) -> None:
    rows = await _load_deliveries(session, announcement.id)
    announcement.status = _aggregate_status(rows)
    announcement.delivered_at = _aggregate_datetime([row.delivered_at for row in rows])
    announcement.played_at = _aggregate_datetime([row.played_at for row in rows])


async def _require_not_killed(session: AsyncSession) -> None:
    if await is_kill_switch_engaged(session):
        raise APIError("kill_switch_active", "The global kill-switch is engaged", status_code=423)


async def _announce_status_event(
    session: AsyncSession,
    announcement: IntercomAnnouncement,
    target_user_id: uuid.UUID,
    status: str,
) -> None:
    target_user = await session.get(User, target_user_id)
    event = {
        "type": "intercom.outcome",
        "announcement_id": announcement.id,
        "target_user_id": public_user_id(target_user) if target_user else "",
        "status": status,
    }
    sender = await session.get(User, announcement.sender_user_id)
    if sender is not None:
        await connection_manager.send_to_user(sender.id, event)
    for user in (await session.scalars(select(User))).all():
        if user.id != announcement.sender_user_id and _is_admin(user):
            await connection_manager.send_to_user(user.id, event)


async def _revoke_pending_announcement(
    session: AsyncSession,
    announcement_id: str,
    *,
    actor_user_id: uuid.UUID,
    device_id: uuid.UUID,
) -> None:
    await session.rollback()
    announcement = await session.get(IntercomAnnouncement, announcement_id)
    if announcement is None:
        return
    revoked: list[IntercomDelivery] = []
    for delivery in await _load_deliveries(session, announcement_id):
        if delivery.status not in {"QUEUED", "DELIVERED"}:
            continue
        delivery.status = "REVOKED"
        revoked.append(delivery)
        await write_audit(
            session,
            actor_user_id=actor_user_id,
            subject_user_id=delivery.target_user_id,
            device_id=device_id,
            action="intercom.announcement.cancelled",
            target=announcement_id,
            risk_tier="LOW",
            outcome="DENIED",
            detail="In-flight delivery was stopped by the global kill-switch.",
        )
    await _recalculate_parent(session, announcement)
    await session.commit()
    for delivery in revoked:
        target_user = await session.get(User, delivery.target_user_id)
        await connection_manager.send_to_device(
            delivery.device_id,
            {
                "type": "intercom.outcome",
                "announcement_id": announcement_id,
                "target_user_id": public_user_id(target_user) if target_user else "",
                "status": "REVOKED",
            },
        )
        await _announce_status_event(session, announcement, delivery.target_user_id, "REVOKED")


@router.get("/recipients", response_model=list[RecipientResponse])
async def list_recipients(
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
) -> list[RecipientResponse]:
    now = datetime.now(UTC)
    rows = (
        await session.execute(
            select(Device, User, IntercomConsent)
            .join(User, Device.owner_id == User.id)
            .outerjoin(IntercomConsent, IntercomConsent.device_id == Device.id)
            .where(Device.is_active.is_(True), Device.revoked_at.is_(None))
            .order_by(User.display_name, Device.name)
        )
    ).all()
    recipients: list[RecipientResponse] = []
    for device, user, consent in rows:
        last_seen = _as_utc(device.last_seen_at)
        user_label = user.display_name or user.username
        primary_role = str(user.roles[0]) if user.roles else "user"
        recipients.append(
            RecipientResponse(
                id=public_device_id(device),
                device_id=public_device_id(device),
                name=device.name,
                user_id=public_user_id(user),
                user_display_name=user_label,
                display_name=device.name or user_label,
                role=primary_role,
                consented=bool(consent and consent.enabled),
                online=bool(last_seen and last_seen >= now - timedelta(seconds=90)),
                last_seen_at=device.last_seen_at,
            )
        )
    return recipients


@router.get("/consent", response_model=ConsentResponse)
async def get_consent(
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
) -> ConsentResponse:
    consent = await session.get(IntercomConsent, principal.device.id)
    if consent is None:
        return ConsentResponse(enabled=False, allow_while_locked=False, updated_at=None)
    return ConsentResponse(
        enabled=consent.enabled,
        allow_while_locked=consent.allow_while_locked,
        updated_at=consent.updated_at,
    )


@router.post("/consent", response_model=ConsentResponse)
async def update_consent(
    body: ConsentUpdate,
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
) -> ConsentResponse:
    consent = await session.get(IntercomConsent, principal.device.id)
    if consent is None:
        consent = IntercomConsent(device_id=principal.device.id)
        session.add(consent)
    consent.enabled = body.enabled
    consent.allow_while_locked = body.enabled and body.allow_while_locked
    await write_audit(
        session,
        actor_user_id=principal.user.id,
        subject_user_id=principal.user.id,
        device_id=principal.device.id,
        action="intercom.consent",
        target=public_device_id(principal.device),
        risk_tier="LOW",
        detail="Intercom receive consent updated.",
        metadata={"enabled": consent.enabled, "allow_while_locked": consent.allow_while_locked},
    )

    revoked: list[IntercomDelivery] = []
    if not consent.enabled:
        revoked = list(
            (
                await session.scalars(
                    select(IntercomDelivery).where(
                        IntercomDelivery.device_id == principal.device.id,
                        IntercomDelivery.status.in_(["QUEUED", "DELIVERED"]),
                    )
                )
            ).all()
        )
        parents: dict[str, IntercomAnnouncement] = {}
        for delivery in revoked:
            delivery.status = "REVOKED"
            await write_audit(
                session,
                actor_user_id=principal.user.id,
                subject_user_id=principal.user.id,
                device_id=principal.device.id,
                action="intercom.announcement.revoked",
                target=delivery.announcement_id,
                risk_tier="LOW",
                outcome="DENIED",
                detail="Pending announcement access was revoked with device consent.",
            )
            parent = await session.get(IntercomAnnouncement, delivery.announcement_id)
            if parent is not None:
                parents[parent.id] = parent
        for parent in parents.values():
            await _recalculate_parent(session, parent)
    await session.commit()
    await session.refresh(consent)

    for delivery in revoked:
        event = {
            "type": "intercom.outcome",
            "announcement_id": delivery.announcement_id,
            "target_user_id": public_user_id(principal.user),
            "status": "REVOKED",
        }
        await connection_manager.send_to_device(delivery.device_id, event)
        parent = await session.get(IntercomAnnouncement, delivery.announcement_id)
        if parent is not None:
            await _announce_status_event(session, parent, principal.user.id, "REVOKED")

    consent_event = {
        "type": "intercom.consent",
        "user_id": public_user_id(principal.user),
        "consented": consent.enabled,
    }
    for user in (await session.scalars(select(User))).all():
        if _is_admin(user):
            await connection_manager.send_to_user(user.id, consent_event)

    return ConsentResponse(
        enabled=consent.enabled,
        allow_while_locked=consent.allow_while_locked,
        updated_at=consent.updated_at,
    )


@router.post("/announcements", response_model=AnnouncementResponse)
async def create_announcement(
    request: Request,
    audio: UploadFile = File(...),
    duration_ms: int = Form(..., ge=1, le=_MAX_DURATION_MS),
    target_user_id: str = Form(default=""),
    mime_type: str = Form(default="audio/mp4"),
    owner_verified: str = Form(...),
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> AnnouncementResponse:
    if not settings.intercom_enabled:
        raise APIError(
            "intercom_disabled", "Intercom is disabled by server policy", status_code=403
        )
    await _require_not_killed(session)

    normalized_mime = mime_type.strip().lower()
    upload_mime = (audio.content_type or "").split(";")[0].strip().lower()
    if normalized_mime not in _ALLOWED_AUDIO_TYPES or (
        upload_mime and upload_mime != normalized_mime
    ):
        raise APIError("intercom_invalid_audio", "Unsupported intercom audio type", status_code=415)
    audio_data = await audio.read(_MAX_AUDIO_BYTES + 1)
    await audio.close()
    if not audio_data or len(audio_data) > _MAX_AUDIO_BYTES:
        raise APIError(
            "intercom_invalid_audio",
            "Intercom audio must be between 1 byte and 10 MB",
            status_code=413,
        )

    target = None
    if target_user_id.strip():
        target = await session.scalar(select(User).where(User.public_id == target_user_id.strip()))
        if target is None:
            await write_audit(
                session,
                actor_user_id=principal.user.id,
                device_id=principal.device.id,
                action="intercom.announcement.rejected",
                target=target_user_id.strip(),
                risk_tier="LOW",
                outcome="DENIED",
                detail="Announcement target is unavailable.",
            )
            await session.commit()
            raise APIError(
                "intercom_target_not_found", "Intercom target is unavailable", status_code=404
            )

    statement = (
        select(Device, User, IntercomConsent)
        .join(User, Device.owner_id == User.id)
        .join(IntercomConsent, IntercomConsent.device_id == Device.id)
        .where(
            Device.is_active.is_(True),
            Device.revoked_at.is_(None),
            IntercomConsent.enabled.is_(True),
        )
    )
    if target is not None:
        statement = statement.where(User.id == target.id)
    recipient_rows = list(
        (await session.execute(statement.order_by(User.display_name, Device.name))).all()
    )
    if target is not None and not recipient_rows:
        await write_audit(
            session,
            actor_user_id=principal.user.id,
            subject_user_id=target.id,
            device_id=principal.device.id,
            action="intercom.announcement.rejected",
            target=public_user_id(target),
            risk_tier="LOW",
            outcome="DENIED",
            detail="Target has no device with active intercom consent.",
        )
        await session.commit()
        raise APIError(
            "intercom_consent_required", "Target has not opted in to intercom", status_code=403
        )

    try:
        assertion = OwnerAssertionInput.model_validate_json(owner_verified)
    except (ValidationError, ValueError):
        raise APIError(
            "policy_verification_required", "A valid face verification is required", status_code=428
        ) from None
    await consume_owner_assertion(
        session,
        principal,
        assertion,
        tier=RiskTier.LOW,
        max_ttl_seconds=settings.owner_assertion_ttl_seconds,
    )

    announcement_id = f"ann-{uuid.uuid4().hex[:12]}"
    scope = "USER" if target is not None else "BROADCAST"
    target_label = (
        ", ".join(dict.fromkeys(device.name for device, _, _ in recipient_rows))[:180]
        if target is not None
        else "All opted-in devices"
    )
    announcement = IntercomAnnouncement(
        id=announcement_id,
        sender_user_id=principal.user.id,
        target_user_id=target.id if target is not None else None,
        target_device_id=None,
        scope=scope,
        target_label=target_label,
        mime_type=normalized_mime,
        duration_ms=duration_ms,
        audio_bytes=audio_data,
        status="QUEUED" if recipient_rows else "MISSED",
    )
    session.add(announcement)
    deliveries: list[IntercomDelivery] = []
    devices_by_id: dict[uuid.UUID, Device] = {}
    for device, user, _ in recipient_rows:
        devices_by_id[device.id] = device
        delivery = IntercomDelivery(
            announcement_id=announcement_id,
            target_user_id=user.id,
            device_id=device.id,
            status="QUEUED",
        )
        deliveries.append(delivery)
        session.add(delivery)
    if not recipient_rows:
        await write_audit(
            session,
            actor_user_id=principal.user.id,
            subject_user_id=principal.user.id,
            device_id=principal.device.id,
            action="intercom.announcement",
            target=announcement_id,
            risk_tier="LOW",
            outcome="FAILURE",
            detail="Broadcast had no opted-in recipients; it was not queued for later delivery.",
        )
    task = asyncio.current_task()
    if task is not None:
        await execution_registry.register(task)
    try:
        await session.commit()
        await session.refresh(announcement)
        await _require_not_killed(session)

        outcome_events: list[tuple[uuid.UUID, str]] = []
        for delivery in deliveries:
            await session.refresh(delivery)
            current_consent = await session.get(IntercomConsent, delivery.device_id)
            if (
                delivery.status == "REVOKED"
                or current_consent is None
                or not current_consent.enabled
            ):
                delivery.status = "REVOKED"
                await write_audit(
                    session,
                    actor_user_id=principal.user.id,
                    subject_user_id=delivery.target_user_id,
                    device_id=principal.device.id,
                    action="intercom.announcement.rejected",
                    target=announcement_id,
                    risk_tier="LOW",
                    outcome="DENIED",
                    detail="Recipient consent was revoked before delivery.",
                )
                outcome_events.append((delivery.target_user_id, "REVOKED"))
                continue

            event = {
                "type": "intercom.announcement",
                "announcement_id": announcement_id,
                "from_name": principal.user.display_name or principal.user.username,
                "audio_url": _audio_url(request, announcement_id, settings),
                "duration_ms": duration_ms,
                "broadcast": scope == "BROADCAST",
            }
            delivered_count = await connection_manager.send_to_device(delivery.device_id, event)
            await session.refresh(delivery)
            current_consent = await session.get(IntercomConsent, delivery.device_id)
            if (
                delivery.status == "REVOKED"
                or current_consent is None
                or not current_consent.enabled
            ):
                delivery.status = "REVOKED"
                outcome_events.append((delivery.target_user_id, "REVOKED"))
            elif delivered_count:
                delivery.status = "DELIVERED"
                delivery.delivered_at = datetime.now(UTC)
                outcome_events.append((delivery.target_user_id, "DELIVERED"))
                await write_audit(
                    session,
                    actor_user_id=principal.user.id,
                    subject_user_id=delivery.target_user_id,
                    device_id=principal.device.id,
                    action="intercom.announcement.delivery",
                    target=announcement_id,
                    risk_tier="LOW",
                    outcome="SUCCESS",
                    detail="Announcement delivered to an opted-in device.",
                    metadata={
                        "recipient_device_id": public_device_id(devices_by_id[delivery.device_id])
                    },
                )
            else:
                delivery.status = "MISSED"
                outcome_events.append((delivery.target_user_id, "MISSED"))
                await write_audit(
                    session,
                    actor_user_id=principal.user.id,
                    subject_user_id=delivery.target_user_id,
                    device_id=principal.device.id,
                    action="intercom.announcement.delivery",
                    target=announcement_id,
                    risk_tier="LOW",
                    outcome="FAILURE",
                    detail=(
                        "Opted-in recipient was offline; "
                        "announcement was not queued for later delivery."
                    ),
                    metadata={
                        "recipient_device_id": public_device_id(devices_by_id[delivery.device_id])
                    },
                )
        await _recalculate_parent(session, announcement)
        await session.commit()
        await session.refresh(announcement)

        for recipient_id, status in outcome_events:
            await _announce_status_event(session, announcement, recipient_id, status)
        all_deliveries = await _load_deliveries(session, announcement_id)
        target_public_id = public_user_id(target) if target is not None else None
        return _serialize(
            announcement,
            principal.user,
            all_deliveries,
            request,
            settings,
            target_user_id=target_public_id,
        )
    except asyncio.CancelledError:
        try:
            await asyncio.shield(
                _revoke_pending_announcement(
                    session,
                    announcement_id,
                    actor_user_id=principal.user.id,
                    device_id=principal.device.id,
                )
            )
        except Exception:
            pass
        raise
    except APIError as exc:
        if exc.code == "kill_switch_active":
            await _revoke_pending_announcement(
                session,
                announcement_id,
                actor_user_id=principal.user.id,
                device_id=principal.device.id,
            )
        raise
    finally:
        if task is not None:
            await execution_registry.unregister(task)


@router.get("/announcements", response_model=list[AnnouncementResponse])
async def list_announcements(
    request: Request,
    target_user_id: str = "",
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> list[AnnouncementResponse]:
    if _is_admin(principal.user):
        result = await session.execute(
            select(IntercomAnnouncement, User)
            .outerjoin(User, IntercomAnnouncement.sender_user_id == User.id)
            .order_by(IntercomAnnouncement.created_at.desc())
        )
        scoped_user_id = None
    else:
        result = await session.execute(
            select(IntercomAnnouncement, User)
            .join(IntercomDelivery, IntercomAnnouncement.id == IntercomDelivery.announcement_id)
            .outerjoin(User, IntercomAnnouncement.sender_user_id == User.id)
            .where(IntercomDelivery.target_user_id == principal.user.id)
            .distinct()
            .order_by(IntercomAnnouncement.created_at.desc())
        )
        scoped_user_id = principal.user.id

    filter_target = target_user_id.strip()
    responses: list[AnnouncementResponse] = []
    for announcement, sender in result.all():
        deliveries = await _load_deliveries(session, announcement.id, user_id=scoped_user_id)
        target = (
            await session.get(User, announcement.target_user_id)
            if announcement.target_user_id
            else None
        )
        resolved_target_id = public_user_id(target) if target else ""
        if filter_target and resolved_target_id != filter_target:
            continue
        responses.append(
            _serialize(
                announcement,
                sender,
                deliveries,
                request,
                settings,
                target_user_id=resolved_target_id,
            )
        )
    return responses


@router.get("/announcements/{announcement_id}/audio")
async def get_announcement_audio(
    announcement_id: str,
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
) -> StreamingResponse:
    await _require_not_killed(session)
    announcement = await session.get(IntercomAnnouncement, announcement_id)
    if announcement is None:
        raise APIError(
            "intercom_announcement_not_found", "Announcement was not found", status_code=404
        )

    # Admin visibility is for the shared log; access to the recording itself is
    # restricted to its sender or a device that explicitly opted in and received it.
    authorized = announcement.sender_user_id == principal.user.id
    if not authorized:
        authorized = (
            await session.scalar(
                select(IntercomDelivery.id)
                .join(IntercomConsent, IntercomConsent.device_id == IntercomDelivery.device_id)
                .where(
                    IntercomDelivery.announcement_id == announcement_id,
                    IntercomDelivery.target_user_id == principal.user.id,
                    IntercomDelivery.device_id == principal.device.id,
                    IntercomDelivery.status.in_(["QUEUED", "DELIVERED", "PLAYED"]),
                    IntercomConsent.enabled.is_(True),
                )
                .limit(1)
            )
        ) is not None
    if not authorized:
        await write_audit(
            session,
            actor_user_id=principal.user.id,
            subject_user_id=principal.user.id,
            device_id=principal.device.id,
            action="intercom.audio.rejected",
            target=announcement_id,
            risk_tier="LOW",
            outcome="DENIED",
            detail="Audio access denied because the device has no active consented delivery.",
        )
        await session.commit()
        raise APIError(
            "permission_denied", "Audio is not available to this device", status_code=403
        )
    return StreamingResponse(
        BytesIO(announcement.audio_bytes),
        media_type=announcement.mime_type,
        headers={
            "Cache-Control": "no-store, private",
            "X-Content-Type-Options": "nosniff",
            "Content-Length": str(len(announcement.audio_bytes)),
        },
    )


@router.post("/announcements/{announcement_id}/outcome", response_model=AnnouncementResponse)
async def report_outcome(
    announcement_id: str,
    body: OutcomeRequest,
    request: Request,
    principal: Principal = Depends(require_principal),
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> AnnouncementResponse:
    announcement = await session.get(IntercomAnnouncement, announcement_id)
    if announcement is None:
        raise APIError(
            "intercom_announcement_not_found", "Announcement was not found", status_code=404
        )
    delivery = await session.scalar(
        select(IntercomDelivery).where(
            IntercomDelivery.announcement_id == announcement_id,
            IntercomDelivery.device_id == principal.device.id,
        )
    )
    if delivery is None:
        await write_audit(
            session,
            actor_user_id=principal.user.id,
            subject_user_id=principal.user.id,
            device_id=principal.device.id,
            action="intercom.outcome.rejected",
            target=announcement_id,
            risk_tier="LOW",
            outcome="DENIED",
            detail="Device is not a recipient of this announcement.",
        )
        await session.commit()
        raise APIError(
            "permission_denied", "Device is not a recipient of this announcement", status_code=403
        )

    requested_status = body.status
    consent = await session.get(IntercomConsent, principal.device.id)
    if requested_status in {"DELIVERED", "PLAYED"} and (consent is None or not consent.enabled):
        requested_status = "REVOKED"
    transitions = {
        "QUEUED": {"DELIVERED", "PLAYED", "MISSED", "REVOKED"},
        "DELIVERED": {"DELIVERED", "PLAYED", "MISSED", "REVOKED"},
        "PLAYED": {"PLAYED"},
        "MISSED": {"MISSED", "REVOKED"},
        "REVOKED": {"REVOKED"},
    }
    if requested_status not in transitions.get(delivery.status, set()):
        raise APIError(
            "intercom_invalid_transition",
            "Announcement outcome cannot move backwards",
            status_code=409,
        )

    delivery.status = requested_status
    now = datetime.now(UTC)
    if requested_status in {"DELIVERED", "PLAYED"} and delivery.delivered_at is None:
        delivery.delivered_at = now
    if requested_status == "PLAYED":
        delivery.played_at = delivery.played_at or now
    await _recalculate_parent(session, announcement)
    await write_audit(
        session,
        actor_user_id=principal.user.id,
        subject_user_id=principal.user.id,
        device_id=principal.device.id,
        action="intercom.outcome",
        target=announcement_id,
        risk_tier="LOW",
        outcome="DENIED" if requested_status == "REVOKED" else "SUCCESS",
        detail=f"Recipient device reported {requested_status}.",
    )
    await session.commit()
    await session.refresh(announcement)
    await _announce_status_event(session, announcement, principal.user.id, requested_status)

    user_deliveries = await _load_deliveries(session, announcement_id, user_id=principal.user.id)
    sender = await session.get(User, announcement.sender_user_id)
    return _serialize(
        announcement,
        sender,
        user_deliveries,
        request,
        settings,
        target_user_id=public_user_id(principal.user),
    )
