# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import asyncio
import json
import logging
import math
from datetime import UTC, datetime
from typing import Any, cast

import aiomqtt
from sqlalchemy import delete, select
from sqlalchemy.engine import CursorResult

from app.config import Settings
from app.core.privacy import contains_raw_biometric_data
from app.db.models import ResourceDevice, UsedNonce
from app.db.session import SessionFactory
from app.devices.mqtt import _tls_context
from app.ws.manager import connection_manager

logger = logging.getLogger("armx.mqtt.state")


def _text(value: Any, maximum: int, *, default: str = "") -> str:
    if not isinstance(value, str):
        return default
    return value.strip()[:maximum]


def _normalize_relays(
    value: Any,
    now: datetime,
    registered_relays: list[dict[str, Any]],
    device_risk_tier: str,
) -> list[dict[str, Any]]:
    incoming: dict[str, str] = {}
    if isinstance(value, list):
        for item in value[:64]:
            if not isinstance(item, dict) or contains_raw_biometric_data(item):
                continue
            relay_id = _text(item.get("id"), 80)
            state = _text(item.get("state"), 8).upper()
            if relay_id and state in {"ON", "OFF", "UNKNOWN"}:
                incoming[relay_id] = state

    normalized: list[dict[str, Any]] = []
    for config in registered_relays:
        if not isinstance(config, dict) or not isinstance(config.get("id"), str):
            continue
        relay_id = config["id"]
        previous_state = _text(config.get("state"), 8, default="UNKNOWN").upper()
        current_state = incoming.get(relay_id, previous_state)
        changed = relay_id in incoming and current_state != previous_state
        normalized.append(
            {
                "id": relay_id,
                "label": _text(config.get("label"), 120, default=relay_id),
                "state": current_state,
                "last_changed_at": now.isoformat()
                if changed
                else config.get("last_changed_at", now.isoformat()),
                # Relay risk is provisioned server-side; MQTT telemetry cannot lower it.
                "risk_tier": _text(config.get("risk_tier"), 12, default=device_risk_tier).upper(),
                "is_momentary": bool(config.get("is_momentary", False)),
            }
        )
    return normalized


_SENSOR_KINDS = frozenset(
    {"TEMPERATURE", "HUMIDITY", "MOTION", "CONTACT", "BATTERY", "POWER", "OTHER"}
)


def _normalize_sensors(value: Any, now: datetime) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    sensors: list[dict[str, Any]] = []
    for item in value[:64]:
        if not isinstance(item, dict) or contains_raw_biometric_data(item):
            continue
        sensor_id = _text(item.get("id"), 80)
        if not sensor_id:
            continue
        raw_value = item.get("value")
        if not isinstance(raw_value, (int, float, str)):
            continue
        try:
            numeric = float(raw_value)
        except (TypeError, ValueError):
            continue
        if not math.isfinite(numeric):
            continue
        raw_kind = _text(item.get("kind"), 48, default="OTHER").upper()
        kind = raw_kind if raw_kind in _SENSOR_KINDS else "OTHER"
        sensors.append(
            {
                "id": sensor_id,
                "label": _text(item.get("label"), 120, default=sensor_id),
                "kind": kind,
                "value": numeric,
                "unit": _text(item.get("unit"), 24),
                "updated_at": now.isoformat(),
                "is_stale": False,
            }
        )
    return sensors


def _normalize_tags(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, str] = {}
    for key, raw in list(value.items())[:32]:
        if (
            isinstance(key, str)
            and isinstance(raw, str)
            and not contains_raw_biometric_data({key: raw})
            and raw.strip()
        ):
            result[key[:48]] = raw.strip()[:160]
    return result


def _state_event(row: ResourceDevice) -> dict[str, Any]:
    return {
        "type": "device.state",
        "device": {
            "id": row.id,
            "online": row.online,
            "name": row.name,
            "site": row.site,
            "kind": row.kind,
            "risk_tier": row.risk_tier,
            "firmware": row.firmware,
            "last_seen_at": row.last_seen_at.isoformat(),
            "relays": row.relays,
            "sensors": row.sensors,
            "tags": row.tags,
        },
    }


async def _apply_message(topic: str, payload: bytes) -> None:
    parts = topic.split("/")
    if len(parts) != 4 or parts[0] != "armx" or parts[3] != "state":
        return
    site, device_id = parts[1], parts[2]
    if len(payload) > 256 * 1024:
        logger.warning("Discarded oversized MQTT state message")
        return
    try:
        state = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        logger.warning("Discarded malformed MQTT state message")
        return
    if not isinstance(state, dict) or contains_raw_biometric_data(state):
        logger.warning("Discarded MQTT state containing prohibited biometric fields")
        return

    now = datetime.now(UTC)
    async with SessionFactory() as session:
        row = await session.get(ResourceDevice, device_id)
        if row is None or row.site != site:
            return
        row.firmware = _text(state.get("firmware"), 48, default=row.firmware)
        row.online = True
        row.last_seen_at = now
        if "relays" in state:
            row.relays = _normalize_relays(state.get("relays"), now, row.relays, row.risk_tier)
        if "sensors" in state:
            row.sensors = _normalize_sensors(state.get("sensors"), now)
        if "tags" in state:
            row.tags = _normalize_tags(state.get("tags"))
        owner_id = row.owner_id
        await session.commit()
        await session.refresh(row)
        event = _state_event(row)
    await connection_manager.send_to_user(owner_id, event)


async def mqtt_state_listener(settings: Settings, stop: asyncio.Event) -> None:
    """Consume authenticated TLS MQTT telemetry from the external broker.

    The backend dials out to the broker; ESP32 devices connect to the same broker directly
    over MQTT/TLS.  Only state for provisioned devices (``armx/{site}/{device}/state``) is
    accepted, and every event is routed only to the owning user's authenticated sockets.
    """

    if not settings.mqtt_enabled:
        return
    while not stop.is_set():
        try:
            async with aiomqtt.Client(
                hostname=settings.mqtt_host,
                port=settings.mqtt_port,
                identifier=f"{settings.mqtt_client_id}-state",
                keepalive=settings.mqtt_keepalive_seconds,
                username=settings.mqtt_username,
                password=settings.mqtt_password.get_secret_value()
                if settings.mqtt_password
                else None,
                tls_context=_tls_context(settings),
            ) as client:
                await client.subscribe("armx/+/+/state", qos=1)
                async for message in client.messages:
                    if stop.is_set():
                        break
                    try:
                        await _apply_message(str(message.topic), bytes(message.payload))
                    except (TypeError, ValueError, UnicodeError):
                        logger.warning("Discarded invalid MQTT state message")
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("Secure MQTT state listener disconnected; retrying")
        if not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=3)
            except TimeoutError:
                pass


async def mark_stale_devices_offline(stop: asyncio.Event) -> None:
    """Mark resource devices offline after 90 seconds without a valid state update."""

    while not stop.is_set():
        now = datetime.now(UTC)
        async with SessionFactory() as session:
            rows = list(
                (
                    await session.scalars(
                        select(ResourceDevice).where(ResourceDevice.online.is_(True))
                    )
                ).all()
            )
            changed: list[tuple[Any, ResourceDevice]] = []
            for row in rows:
                seen = row.last_seen_at
                seen_utc = seen.replace(tzinfo=UTC) if seen.tzinfo is None else seen.astimezone(UTC)
                if (now - seen_utc).total_seconds() > 90:
                    row.online = False
                    row.sensors = [
                        {**sensor, "is_stale": True}
                        for sensor in row.sensors
                        if isinstance(sensor, dict)
                    ]
                    changed.append((row.owner_id, row))
            expired_nonces = cast(
                CursorResult[Any],
                await session.execute(delete(UsedNonce).where(UsedNonce.expires_at <= now)),
            )
            if changed or expired_nonces.rowcount:
                await session.commit()
                for owner_id, row in changed:
                    await session.refresh(row)
                    await connection_manager.send_to_user(owner_id, _state_event(row))
        try:
            await asyncio.wait_for(stop.wait(), timeout=30)
        except TimeoutError:
            pass
