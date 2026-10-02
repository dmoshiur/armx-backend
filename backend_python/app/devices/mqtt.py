# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

from __future__ import annotations

import asyncio
import json
import logging
import ssl
from typing import Any

import aiomqtt

from app.config import Settings
from app.core.errors import APIError

logger = logging.getLogger("armx.mqtt")


def _tls_context(settings: Settings) -> ssl.SSLContext:
    try:
        return ssl.create_default_context(cafile=settings.mqtt_tls_ca_file)
    except (OSError, ssl.SSLError):
        raise APIError(
            "mqtt_tls_unavailable",
            "Secure device transport is unavailable",
            status_code=503,
            retryable=True,
        ) from None


async def publish_device_command(
    settings: Settings,
    *,
    site: str,
    device_id: str,
    command_id: str,
    command: str,
    parameters: dict[str, Any],
) -> None:
    """Publish a command over verified TLS; no insecure MQTT fallback exists."""

    if not settings.mqtt_enabled:
        raise APIError(
            "device_transport_unavailable",
            "Device transport is unavailable",
            status_code=503,
            retryable=True,
        )
    payload = json.dumps(
        {
            "command_id": command_id,
            "command": command,
            "parameters": parameters,
        },
        separators=(",", ":"),
        ensure_ascii=False,
    )
    username = settings.mqtt_username
    password = settings.mqtt_password.get_secret_value() if settings.mqtt_password else None
    try:
        async with asyncio.timeout(5):
            async with aiomqtt.Client(
                hostname=settings.mqtt_host,
                port=settings.mqtt_port,
                identifier=settings.mqtt_client_id,
                username=username,
                password=password,
                tls_context=_tls_context(settings),
            ) as client:
                await client.publish(
                    f"armx/{site}/{device_id}/cmd",
                    payload,
                    qos=1,
                )
    except TimeoutError:
        raise APIError(
            "device_offline", "Device is offline", status_code=409, retryable=True
        ) from None
    except (aiomqtt.MqttError, OSError, ssl.SSLError):
        logger.warning("MQTT command publish failed; sensitive command values omitted")
        raise APIError(
            "device_offline", "Device is offline", status_code=409, retryable=True
        ) from None
