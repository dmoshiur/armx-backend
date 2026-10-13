# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Operational alerting.

A single, best-effort webhook. Alerts never block the caller, never include credentials or
user content, and a failing alert endpoint can never make the application fail: the point is
to notify a human, not to become a new dependency in the request path.
"""

from __future__ import annotations

import asyncio
from typing import Final

import httpx

from app.core.logging import get_logger
from app.core.redaction import redact_mapping

__all__ = ["AlertSeverity", "send_alert"]

logger = get_logger("alerts")

_ALERT_TIMEOUT: Final = 5.0

#: Strong references to in-flight alert deliveries (see send_alert).
_PENDING_ALERTS: set[asyncio.Task[None]] = set()


class AlertSeverity:
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


def send_alert(
    title: str,
    *,
    severity: str = AlertSeverity.WARNING,
    detail: dict[str, object] | None = None,
    webhook_url: str | None = None,
) -> None:
    """
    Fire-and-forget alert.

    Called from async code; if there is no running loop (CLI usage) the alert is sent
    synchronously so a failed migration still notifies someone.
    """
    from app.config import get_settings

    configured = get_settings()
    url = webhook_url or configured.alert_webhook_url
    if not url:
        return
    payload = {
        "title": title,
        "severity": severity,
        "environment": configured.environment,
        "app": configured.app_name,
        "detail": redact_mapping(detail or {}),
    }
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # Synchronous context (CLI/worker startup): keep it short and swallow failures.
        try:
            httpx.post(url, json=payload, timeout=_ALERT_TIMEOUT)
        except Exception as exc:
            logger.warning("alert delivery failed: %s", type(exc).__name__)
        return
    task = loop.create_task(_post_alert(url, payload))
    # Hold a reference until completion: a bare create_task can be collected mid-flight.
    _PENDING_ALERTS.add(task)
    task.add_done_callback(_PENDING_ALERTS.discard)


async def _post_alert(url: str, payload: dict[str, object]) -> None:
    try:
        async with httpx.AsyncClient(timeout=_ALERT_TIMEOUT) as client:
            response = await client.post(url, json=payload)
            if response.status_code >= 400:
                logger.warning("alert endpoint rejected the alert: %s", response.status_code)
    except Exception as exc:
        logger.warning("alert delivery failed: %s", type(exc).__name__)
    else:
        logger.info("alert delivered: %s", payload.get("title"))
