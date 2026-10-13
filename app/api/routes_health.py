# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Health, readiness and metrics.

``/health`` is the container liveness probe: it answers whenever the process is alive and
reports database reachability without ever exposing configuration values.

``/ready`` is what a load balancer should use: it fails until migrations are applied, so a
new container never receives traffic against an old schema.

``/metrics`` is Prometheus text format. Outside local development it requires an admin
session (see :func:`app.api.routes_health.metrics`), because tool names and denial counts are
operational data, not public data.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app import __version__
from app.api.deps import app_settings, db_session
from app.config import Settings
from app.core.errors import APIError
from app.core.logging import get_logger
from app.core.metrics import render_prometheus, set_gauge
from app.core.time import utcnow
from app.db.bootstrap import current_migration_revision, pending_approval_count
from app.db.session import check_database

__all__ = ["router"]

logger = get_logger("api.health")
router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: str
    server_version: str
    environment: str
    database: str
    at: datetime


class ReadyResponse(BaseModel):
    status: str
    database: str
    migration_revision: str | None
    kill_switch_engaged: bool
    llm_provider: str
    email_delivery_mode: str
    worker_enabled: bool
    at: datetime


@router.get("/health", response_model=HealthResponse)
async def health(
    session: AsyncSession = Depends(db_session),
    settings: Settings = Depends(app_settings),
) -> HealthResponse:
    """Liveness. 503 when the database is unreachable, never a leaked exception detail."""
    ok, _ = await check_database(session)
    if not ok:
        raise APIError(
            "service_unavailable", "Database unavailable", status_code=503, retryable=True
        )
    return HealthResponse(
        status="ok",
        server_version=__version__,
        environment=settings.environment,
        database="ok",
        at=utcnow(),
    )


@router.get("/ready", response_model=ReadyResponse)
async def ready(
    session: AsyncSession = Depends(db_session),
    settings: Settings = Depends(app_settings),
) -> ReadyResponse:
    """Readiness gate: database reachable *and* schema migrated."""
    ok, error = await check_database(session)
    if not ok:
        raise APIError(
            "service_unavailable", error or "Database unavailable", status_code=503, retryable=True
        )
    revision = await current_migration_revision(session)
    if revision is None:
        raise APIError(
            "service_unavailable",
            "Database schema is not migrated",
            status_code=503,
            retryable=True,
        )
    from app.security.kill_switch import KillSwitch  # local import: avoids a cycle at import time

    engaged = await KillSwitch(settings).is_engaged(session)
    return ReadyResponse(
        status="ready",
        database="ok",
        migration_revision=revision,
        kill_switch_engaged=engaged,
        llm_provider=settings.llm_provider,
        email_delivery_mode=settings.email_delivery_mode,
        worker_enabled=settings.worker_enabled,
        at=utcnow(),
    )


@router.get("/metrics", include_in_schema=False)
async def metrics(
    request: Request,
    session: AsyncSession = Depends(db_session),
    settings: Settings = Depends(app_settings),
) -> Response:
    """
    Prometheus metrics.

    Local development gets an unauthenticated endpoint for convenience; everywhere else an
    admin session is required. The count of pending approvals is refreshed from the database
    on every scrape so a stalled approval queue is visible on a dashboard.
    """
    if not settings.metrics_enabled:
        raise APIError.not_found("Metrics are disabled")
    if not settings.is_local_dev:
        from app.auth.dependencies import require_role  # local import: avoids an import cycle
        from app.core.enums import Role

        require_role(Role.ADMIN)(request)  # synchronous dependency: raises, never awaits
    try:
        set_gauge("pending_approvals", float(await pending_approval_count(session)))
    except Exception as exc:
        logger.warning("could not refresh gauges for metrics scrape: %s", type(exc).__name__)
    return Response(content=render_prometheus(), media_type="text/plain; version=0.0.4")
