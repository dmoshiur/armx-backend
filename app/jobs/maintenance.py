# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Periodic maintenance.

Runs in every API process (the work is idempotent and cheap) and covers the housekeeping that
makes the guarantees elsewhere true rather than aspirational:

* expired approvals are flipped to ``expired`` *and* audited, so "this was requested and never
  confirmed" stays visible,
* abandoned job claims are requeued instead of silently vanishing,
* retention policies actually delete data (memory, audit, jobs, mail),
* a stale backup raises an alert, because an untested backup is not a backup.
"""

from __future__ import annotations

import asyncio
import contextlib
import glob
import os
from collections.abc import Awaitable, Callable
from datetime import timedelta
from typing import Final

from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.core.alerts import AlertSeverity, send_alert
from app.core.enums import JobStatus
from app.core.logging import get_logger
from app.core.metrics import inc, set_gauge
from app.core.time import utcnow
from app.db.bootstrap import purge_expired_rows
from app.db.models import AuditEvent, ImageAsset, Job, MailOutboxMessage, MemoryItem
from app.db.session import session_scope
from app.db.sql import affected_rows
from app.security.approvals import expire_stale

__all__ = ["maintenance_loop", "run_maintenance_once"]

logger = get_logger("jobs.maintenance")

_INTERVAL_SECONDS: Final = 300
_BACKUP_GRACE_SECONDS: Final = 26 * 3600  # daily backup + slack before alerting
_MAIL_OUTBOX_RETENTION_DAYS: Final = 30
_EXPIRING_APPROVAL_BATCH: Final = 500


async def _expire_approvals(session: AsyncSession) -> int:
    """Flip stale approvals to expired and audit each one (implemented in the security module)."""
    return await expire_stale(session, limit=_EXPIRING_APPROVAL_BATCH)


async def _requeue_abandoned_jobs(session: AsyncSession, settings: Settings) -> int:
    """Return jobs whose worker lease expired to the queue (bounded by max attempts)."""
    now = utcnow()
    result = await session.execute(
        update(Job)
        .where(
            Job.status == JobStatus.RUNNING,
            Job.lock_expires_at.is_not(None),
            Job.lock_expires_at < now,
        )
        .values(
            status=JobStatus.QUEUED,
            available_at=now,
            locked_by=None,
            lock_expires_at=None,
            error_code="worker_lease_expired",
        )
    )
    requeued = affected_rows(result)
    if requeued:
        logger.warning("requeued %d abandoned job(s)", requeued)
        inc("jobs_requeued", {"reason": "lease_expired"}, float(requeued))
    return requeued


async def _apply_retention(session: AsyncSession, settings: Settings) -> dict[str, int]:
    """Delete rows past their retention window."""
    now = utcnow()
    removed: dict[str, int] = {}

    result = await session.execute(
        delete(AuditEvent).where(
            AuditEvent.occurred_at < now - timedelta(days=settings.audit_retention_days)
        )
    )
    removed["audit_events"] = affected_rows(result)

    result = await session.execute(
        delete(Job).where(
            Job.status.in_(
                (JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.CANCELLED, JobStatus.TIMED_OUT)
            ),
            Job.created_at < now - timedelta(days=settings.job_retention_days),
        )
    )
    removed["jobs"] = affected_rows(result)

    result = await session.execute(
        delete(MemoryItem).where(
            MemoryItem.deleted_at.is_not(None),
            MemoryItem.deleted_at < now - timedelta(days=settings.memory_retention_days),
        )
    )
    removed["memory_items"] = affected_rows(result)

    result = await session.execute(
        delete(MailOutboxMessage).where(
            MailOutboxMessage.created_at < now - timedelta(days=_MAIL_OUTBOX_RETENTION_DAYS)
        )
    )
    removed["mail_outbox"] = affected_rows(result)

    result = await session.execute(
        delete(ImageAsset).where(ImageAsset.expires_at.is_not(None), ImageAsset.expires_at < now)
    )
    removed["image_assets"] = affected_rows(result)

    await session.flush()
    return removed


def _newest_backup_age_seconds(directory: str) -> float | None:
    """Age of the newest backup file, or ``None`` when no backup exists yet."""
    if not directory:
        return None
    pattern = os.path.join(directory, "*")
    candidates = [path for path in glob.glob(pattern) if os.path.isfile(path)]
    if not candidates:
        return None
    newest = max(os.path.getmtime(path) for path in candidates)
    return max(0.0, utcnow().timestamp() - newest)


async def _check_backup_freshness(settings: Settings) -> None:
    age = _newest_backup_age_seconds(settings.backup_dir)
    if age is None:
        set_gauge("backup_age_seconds", -1)
        return
    set_gauge("backup_age_seconds", age)
    threshold = max(_BACKUP_GRACE_SECONDS, settings.backup_age_seconds + _BACKUP_GRACE_SECONDS)
    if age > threshold:
        send_alert(
            "Database backup is stale",
            severity=AlertSeverity.CRITICAL,
            detail={"backup_dir": settings.backup_dir, "age_hours": round(age / 3600, 1)},
        )


async def run_maintenance_once(settings: Settings) -> dict[str, object]:
    """Run every maintenance task once. Individual failures never abort the pass."""
    summary: dict[str, object] = {}
    async with session_scope(settings) as session:
        with contextlib.suppress(Exception):
            summary["purged"] = await purge_expired_rows(session)
        with contextlib.suppress(Exception):
            summary["approvals_expired"] = await _expire_approvals(session)
        with contextlib.suppress(Exception):
            summary["jobs_requeued"] = await _requeue_abandoned_jobs(session, settings)
        with contextlib.suppress(Exception):
            summary["retention"] = await _apply_retention(session, settings)
    with contextlib.suppress(Exception):
        await _check_backup_freshness(settings)
    inc("maintenance_passes")
    return summary


async def maintenance_loop(settings: Settings, stop: asyncio.Event) -> None:
    """Run maintenance every five minutes until ``stop`` is set."""
    logger.info("maintenance loop started (interval=%ss)", _INTERVAL_SECONDS)
    while not stop.is_set():
        try:
            summary = await run_maintenance_once(settings)
            logger.debug("maintenance pass complete: %s", summary)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("maintenance pass failed: %s", type(exc).__name__)
        try:
            await asyncio.wait_for(stop.wait(), timeout=_INTERVAL_SECONDS)
        except TimeoutError:
            continue
    logger.info("maintenance loop stopped")


#: Extension point: other modules may add maintenance tasks at import time.
MAINTENANCE_TASKS: list[tuple[str, Callable[[AsyncSession, Settings], Awaitable[object]]]] = []
