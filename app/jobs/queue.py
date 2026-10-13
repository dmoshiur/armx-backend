# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Job queue built on the primary database.

Why not Celery/RQ: the deployment runs on Supabase with no Redis, and a broker would add a
second source of truth for "was this side effect attempted". PostgreSQL already gives us
atomic claims (``SKIP LOCKED``), and a job row is auditable.

The claim/complete/fail transitions are all conditional updates, so two workers cannot run
the same job and a double-completion is a no-op rather than a duplicate side effect.
"""

from __future__ import annotations

import importlib
import pkgutil
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Final

from sqlalchemy import Select, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.core.crypto import stable_hash
from app.core.enums import AuditOutcome, AuditSource, JobStatus
from app.core.errors import ErrorCode
from app.core.logging import get_logger
from app.core.metrics import inc, observe
from app.core.risk import Risk
from app.core.time import utcnow
from app.db.models import Job
from app.db.sql import affected_rows
from app.registry.core import ToolContext

__all__ = [
    "JobHandler",
    "claim_next_job",
    "complete_job",
    "enqueue_job",
    "fail_job",
    "job_handler",
    "job_handlers",
    "load_job_handlers",
    "request_cancel",
]

logger = get_logger("jobs")

#: A claimed job that has not been touched for this long is considered abandoned.
_CLAIM_LEASE_SECONDS: Final = 120

#: Retry backoff: attempt 1 -> 5s, 2 -> 10s, 3 -> 20s (capped at 5 minutes).
_BACKOFF_BASE_SECONDS: Final = 5
_BACKOFF_MAX_SECONDS: Final = 300

JobHandler = Callable[[Job, ToolContext], Awaitable[dict[str, Any] | None]]

_HANDLERS: dict[str, JobHandler] = {}
_HANDLERS_LOADED = False


@dataclass(frozen=True, slots=True)
class _HandlerRegistration:
    kind: str
    handler: JobHandler


def job_handler(kind: str) -> Callable[[JobHandler], JobHandler]:
    """Register the coroutine that executes one job ``kind``."""

    def decorator(handler: JobHandler) -> JobHandler:
        if kind in _HANDLERS:
            raise ValueError(f"duplicate job handler for kind {kind!r}")
        _HANDLERS[kind] = handler
        return handler

    return decorator


def job_handlers() -> dict[str, JobHandler]:
    return dict(_HANDLERS)


def load_job_handlers() -> dict[str, JobHandler]:
    """Import every module under :mod:`app.jobs.handlers` (first-party only)."""
    global _HANDLERS_LOADED
    if _HANDLERS_LOADED:
        return dict(_HANDLERS)
    try:
        package = importlib.import_module("app.jobs.handlers")
    except ModuleNotFoundError:  # pragma: no cover - handlers always ship together
        logger.warning("no job handler package found; the worker will idle")
        _HANDLERS_LOADED = True
        return {}
    for module_info in pkgutil.iter_modules(package.__path__):
        if module_info.name.startswith("_"):
            continue
        importlib.import_module(f"app.jobs.handlers.{module_info.name}")
    _HANDLERS_LOADED = True
    logger.info("job handlers loaded: %s", ", ".join(sorted(_HANDLERS)) or "(none)")
    return dict(_HANDLERS)


def _derive_idempotency_key(
    *, kind: str, payload: dict[str, Any], explicit: str | None, user_id: uuid.UUID | None
) -> str | None:
    """
    A write-style job always gets an idempotency key.

    Two identical requests therefore share one job row instead of producing two deploys, two
    emails or two n8n invocations - the usual way a retry turns into a duplicate side effect.
    """
    if explicit:
        return explicit[:80]
    if user_id is None:
        return None
    digest = stable_hash({"kind": kind, "payload": payload, "user": str(user_id)})
    return f"{kind}:{digest[:40]}"


async def enqueue_job(
    session: AsyncSession,
    settings: Settings,
    *,
    kind: str,
    payload: dict[str, Any],
    user_id: uuid.UUID | None = None,
    session_id: uuid.UUID | None = None,
    trace_id: str | None = None,
    tool_name: str | None = None,
    risk: Risk | None = None,
    approval_id: uuid.UUID | None = None,
    idempotency_key: str | None = None,
    timeout_seconds: int | None = None,
    max_attempts: int | None = None,
    delay_seconds: int = 0,
) -> Job:
    """
    Persist a job and return it.

    Re-submitting an identical job (same kind, payload and actor) returns the existing row
    while it is still queued or running, so at-most-once side effects hold across retries.
    """
    key = _derive_idempotency_key(
        kind=kind, payload=payload, explicit=idempotency_key, user_id=user_id
    )
    if key is not None:
        existing = (
            await session.execute(
                select(Job).where(
                    Job.idempotency_key == key,
                    Job.status.in_((JobStatus.QUEUED, JobStatus.RUNNING)),
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            logger.info("job %s reuses in-flight job %s for kind=%s", key, existing.id, kind)
            inc("job_deduplicated", {"kind": kind})
            return existing

    now = utcnow()
    job = Job(
        kind=kind,
        status=JobStatus.QUEUED,
        tool_name=tool_name,
        risk=risk,
        payload=payload,
        attempts=0,
        max_attempts=max_attempts or settings.job_max_attempts,
        timeout_seconds=timeout_seconds or settings.job_timeout_seconds,
        idempotency_key=key,
        user_id=user_id,
        session_id=session_id,
        trace_id=trace_id,
        approval_id=approval_id,
        created_at=now,
        available_at=now + timedelta(seconds=max(0, delay_seconds)),
    )
    session.add(job)
    await session.flush()
    inc("jobs_enqueued", {"kind": kind})
    return job


def claimable_jobs_query() -> Select[Job]:
    """Jobs that are queued, due, and whose previous claim (if any) has expired."""
    now = utcnow()
    return (
        select(Job)
        .where(
            Job.status == JobStatus.QUEUED,
            Job.available_at <= now,
        )
        .order_by(Job.available_at.asc(), Job.created_at.asc())
        .limit(1)
    )


async def claim_next_job(session: AsyncSession, *, worker_name: str, postgres: bool) -> Job | None:
    """
    Atomically claim the next due job.

    On PostgreSQL the row is selected ``FOR UPDATE SKIP LOCKED`` and the status update happens
    in the same transaction, which is what makes concurrent workers safe. SQLite (local
    development only) serialises writers anyway, so the conditional update alone is enough.
    """
    statement = claimable_jobs_query()
    if postgres:
        statement = statement.with_for_update(skip_locked=True)
    job = (await session.execute(statement)).scalars().one_or_none()
    if job is None:
        return None

    now = utcnow()
    result = await session.execute(
        update(Job)
        .where(Job.id == job.id, Job.status == JobStatus.QUEUED)
        .values(
            status=JobStatus.RUNNING,
            started_at=now,
            locked_by=worker_name,
            lock_expires_at=now + timedelta(seconds=_CLAIM_LEASE_SECONDS),
            attempts=Job.attempts + 1,
        )
    )
    if not affected_rows(result):
        # Someone else won the race; the caller retries on the next poll.
        await session.rollback()
        return None
    await session.commit()
    await session.refresh(job)
    inc("jobs_claimed", {"kind": job.kind})
    return job


async def complete_job(
    session: AsyncSession,
    job: Job,
    *,
    result_payload: dict[str, Any] | None = None,
) -> bool:
    """Mark a job succeeded. Returns ``False`` when it was already finished."""
    outcome = await session.execute(
        update(Job)
        .where(Job.id == job.id, Job.status == JobStatus.RUNNING)
        .values(
            status=JobStatus.SUCCEEDED,
            result=result_payload or {},
            finished_at=utcnow(),
            locked_by=None,
            lock_expires_at=None,
        )
    )
    await session.commit()
    if not affected_rows(outcome):
        logger.warning("job %s was already finished; ignoring duplicate completion", job.id)
        return False
    inc("jobs_finished", {"kind": job.kind, "status": "succeeded"})
    return True


async def fail_job(
    session: AsyncSession,
    job: Job,
    *,
    error_code: str,
    error_message: str,
    retryable: bool = False,
    timed_out: bool = False,
) -> JobStatus:
    """
    Record a failure, retrying with backoff while attempts remain.

    A non-retryable failure never retries: repeating an uncertain write is how a system
    sends the same email twice.
    """
    exhausted = job.attempts >= job.max_attempts
    if retryable and not exhausted:
        delay = min(_BACKOFF_BASE_SECONDS * (2 ** max(0, job.attempts - 1)), _BACKOFF_MAX_SECONDS)
        await session.execute(
            update(Job)
            .where(Job.id == job.id)
            .values(
                status=JobStatus.QUEUED,
                error_code=error_code,
                error_message=error_message[:400],
                available_at=utcnow() + timedelta(seconds=delay),
                locked_by=None,
                lock_expires_at=None,
            )
        )
        await session.commit()
        inc("jobs_retried", {"kind": job.kind})
        logger.warning(
            "job %s (%s) failed, retrying in %ss: %s", job.id, job.kind, delay, error_code
        )
        return JobStatus.QUEUED

    final = JobStatus.TIMED_OUT if timed_out else JobStatus.FAILED
    await session.execute(
        update(Job)
        .where(Job.id == job.id)
        .values(
            status=final,
            error_code=error_code,
            error_message=error_message[:400],
            finished_at=utcnow(),
            locked_by=None,
            lock_expires_at=None,
        )
    )
    await session.commit()
    inc("jobs_finished", {"kind": job.kind, "status": final.value})
    logger.error("job %s (%s) failed permanently: %s", job.id, job.kind, error_code)
    return final


async def request_cancel(session: AsyncSession, job_id: uuid.UUID) -> bool:
    """Cancel a queued job (a running job is cancelled cooperatively by the worker)."""
    result = await session.execute(
        update(Job)
        .where(Job.id == job_id, Job.status == JobStatus.QUEUED)
        .values(status=JobStatus.CANCELLED, finished_at=utcnow())
    )
    await session.commit()
    return bool(affected_rows(result))


def audit_outcome_for(status: JobStatus) -> AuditOutcome:
    """Map a terminal job status to the audit outcome written for it."""
    if status is JobStatus.SUCCEEDED:
        return AuditOutcome.SUCCEEDED
    if status is JobStatus.CANCELLED:
        return AuditOutcome.CANCELLED
    if status is JobStatus.TIMED_OUT:
        return AuditOutcome.FAILED
    return AuditOutcome.FAILED


def job_error_code(status: JobStatus) -> str:
    return ErrorCode.TOOL_TIMEOUT if status is JobStatus.TIMED_OUT else ErrorCode.TOOL_FAILED


def source_for_worker() -> AuditSource:
    return AuditSource.WORKER


def note_duration(job: Job) -> None:
    if job.started_at and job.finished_at:
        observe(
            "job_duration", (job.finished_at - job.started_at).total_seconds(), {"kind": job.kind}
        )
