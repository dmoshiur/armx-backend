# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Worker loop.

Runs either in the dedicated ``worker`` container (``WORKER_IN_API=false``) or inside the API
process for local development. Either way the loop:

* refuses to start a job while the kill-switch is engaged, so slow integration calls stop
  immediately rather than draining a backlog of deploys and messages,
* enforces a per-job timeout, because a hung HTTP call must not hold a worker forever,
* writes exactly one audit row per attempt,
* never retries a non-retryable failure - an uncertain write is reported, not repeated.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from typing import Any

from app.audit.service import record_event
from app.config import Settings
from app.core.alerts import AlertSeverity, send_alert
from app.core.enums import AuditOutcome, AuditSource, JobStatus
from app.core.errors import ErrorCode
from app.core.logging import bind_trace_context, get_logger
from app.core.metrics import observe
from app.core.time import utcnow
from app.db.models import Job
from app.db.session import session_scope
from app.db.urls import is_postgres
from app.jobs.queue import (
    JobHandler,
    claim_next_job,
    complete_job,
    fail_job,
    load_job_handlers,
    note_duration,
)
from app.registry.core import ToolContext, ToolInvocationError
from app.security.kill_switch import KillSwitch

__all__ = ["run_job_attempt", "worker_loop"]

logger = get_logger("jobs.worker")

#: Ceiling on any single job, regardless of what the job row asks for.
_MAX_JOB_SECONDS = 3600


async def _wait_for_stop(stop: asyncio.Event, seconds: float) -> None:
    with contextlib.suppress(asyncio.TimeoutError):
        await asyncio.wait_for(stop.wait(), timeout=seconds)


def _context_for(job: Job, settings: Settings) -> ToolContext:
    return ToolContext(
        settings=settings,
        actor_id=job.user_id,
        session_id=job.session_id,
        trace_id=job.trace_id or f"job-{job.id.hex[:12]}",
        approval_id=job.approval_id,
        idempotency_key=job.idempotency_key,
    )


async def run_job_attempt(
    settings: Settings, job: Job, handlers: dict[str, JobHandler]
) -> JobStatus:
    """
    Execute one claimed job attempt in its own session and write its audit row.

    Job handlers are trusted first-party code (never model-authored), so they receive the
    same :class:`ToolContext` a tool would, minus any client-controlled field.
    """
    handler = handlers.get(job.kind)
    bind_trace_context(trace_id=job.trace_id, actor_id=str(job.user_id or ""))
    async with session_scope(settings) as session:
        if handler is None:
            status = await fail_job(
                session,
                job,
                error_code=ErrorCode.TOOL_UNKNOWN,
                error_message=f"no handler registered for job kind {job.kind!r}",
                retryable=False,
            )
            await record_event(
                session,
                name=job.tool_name or job.kind,
                tool_version="",
                outcome=AuditOutcome.FAILED,
                risk=job.risk,
                actor_user_id=job.user_id,
                session_id=job.session_id,
                arguments=job.payload,
                error_code=ErrorCode.TOOL_UNKNOWN,
                result_summary="no handler registered for this job kind",
                trace_id=job.trace_id,
                source=AuditSource.WORKER,
                idempotency_key=job.idempotency_key,
            )
            return status

        kill_switch = KillSwitch(settings)
        if await kill_switch.is_engaged(session):
            # Fail without retrying: the action never started, and the operator must
            # explicitly release the kill-switch before anything runs again.
            status = await fail_job(
                session,
                job,
                error_code=ErrorCode.KILL_SWITCH_ENGAGED,
                error_message="kill switch engaged before the job started",
                retryable=False,
            )
            await record_event(
                session,
                name=job.tool_name or job.kind,
                outcome=AuditOutcome.DENIED,
                risk=job.risk,
                actor_user_id=job.user_id,
                session_id=job.session_id,
                arguments=job.payload,
                error_code=ErrorCode.KILL_SWITCH_ENGAGED,
                result_summary="kill switch engaged; job not started",
                trace_id=job.trace_id,
                source=AuditSource.WORKER,
                idempotency_key=job.idempotency_key,
            )
            return status

    started = utcnow()
    context = _context_for(job, settings)
    timeout = min(job.timeout_seconds or settings.job_timeout_seconds, _MAX_JOB_SECONDS)
    try:
        result = await asyncio.wait_for(handler(job, context), timeout=timeout)
        outcome = AuditOutcome.SUCCEEDED
        error_code: str | None = None
        summary = _result_summary(result)
    except TimeoutError:
        outcome = AuditOutcome.FAILED
        error_code = ErrorCode.TOOL_TIMEOUT
        summary = f"job exceeded its {timeout}s timeout"
        result = None
    except ToolInvocationError as exc:
        outcome = AuditOutcome.FAILED
        error_code = exc.code
        summary = exc.message
        result = None
    except asyncio.CancelledError:
        # Shutdown: leave the job claim to expire so another worker retries it.
        logger.info("job %s cancelled during shutdown", job.id)
        raise
    except Exception as exc:
        outcome = AuditOutcome.FAILED
        error_code = ErrorCode.TOOL_FAILED
        summary = f"{type(exc).__name__} in job handler"
        result = None
        logger.error("job %s raised %s", job.id, type(exc).__name__)

    duration_ms = int((utcnow() - started).total_seconds() * 1000)
    observe("job_handler_duration", duration_ms / 1000, {"kind": job.kind})

    async with session_scope(settings) as session:
        if outcome is AuditOutcome.SUCCEEDED:
            await complete_job(session, job, result_payload=result or {})
            final_status = JobStatus.SUCCEEDED
        else:
            final_status = await fail_job(
                session,
                job,
                error_code=error_code or ErrorCode.TOOL_FAILED,
                error_message=summary,
                retryable=False,
                timed_out=error_code == ErrorCode.TOOL_TIMEOUT,
            )
        await record_event(
            session,
            name=job.tool_name or job.kind,
            outcome=outcome,
            risk=job.risk,
            actor_user_id=job.user_id,
            session_id=job.session_id,
            arguments=job.payload,
            error_code=error_code,
            result_summary=summary,
            duration_ms=duration_ms,
            trace_id=job.trace_id,
            approval_id=job.approval_id,
            idempotency_key=job.idempotency_key,
            source=AuditSource.WORKER,
        )
        if final_status is JobStatus.FAILED:
            send_alert(
                f"Job failed permanently: {job.kind}",
                severity=AlertSeverity.CRITICAL,
                detail={"job_id": str(job.id), "error_code": error_code, "kind": job.kind},
            )
    note_duration(job)
    return final_status


def _result_summary(result: dict[str, Any] | None) -> str:
    if not result:
        return "job completed"
    for key in ("summary", "message", "status"):
        value = result.get(key)
        if isinstance(value, str) and value:
            return value[:400]
    return "job completed"


async def worker_loop(settings: Settings, stop: asyncio.Event, *, worker_name: str) -> None:
    """Poll, claim and execute jobs until ``stop`` is set."""
    handlers = load_job_handlers()
    postgres = is_postgres(settings.database_url)
    if not handlers:
        logger.warning("worker %s has no handlers and will idle", worker_name)
    logger.info(
        "worker %s started (handlers=%d, dialect=%s)",
        worker_name,
        len(handlers),
        "postgresql" if postgres else "sqlite",
    )

    while not stop.is_set():
        job: Job | None = None
        try:
            async with session_scope(settings) as session:
                job = await claim_next_job(session, worker_name=worker_name, postgres=postgres)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("worker %s could not claim a job: %s", worker_name, type(exc).__name__)
            await _wait_for_stop(stop, min(30.0, settings.worker_poll_interval_seconds * 5))
            continue

        if job is None:
            await _wait_for_stop(stop, settings.worker_poll_interval_seconds)
            continue

        try:
            await run_job_attempt(settings, job, handlers)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("worker %s job %s crashed: %s", worker_name, job.id, type(exc).__name__)

    logger.info("worker %s stopped", worker_name)


def build_worker_id() -> str:
    """Unique worker identifier recorded on claimed jobs."""
    return f"worker-{uuid.uuid4().hex[:8]}"
