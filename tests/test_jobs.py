# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""Job queue: deduplication, atomic claims, retry policy, and kill-switch enforcement."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.core.enums import AuditOutcome, JobStatus
from app.db.models import AuditEvent, Job, User
from app.jobs.queue import (
    claim_next_job,
    complete_job,
    enqueue_job,
    fail_job,
    job_handlers,
)
from app.jobs.worker import run_job_attempt
from app.security.kill_switch import KillSwitch


async def _enqueue(db: AsyncSession, settings: Settings, user: User, **overrides) -> Job:
    payload = {"task": "unit", "value": 1, **overrides.pop("payload", {})}
    return await enqueue_job(
        db,
        settings,
        kind=overrides.pop("kind", "unit_job"),
        payload=payload,
        user_id=user.id,
        **overrides,
    )


async def test_identical_enqueues_share_one_job(
    db: AsyncSession, tmp_settings, regular_user
) -> None:
    """A retried request must not enqueue a second deploy, email or workflow run."""
    first = await _enqueue(db, tmp_settings, regular_user)
    second = await _enqueue(db, tmp_settings, regular_user)
    assert first.id == second.id
    assert second.status is JobStatus.QUEUED

    differing = await _enqueue(db, tmp_settings, regular_user, payload={"value": 2})
    assert differing.id != first.id


async def test_explicit_idempotency_key_is_respected(
    db: AsyncSession, tmp_settings, regular_user
) -> None:
    first = await _enqueue(db, tmp_settings, regular_user, idempotency_key="deploy-2026-10-13")
    second = await _enqueue(db, tmp_settings, regular_user, idempotency_key="deploy-2026-10-13")
    assert first.id == second.id


async def test_claiming_is_exclusive(db: AsyncSession, tmp_settings, regular_user) -> None:
    await _enqueue(db, tmp_settings, regular_user)

    claimed = await claim_next_job(db, worker_name="worker-a", postgres=False)
    assert claimed is not None
    assert claimed.status is JobStatus.RUNNING
    assert claimed.attempts == 1
    assert claimed.locked_by == "worker-a"

    # The same job cannot be claimed twice while it is running.
    assert await claim_next_job(db, worker_name="worker-b", postgres=False) is None


async def test_completion_is_idempotent(db: AsyncSession, tmp_settings, regular_user) -> None:
    await _enqueue(db, tmp_settings, regular_user)
    job = await claim_next_job(db, worker_name="worker-a", postgres=False)
    assert job is not None
    assert await complete_job(db, job, result_payload={"ok": True}) is True
    assert await complete_job(db, job, result_payload={"ok": True}) is False

    refreshed = (await db.execute(select(Job).where(Job.id == job.id))).scalar_one()
    assert refreshed.status is JobStatus.SUCCEEDED


async def test_retryable_failures_back_off_then_give_up(
    db: AsyncSession, tmp_settings, regular_user
) -> None:
    job = await _enqueue(db, tmp_settings, regular_user, max_attempts=2)
    claimed = await claim_next_job(db, worker_name="worker-a", postgres=False)
    assert claimed is not None

    status = await fail_job(
        db, claimed, error_code="tool_timeout", error_message="timed out", retryable=True
    )
    assert status is JobStatus.QUEUED
    refreshed = (await db.execute(select(Job).where(Job.id == job.id))).scalar_one()
    assert refreshed.available_at > refreshed.created_at

    # Second attempt exhausts max_attempts and becomes terminal.
    fresh = (await db.execute(select(Job).where(Job.id == job.id))).scalar_one()
    fresh.available_at = refreshed.created_at
    await db.commit()
    claimed_again = await claim_next_job(db, worker_name="worker-a", postgres=False)
    assert claimed_again is not None and claimed_again.attempts == 2
    status = await fail_job(
        db,
        claimed_again,
        error_code="tool_timeout",
        error_message="timed out again",
        retryable=True,
    )
    assert status is JobStatus.FAILED


async def test_non_retryable_failure_never_retries(
    db: AsyncSession, tmp_settings, regular_user
) -> None:
    await _enqueue(db, tmp_settings, regular_user, max_attempts=5)
    job = await claim_next_job(db, worker_name="worker-a", postgres=False)
    assert job is not None
    status = await fail_job(
        db, job, error_code="destination_not_allowed", error_message="not allowed", retryable=False
    )
    assert status is JobStatus.FAILED


async def test_worker_executes_a_registered_handler(
    db: AsyncSession, tmp_settings, regular_user, monkeypatch
) -> None:
    calls: list[str] = []

    async def handler(job: Job, ctx) -> dict[str, str]:
        calls.append(job.kind)
        assert ctx.actor_id == regular_user.id
        return {"summary": "done"}

    monkeypatch.setitem(job_handlers(), "unit_job", handler)
    await _enqueue(db, tmp_settings, regular_user)
    job = await claim_next_job(db, worker_name="worker-a", postgres=False)
    assert job is not None

    status = await run_job_attempt(tmp_settings, job, {"unit_job": handler})
    assert status is JobStatus.SUCCEEDED
    assert calls == ["unit_job"]

    events = (
        (await db.execute(select(AuditEvent).where(AuditEvent.tool_name == "unit_job")))
        .scalars()
        .all()
    )
    await db.commit()
    assert [event.outcome for event in events] == [AuditOutcome.SUCCEEDED]


async def test_kill_switch_stops_a_queued_job_before_the_handler_runs(
    db: AsyncSession, tmp_settings, regular_user, monkeypatch
) -> None:
    """The kill-switch must stop integration work, not just new user requests."""
    calls: list[str] = []

    async def handler(job: Job, ctx) -> dict[str, str]:
        calls.append(job.kind)
        return {}

    monkeypatch.setitem(job_handlers(), "unit_job", handler)
    await _enqueue(db, tmp_settings, regular_user)
    job = await claim_next_job(db, worker_name="worker-a", postgres=False)
    assert job is not None

    switch = KillSwitch(tmp_settings)
    await switch.engage(db, actor_user_id=regular_user.id, reason="security drill")
    await db.commit()

    status = await run_job_attempt(tmp_settings, job, {"unit_job": handler})
    assert status is JobStatus.FAILED
    assert calls == []  # the handler never ran

    events = (
        (await db.execute(select(AuditEvent).where(AuditEvent.tool_name == "unit_job")))
        .scalars()
        .all()
    )
    assert [event.outcome for event in events] == [AuditOutcome.DENIED]
    assert events[0].error_code == "kill_switch_engaged"

    # Release and confirm the switch reports its state.
    await switch.disengage(db, actor_user_id=regular_user.id, reason="drill complete")
    await db.commit()
    assert await switch.is_engaged(db) is False


async def test_unknown_job_kind_fails_and_is_audited(
    db: AsyncSession, tmp_settings, regular_user
) -> None:
    await _enqueue(db, tmp_settings, regular_user, kind="never_registered")
    job = await claim_next_job(db, worker_name="worker-a", postgres=False)
    assert job is not None
    status = await run_job_attempt(tmp_settings, job, {})
    assert status is JobStatus.FAILED
    events = (
        (await db.execute(select(AuditEvent).where(AuditEvent.tool_name == "never_registered")))
        .scalars()
        .all()
    )
    assert events and events[0].error_code == "tool_unknown"


@pytest.mark.parametrize("concurrency", [1, 4])
async def test_many_queued_jobs_are_claimed_at_most_once(
    db: AsyncSession, tmp_settings, regular_user, concurrency: int
) -> None:
    for index in range(concurrency):
        await _enqueue(db, tmp_settings, regular_user, payload={"value": index})

    claimed_ids: set[object] = set()
    for _ in range(concurrency):
        job = await claim_next_job(db, worker_name="worker-a", postgres=False)
        assert job is not None
        assert job.id not in claimed_ids
        claimed_ids.add(job.id)
    assert len(claimed_ids) == concurrency
    assert await claim_next_job(db, worker_name="worker-a", postgres=False) is None
