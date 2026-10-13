# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
PostgreSQL-specific tests (CI job ``test-postgres``).

The main suite runs on SQLite for speed and isolation; these tests exist because production runs
on Supabase PostgreSQL and three things genuinely differ: JSONB, ``timestamp with time zone``,
and ``SELECT ... FOR UPDATE SKIP LOCKED`` (the guarantee behind at-most-once job execution).

Skipped automatically when ``DATABASE_URL`` is not PostgreSQL, so a local run stays green.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import inspect, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import Settings
from app.core.enums import JobStatus, Role
from app.core.risk import Risk
from app.core.time import utcnow
from app.db.models import AuditEvent, Job, ToolDefinition, User
from app.db.session import create_engine_for, dispose_engines
from app.jobs.queue import claim_next_job, enqueue_job

pytestmark = pytest.mark.skipif(
    Settings().uses_sqlite is not False,
    reason="requires DATABASE_URL pointing at PostgreSQL",
)


@pytest.fixture
def pg_settings() -> Settings:
    configured = Settings()
    if configured.uses_sqlite:
        pytest.skip("DATABASE_URL is not PostgreSQL")
    return configured


@pytest.fixture
async def pg_session(pg_settings: Settings):
    engine = create_engine_for(pg_settings)
    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session
        await session.rollback()
    await engine.dispose()
    await dispose_engines()


async def test_migration_created_every_table(pg_settings: Settings) -> None:
    engine = create_engine_for(pg_settings)
    try:
        async with engine.connect() as connection:
            tables = await connection.run_sync(
                lambda sync_conn: set(inspect(sync_conn).get_table_names())
            )
    finally:
        await engine.dispose()
        await dispose_engines()
    assert {"users", "sessions", "audit_events", "approvals", "linked_devices", "jobs"} <= tables


async def test_enum_columns_round_trip_as_values(pg_session: AsyncSession) -> None:
    user = User(
        email=f"pg-{uuid.uuid4().hex[:8]}@example.com",
        display_name="PG",
        role=Role.VIP,
        password_hash="x",
        email_verified_at=utcnow(),
    )
    pg_session.add(user)
    await pg_session.flush()
    raw = (
        await pg_session.execute(
            text("SELECT role FROM users WHERE id = :id"), {"id": str(user.id)}
        )
    ).scalar()
    assert raw == "vip"
    assert user.role is Role.VIP


async def test_jsonb_columns_are_queryable(pg_session: AsyncSession) -> None:
    pg_session.add(
        ToolDefinition(
            name=f"pg_tool_{uuid.uuid4().hex[:6]}",
            version="1.0",
            description="jsonb round trip",
            risk=Risk.LOW,
            enabled=True,
            default_enabled=True,
            required_scopes=["x"],
            confirm_required=False,
            rate_limit="1/minute",
            dry_run_supported=False,
            input_schema={"type": "object"},
            output_schema={"type": "object"},
            registered_at=utcnow(),
            updated_at=utcnow(),
        )
    )
    await pg_session.flush()
    event = AuditEvent(
        occurred_at=utcnow(),
        tool_name="jsonb_check",
        risk=Risk.LOW,
        arguments_hash="0" * 64,
        arguments_redacted={"nested": {"value": 42}},
        outcome="succeeded",
    )
    pg_session.add(event)
    await pg_session.flush()
    found = (
        (
            await pg_session.execute(
                select(AuditEvent).where(
                    AuditEvent.arguments_redacted["nested"]["value"].as_integer() == 42
                )
            )
        )
        .scalars()
        .all()
    )
    assert found, "JSONB containment query returned nothing"


async def test_timestamptz_round_trips_as_aware_utc(pg_session: AsyncSession) -> None:
    user = User(
        email=f"pg-tz-{uuid.uuid4().hex[:8]}@example.com",
        display_name="TZ",
        role=Role.USER,
        password_hash="x",
    )
    pg_session.add(user)
    await pg_session.flush()
    await pg_session.refresh(user)
    assert user.created_at.tzinfo is not None
    assert user.created_at.utcoffset() is not None


async def test_skip_locked_claim_is_at_most_once(pg_settings: Settings) -> None:
    """Two concurrent claimers must never receive the same job."""
    engine = create_engine_for(pg_settings)
    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with factory() as setup:
            user = User(
                email=f"pg-job-{uuid.uuid4().hex[:8]}@example.com",
                display_name="Jobs",
                role=Role.USER,
                password_hash="x",
            )
            setup.add(user)
            await setup.flush()
            for index in range(2):
                await enqueue_job(
                    setup, pg_settings, kind="pg_claim", payload={"i": index}, user_id=user.id
                )
            await setup.commit()

        async def claim(worker: str) -> uuid.UUID | None:
            async with factory() as session:
                job = await claim_next_job(session, worker_name=worker, postgres=True)
                return job.id if job else None

        first, second = await _gather(claim("w1"), claim("w2"))
        claimed = {job for job in (first, second) if job is not None}
        assert len(claimed) == 2, "both concurrent claimers must receive distinct jobs"
    finally:
        async with factory() as cleanup:
            await cleanup.execute(Job.__table__.delete().where(Job.kind == "pg_claim"))
            await cleanup.commit()
        await engine.dispose()
        await dispose_engines()


async def test_job_status_enum_is_stored_as_text(pg_settings: Settings) -> None:
    engine = create_engine_for(pg_settings)
    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with factory() as session:
            user = User(
                email=f"pg-enum-{uuid.uuid4().hex[:8]}@example.com",
                display_name="Enum",
                role=Role.USER,
                password_hash="x",
            )
            session.add(user)
            await session.flush()
            job = await enqueue_job(
                session, pg_settings, kind="pg_enum", payload={}, user_id=user.id
            )
            await session.commit()
            raw = (
                await session.execute(
                    text("SELECT status FROM jobs WHERE id = :id"), {"id": str(job.id)}
                )
            ).scalar()
            assert raw == JobStatus.QUEUED.value
            await session.execute(Job.__table__.delete().where(Job.id == job.id))
            await session.commit()
    finally:
        await engine.dispose()
        await dispose_engines()


async def _gather(*coroutines):  # type: ignore[no-untyped-def]
    import asyncio

    return await asyncio.gather(*coroutines)
