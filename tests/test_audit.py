# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""Audit writer: canonical hashing, redaction, and queryable evidence."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import audit_event_query, count_events, record_event
from app.core.crypto import stable_hash
from app.core.enums import AuditOutcome, AuditSource
from app.core.risk import Risk
from app.db.models import User


async def test_records_the_canonical_argument_hash(db: AsyncSession, regular_user: User) -> None:
    arguments = {"b": 2, "a": {"nested": [1, 2, 3]}}
    event = await record_event(
        db,
        name="set_light",
        tool_version="1.0",
        outcome=AuditOutcome.SUCCEEDED,
        risk=Risk.LOW,
        actor_user_id=regular_user.id,
        actor_role=regular_user.role,
        arguments=arguments,
        result_summary="light on",
        trace_id="trace-abc",
    )
    assert event.arguments_hash == stable_hash(arguments)
    # Key order can never change the hash, or an approval would be invalidated by JSON
    # serialisation order alone.
    reordered = await record_event(
        db,
        name="set_light",
        outcome=AuditOutcome.SUCCEEDED,
        arguments={"a": {"nested": [1, 2, 3]}, "b": 2},
    )
    assert reordered.arguments_hash == event.arguments_hash
    assert event.trace_id == "trace-abc"
    assert event.source is AuditSource.API


async def test_credentials_in_arguments_are_redacted(db: AsyncSession) -> None:
    event = await record_event(
        db,
        name="send_mail",
        outcome=AuditOutcome.DENIED,
        risk=Risk.HIGH,
        arguments={
            "to": "someone@example.com",
            "smtp_password": "super-secret-value",
            # Credential-shaped fixtures, reviewed: they exist to prove redaction works.
            "api_key": "sk-proj-abcdefghijklmnopqrstuvwxyz123456",  # secret-scan:allow
            "nested": {  # secret-scan:allow
                "authorization": "Bearer abcdefghijklmnopqrstuvwxyz"
            },
        },
    )
    rendered = repr(event.arguments_redacted)
    assert "super-secret-value" not in rendered
    assert "sk-proj-" not in rendered
    assert "Bearer abcdefghijklmnopqrstuvwxyz" not in rendered
    assert event.arguments_redacted["to"] == "someone@example.com"
    # The hash still covers the real values, so approvals remain exact.
    assert event.arguments_hash == stable_hash(
        {
            "to": "someone@example.com",
            "smtp_password": "super-secret-value",
            # A credential-shaped fixture, reviewed: it exists to prove redaction works.
            "api_key": "sk-proj-abcdefghijklmnopqrstuvwxyz123456",  # secret-scan:allow
            "nested": {
                "authorization": "Bearer abcdefghijklmnopqrstuvwxyz"
            },  # secret-scan:allow (redaction fixture)
        }
    )


async def test_long_results_are_truncated_and_sanitised(db: AsyncSession) -> None:
    event = await record_event(
        db,
        name="web_search",
        outcome=AuditOutcome.SUCCEEDED,
        result_summary="a" * 5000 + "\x00\x07",
    )
    assert event.result_summary is not None
    assert len(event.result_summary) <= 620
    assert "\x00" not in event.result_summary


async def test_query_filters_by_actor_outcome_and_tool(
    db: AsyncSession, regular_user: User
) -> None:
    await record_event(
        db, name="set_light", outcome=AuditOutcome.SUCCEEDED, actor_user_id=regular_user.id
    )
    await record_event(
        db,
        name="web_deploy",
        outcome=AuditOutcome.DENIED,
        risk=Risk.HIGH,
        actor_user_id=regular_user.id,
        error_code="kill_switch_engaged",
    )
    await record_event(db, name="set_light", outcome=AuditOutcome.SUCCEEDED)

    statement = audit_event_query(actor_user_id=regular_user.id)
    assert await count_events(db, statement) == 2

    denied = audit_event_query(actor_user_id=regular_user.id, outcome=AuditOutcome.DENIED)
    assert await count_events(db, denied) == 1

    by_tool = audit_event_query(actor_user_id=regular_user.id, tool_name="set_light")
    assert await count_events(db, by_tool) == 1

    high_risk = audit_event_query(risk_at_least=Risk.HIGH)
    rows = (await db.execute(high_risk)).scalars().all()
    assert {row.tool_name for row in rows} == {"web_deploy"}


async def test_audit_rows_survive_a_broken_reference(db: AsyncSession, regular_user: User) -> None:
    """Deleting the actor must not erase the evidence that an action happened."""
    from sqlalchemy import select

    from app.db.models import AuditEvent

    await record_event(
        db, name="set_light", outcome=AuditOutcome.SUCCEEDED, actor_user_id=regular_user.id
    )
    await db.delete(regular_user)
    await db.commit()

    rows = (await db.execute(select(AuditEvent))).scalars().all()
    assert len(rows) == 1
    assert rows[0].actor_user_id is None
    assert rows[0].tool_name == "set_light"
    assert rows[0].arguments_hash
