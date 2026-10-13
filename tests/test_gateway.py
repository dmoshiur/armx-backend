# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Security Gateway tests.

These are the tests that matter most in this codebase: they pin the properties that make the
"the LLM is an untrusted planner" claim true rather than aspirational. Each one asserts on the
gateway's verdict *and* on the database side effect (audit row, approval row, whether the handler
ran at all).
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.core.enums import ApprovalStatus, AuditOutcome, AuditSource, PermissionSubject, Role
from app.core.risk import Risk
from app.core.time import utcnow
from app.db.models import Approval, AuditEvent, ToolDefinition, ToolPermission
from app.security.gateway import ActorRef, SecurityGateway
from tests.factories import Spy, make_actor, make_device, make_registry, make_spec

ALL_SCOPES = frozenset({"tools:basic", "tools:advanced", "tools:all", "smart_home:write"})


async def _actor(
    db: AsyncSession, *, scopes: frozenset[str] = ALL_SCOPES, email: str | None = None
) -> ActorRef:
    """An administrator-shaped actor backed by a real account (audit rows carry a foreign key)."""
    return await make_actor(db, role=Role.ADMIN, scopes=scopes, email=email)


async def _device_id(db: AsyncSession) -> uuid.UUID:
    """A registered device, so device-scoped audit rows and approvals stay referential."""
    return (await make_device(db)).id


async def _audit_rows(db: AsyncSession, name: str) -> list[AuditEvent]:
    return list(
        (
            await db.execute(
                select(AuditEvent)
                .where(AuditEvent.tool_name == name)
                .order_by(AuditEvent.occurred_at)
            )
        )
        .scalars()
        .all()
    )


class TestAuthorization:
    async def test_low_risk_tool_runs_and_is_audited(
        self, db: AsyncSession, tmp_settings: Settings
    ) -> None:
        spy = Spy()
        registry = make_registry(tmp_settings, make_spec(name="probe_low", spy=spy))
        gateway = SecurityGateway(tmp_settings, registry)
        actor = await _actor(db)

        outcome = await gateway.invoke(
            db, tool_name="probe_low", arguments={"value": "hello"}, actor=actor, registry=registry
        )
        assert outcome.status == "succeeded"
        assert outcome.result is not None and outcome.result.data["echo"] == "hello"
        assert spy.names == ["probe_low"]

        rows = await _audit_rows(db, "probe_low")
        assert len(rows) == 1
        event = rows[0]
        assert event.outcome is AuditOutcome.SUCCEEDED
        assert event.actor_user_id == actor.user_id
        assert event.risk is Risk.LOW
        assert event.arguments_redacted == {"value": "hello", "count": 1}
        assert event.arguments_hash and len(event.arguments_hash) == 64
        assert event.occurred_at is not None

    async def test_unknown_tool_is_refused_and_audited(
        self, db: AsyncSession, tmp_settings: Settings
    ) -> None:
        spy = Spy()
        registry = make_registry(tmp_settings, make_spec(name="probe_low", spy=spy))
        gateway = SecurityGateway(tmp_settings, registry)

        outcome = await gateway.invoke(
            db,
            tool_name="shell",
            arguments={"cmd": "rm -rf /"},
            actor=await _actor(db),
            registry=registry,
        )
        assert outcome.status == "denied"
        assert outcome.error_code == "tool_unknown"
        assert spy.calls == []

        rows = await _audit_rows(db, "shell")
        assert len(rows) == 1
        assert rows[0].outcome is AuditOutcome.DENIED
        assert rows[0].error_code == "tool_unknown"

    async def test_disabled_tool_is_refused_even_though_it_exists(
        self, db: AsyncSession, tmp_settings: Settings
    ) -> None:
        spy = Spy()
        registry = make_registry(tmp_settings, make_spec(name="probe_off", spy=spy))
        db.add(
            ToolDefinition(
                name="probe_off",
                version="1.0.0",
                description="probe",
                risk=Risk.LOW,
                enabled=False,
                default_enabled=True,
                required_scopes=[],
                confirm_required=False,
                rate_limit="60/hour",
                dry_run_supported=False,
                input_schema={},
                output_schema={},
                registered_at=utcnow(),
                updated_at=utcnow(),
            )
        )
        await db.commit()

        outcome = await SecurityGateway(tmp_settings, registry).invoke(
            db, tool_name="probe_off", arguments={}, actor=await _actor(db), registry=registry
        )
        assert outcome.status == "denied"
        assert outcome.error_code == "tool_disabled"
        assert spy.calls == []

    async def test_missing_scope_is_refused(self, db: AsyncSession, tmp_settings: Settings) -> None:
        spy = Spy()
        registry = make_registry(
            tmp_settings,
            make_spec(name="probe_scoped", required_scopes=("smart_home:write",), spy=spy),
        )
        gateway = SecurityGateway(tmp_settings, registry)

        denied = await gateway.invoke(
            db,
            tool_name="probe_scoped",
            arguments={},
            actor=await _actor(db, scopes=frozenset({"tools:basic"})),
            registry=registry,
        )
        assert denied.status == "denied"
        assert denied.error_code == "scope_required"
        assert spy.calls == []

        allowed = await gateway.invoke(
            db, tool_name="probe_scoped", arguments={}, actor=await _actor(db), registry=registry
        )
        assert allowed.status == "succeeded"
        assert spy.names == ["probe_scoped"]

    async def test_global_permission_override_denies(
        self, db: AsyncSession, tmp_settings: Settings
    ) -> None:
        spy = Spy()
        registry = make_registry(tmp_settings, make_spec(name="probe_blocked", spy=spy))
        db.add(
            ToolPermission(
                tool_name="probe_blocked",
                subject_type=PermissionSubject.GLOBAL,
                subject_id="",
                allowed=False,
                created_at=utcnow(),
                updated_at=utcnow(),
            )
        )
        await db.commit()

        outcome = await SecurityGateway(tmp_settings, registry).invoke(
            db, tool_name="probe_blocked", arguments={}, actor=await _actor(db), registry=registry
        )
        assert outcome.status == "denied"
        assert outcome.error_code == "forbidden"
        assert spy.calls == []

    async def test_per_user_override_beats_the_role_then_global(
        self, db: AsyncSession, tmp_settings: Settings
    ) -> None:
        actor = await _actor(db)
        spy = Spy()
        registry = make_registry(tmp_settings, make_spec(name="probe_matrix", spy=spy))
        now = utcnow()
        for subject_type, subject_id, allowed in (
            (PermissionSubject.GLOBAL, "", False),
            (PermissionSubject.ROLE, "admin", False),
            (PermissionSubject.USER, str(actor.user_id), True),
        ):
            db.add(
                ToolPermission(
                    tool_name="probe_matrix",
                    subject_type=subject_type,
                    subject_id=subject_id,
                    allowed=allowed,
                    created_at=now,
                    updated_at=now,
                )
            )
        await db.commit()

        outcome = await SecurityGateway(tmp_settings, registry).invoke(
            db, tool_name="probe_matrix", arguments={}, actor=actor, registry=registry
        )
        assert outcome.status == "succeeded", outcome.error_code or "the user exception must win"
        assert spy.names == ["probe_matrix"]

    async def test_arguments_are_validated_before_the_handler_runs(
        self, db: AsyncSession, tmp_settings: Settings
    ) -> None:
        spy = Spy()
        registry = make_registry(tmp_settings, make_spec(name="probe_args", spy=spy))
        outcome = await SecurityGateway(tmp_settings, registry).invoke(
            db,
            tool_name="probe_args",
            arguments={"count": "not-a-number", "unexpected": True},
            actor=await _actor(db),
            registry=registry,
        )
        assert outcome.status == "denied"
        assert outcome.error_code == "tool_argument_invalid"
        assert spy.calls == []


class TestKillSwitch:
    async def test_engaged_kill_switch_stops_action_tools_but_not_health_checks(
        self, db: AsyncSession, tmp_settings: Settings
    ) -> None:
        from app.security.kill_switch import KillSwitch

        spy = Spy()
        registry = make_registry(
            tmp_settings, make_spec(name="probe_action", spy=spy)
        )  # health_status ships with the app
        gateway = SecurityGateway(tmp_settings, registry)
        actor = await _actor(db)

        await KillSwitch(tmp_settings).engage(db, actor_user_id=actor.user_id, reason="test")
        await db.commit()

        blocked = await gateway.invoke(
            db, tool_name="probe_action", arguments={}, actor=actor, registry=registry
        )
        assert blocked.status == "denied"
        assert blocked.error_code == "kill_switch_engaged"
        assert spy.calls == []

        allowed = await gateway.invoke(
            db, tool_name="health_status", arguments={}, actor=actor, registry=registry
        )
        assert allowed.status == "succeeded", "a health check is always allowed"
        assert spy.calls == [], "only the kill-switch allowlist may still run"

        rows = await _audit_rows(db, "probe_action")
        assert rows[-1].error_code == "kill_switch_engaged"


class TestRateLimiting:
    async def test_tool_limit_is_enforced_per_actor_and_device(
        self, db: AsyncSession, tmp_settings: Settings
    ) -> None:
        spy = Spy()
        registry = make_registry(
            tmp_settings, make_spec(name="probe_limited", rate_limit="2/minute", spy=spy)
        )
        gateway = SecurityGateway(tmp_settings, registry)
        actor = await _actor(db)
        device = await _device_id(db)

        results = [
            await gateway.invoke(
                db,
                tool_name="probe_limited",
                arguments={"count": index},
                actor=actor,
                device_id=device,
                registry=registry,
            )
            for index in range(3)
        ]
        assert [outcome.status for outcome in results] == ["succeeded", "succeeded", "denied"]
        assert results[-1].error_code == "rate_limited"
        assert results[-1].retry_after > 0
        assert len(spy.calls) == 2, "a rate-limited call must never reach the handler"

        # A different device has its own budget.
        other_device = await gateway.invoke(
            db,
            tool_name="probe_limited",
            arguments={"count": 9},
            actor=actor,
            device_id=await _device_id(db),
            registry=registry,
        )
        assert other_device.status == "succeeded"


class TestApprovals:
    async def test_high_risk_tool_creates_an_approval_instead_of_running(
        self, db: AsyncSession, tmp_settings: Settings
    ) -> None:
        spy = Spy()
        registry = make_registry(
            tmp_settings, make_spec(name="probe_high", risk=Risk.HIGH, confirm=True, spy=spy)
        )
        gateway = SecurityGateway(tmp_settings, registry)
        actor = await _actor(db, email="approver@example.com")

        outcome = await gateway.invoke(
            db,
            tool_name="probe_high",
            arguments={"value": "deploy"},
            actor=actor,
            registry=registry,
        )
        assert outcome.status == "pending_approval"
        assert outcome.error_code == "approval_required"
        assert outcome.approval_id is not None
        assert spy.calls == [], "a HIGH action must not run before approval"

        approval = (
            (await db.execute(select(Approval).where(Approval.id == outcome.approval_id)))
            .scalars()
            .one()
        )
        assert approval.status is ApprovalStatus.PENDING
        assert approval.risk is Risk.HIGH
        assert approval.action_hash
        assert approval.single_use is True
        assert approval.expires_at > utcnow()
        assert "value" in approval.summary

        rows = await _audit_rows(db, "probe_high")
        assert rows[-1].outcome is AuditOutcome.PENDING_APPROVAL
        assert rows[-1].approval_id == approval.id

    async def test_approval_executes_once_and_only_for_its_own_arguments(
        self, db: AsyncSession, tmp_settings: Settings
    ) -> None:
        from app.security.approvals import decide

        spy = Spy()
        registry = make_registry(
            tmp_settings, make_spec(name="probe_high", risk=Risk.HIGH, confirm=True, spy=spy)
        )
        gateway = SecurityGateway(tmp_settings, registry)
        actor = await _actor(db, email="approver2@example.com")

        pending = await gateway.invoke(
            db, tool_name="probe_high", arguments={"value": "v1"}, actor=actor, registry=registry
        )
        approval_id = pending.approval_id
        assert approval_id is not None
        approval = (
            (await db.execute(select(Approval).where(Approval.id == approval_id))).scalars().one()
        )
        await decide(db, approval, approve=True)
        await db.commit()

        changed = await gateway.invoke(
            db,
            tool_name="probe_high",
            arguments={"value": "v2"},
            actor=actor,
            approval_id=approval_id,
            registry=registry,
        )
        assert changed.status == "denied"
        assert changed.error_code == "approval_argument_mismatch"
        assert spy.calls == []

        executed = await gateway.invoke(
            db,
            tool_name="probe_high",
            arguments={"value": "v1"},
            actor=actor,
            approval_id=approval_id,
            registry=registry,
        )
        assert executed.status == "succeeded"
        assert spy.names == ["probe_high"]

        replay = await gateway.invoke(
            db,
            tool_name="probe_high",
            arguments={"value": "v1"},
            actor=actor,
            approval_id=approval_id,
            registry=registry,
        )
        assert replay.status == "denied"
        assert replay.error_code in {"approval_already_used", "approval_invalid"}
        assert len(spy.calls) == 1, "a single-use approval must not carry out the action twice"

    async def test_approval_is_bound_to_the_actor_session_and_device(
        self, db: AsyncSession, tmp_settings: Settings
    ) -> None:
        from app.security.approvals import decide

        registry = make_registry(
            tmp_settings, make_spec(name="probe_high", risk=Risk.HIGH, confirm=True)
        )
        gateway = SecurityGateway(tmp_settings, registry)
        actor = await _actor(db)
        device_a, device_b = await _device_id(db), await _device_id(db)

        pending = await gateway.invoke(
            db,
            tool_name="probe_high",
            arguments={"value": "v"},
            actor=actor,
            device_id=device_a,
            registry=registry,
        )
        approval_id = pending.approval_id
        assert approval_id is not None
        approval = (
            (await db.execute(select(Approval).where(Approval.id == approval_id))).scalars().one()
        )
        await decide(db, approval, approve=True)
        await db.commit()

        other_device = await gateway.invoke(
            db,
            tool_name="probe_high",
            arguments={"value": "v"},
            actor=actor,
            device_id=device_b,
            approval_id=approval_id,
            registry=registry,
        )
        assert other_device.status == "denied"
        assert other_device.error_code == "approval_argument_mismatch"

        # And it cannot be borrowed by another account.
        stranger_actor = await _actor(db, email="stranger@example.com")
        stranger = await gateway.invoke(
            db,
            tool_name="probe_high",
            arguments={"value": "v"},
            actor=stranger_actor,
            device_id=device_a,
            approval_id=approval_id,
            registry=registry,
        )
        assert stranger.status == "denied"
        assert stranger.error_code == "approval_invalid"

    async def test_denied_approval_cannot_be_executed(
        self, db: AsyncSession, tmp_settings: Settings
    ) -> None:
        from app.security.approvals import decide

        spy = Spy()
        registry = make_registry(
            tmp_settings, make_spec(name="probe_high", risk=Risk.HIGH, confirm=True, spy=spy)
        )
        gateway = SecurityGateway(tmp_settings, registry)
        actor = await _actor(db, email="approver4@example.com")

        pending = await gateway.invoke(
            db, tool_name="probe_high", arguments={}, actor=actor, registry=registry
        )
        approval_id = pending.approval_id
        assert approval_id is not None
        approval = (
            (await db.execute(select(Approval).where(Approval.id == approval_id))).scalars().one()
        )
        await decide(db, approval, approve=False, reason="not now")
        await db.commit()

        outcome = await gateway.invoke(
            db,
            tool_name="probe_high",
            arguments={},
            actor=actor,
            approval_id=approval_id,
            registry=registry,
        )
        assert outcome.status == "denied"
        assert outcome.error_code == "approval_denied"
        assert spy.calls == []

    async def test_expired_approval_is_refused(
        self, db: AsyncSession, tmp_settings: Settings
    ) -> None:
        from app.security.approvals import decide

        registry = make_registry(
            tmp_settings, make_spec(name="probe_high", risk=Risk.HIGH, confirm=True)
        )
        gateway = SecurityGateway(tmp_settings, registry)
        actor = await _actor(db)

        pending = await gateway.invoke(
            db, tool_name="probe_high", arguments={}, actor=actor, registry=registry
        )
        approval_id = pending.approval_id
        assert approval_id is not None
        approval = (
            (await db.execute(select(Approval).where(Approval.id == approval_id))).scalars().one()
        )
        await decide(db, approval, approve=True)
        approval.expires_at = utcnow().replace(year=utcnow().year - 1)
        await db.commit()

        outcome = await gateway.invoke(
            db,
            tool_name="probe_high",
            arguments={},
            actor=actor,
            approval_id=approval_id,
            registry=registry,
        )
        assert outcome.status == "denied"
        assert outcome.error_code == "approval_expired"

    async def test_device_principal_cannot_request_a_high_action(
        self, db: AsyncSession, tmp_settings: Settings
    ) -> None:
        registry = make_registry(
            tmp_settings, make_spec(name="probe_high", risk=Risk.HIGH, confirm=True)
        )
        device_actor = ActorRef(user_id=None, role=None, scopes=ALL_SCOPES, label="esp32")
        outcome = await SecurityGateway(tmp_settings, registry).invoke(
            db, tool_name="probe_high", arguments={}, actor=device_actor, registry=registry
        )
        assert outcome.status == "denied"
        assert outcome.error_code == "forbidden"


class TestDryRunAndFailures:
    async def test_dry_run_needs_no_approval_and_changes_nothing(
        self, db: AsyncSession, tmp_settings: Settings
    ) -> None:
        spy = Spy()
        registry = make_registry(
            tmp_settings,
            make_spec(
                name="probe_high", risk=Risk.HIGH, confirm=True, dry_run_supported=True, spy=spy
            ),
        )
        outcome = await SecurityGateway(tmp_settings, registry).invoke(
            db,
            tool_name="probe_high",
            arguments={"value": "v"},
            actor=await _actor(db, email="dryrun@example.com"),
            dry_run=True,
            registry=registry,
        )
        assert outcome.status == "dry_run"
        assert spy.calls and spy.calls[0]["dry_run"] is True

        rows = await _audit_rows(db, "probe_high")
        assert rows[-1].outcome is AuditOutcome.DRY_RUN
        assert rows[-1].dry_run is True

    async def test_dry_run_is_refused_when_the_tool_cannot_support_it(
        self, db: AsyncSession, tmp_settings: Settings
    ) -> None:
        spy = Spy()
        registry = make_registry(tmp_settings, make_spec(name="probe_low", spy=spy))
        outcome = await SecurityGateway(tmp_settings, registry).invoke(
            db,
            tool_name="probe_low",
            arguments={},
            actor=await _actor(db),
            dry_run=True,
            registry=registry,
        )
        assert outcome.status == "denied"
        assert outcome.error_code == "dry_run_only"
        assert spy.calls == []

    @pytest.mark.parametrize("behaviour", ["fail", "raise"])
    async def test_tool_failures_are_recorded_as_failed(
        self, db: AsyncSession, tmp_settings: Settings, behaviour: str
    ) -> None:
        registry = make_registry(
            tmp_settings,
            make_spec(name="probe_bad", behaviour=behaviour),  # type: ignore[arg-type]
        )
        outcome = await SecurityGateway(tmp_settings, registry).invoke(
            db, tool_name="probe_bad", arguments={}, actor=await _actor(db), registry=registry
        )
        assert outcome.status == "failed"
        assert outcome.error_code == "tool_failed"

        rows = await _audit_rows(db, "probe_bad")
        assert rows[-1].outcome is AuditOutcome.FAILED
        assert rows[-1].error_code == "tool_failed"

    async def test_slow_tool_is_cut_off_by_its_timeout(
        self, db: AsyncSession, tmp_settings: Settings
    ) -> None:
        registry = make_registry(
            tmp_settings, make_spec(name="probe_slow", behaviour="slow", timeout_seconds=0.2)
        )
        outcome = await SecurityGateway(tmp_settings, registry).invoke(
            db, tool_name="probe_slow", arguments={}, actor=await _actor(db), registry=registry
        )
        assert outcome.status == "failed"
        assert outcome.error_code == "tool_timeout"

    async def test_self_approval_is_ignored_for_an_interactive_source(
        self, db: AsyncSession, tmp_settings: Settings
    ) -> None:
        spy = Spy()
        registry = make_registry(
            tmp_settings, make_spec(name="probe_high", risk=Risk.HIGH, confirm=True, spy=spy)
        )
        outcome = await SecurityGateway(tmp_settings, registry).invoke(
            db,
            tool_name="probe_high",
            arguments={},
            actor=await _actor(db, email="interactive@example.com"),
            source=AuditSource.API,
            self_approved=True,
            registry=registry,
        )
        assert outcome.status == "pending_approval"
        assert spy.calls == []

    async def test_self_approval_is_honoured_for_a_scheduled_source(
        self, db: AsyncSession, tmp_settings: Settings
    ) -> None:
        spy = Spy()
        registry = make_registry(
            tmp_settings, make_spec(name="probe_high", risk=Risk.HIGH, confirm=True, spy=spy)
        )
        outcome = await SecurityGateway(tmp_settings, registry).invoke(
            db,
            tool_name="probe_high",
            arguments={},
            actor=await _actor(db, email="scheduled@example.com"),
            source=AuditSource.SCHEDULE,
            self_approved=True,
            registry=registry,
        )
        assert outcome.status == "succeeded"
        assert spy.names == ["probe_high"]
        rows = await _audit_rows(db, "probe_high")
        assert rows[-1].source is AuditSource.SCHEDULE


class TestCatalogue:
    async def test_describe_tools_only_lists_what_the_actor_may_use(
        self, db: AsyncSession, tmp_settings: Settings
    ) -> None:
        registry = make_registry(
            tmp_settings,
            make_spec(name="probe_open"),
            make_spec(name="probe_scoped", required_scopes=("smart_home:write",)),
            make_spec(name="probe_off", enabled=False),
        )
        gateway = SecurityGateway(tmp_settings, registry)

        limited = await gateway.describe_tools(
            db, actor=await _actor(db, scopes=frozenset({"tools:basic"})), registry=registry
        )
        # health_status ships with the app and asks for no scope, so every actor may run it.
        names = {entry["name"] for entry in limited}
        assert names == {"probe_open", "health_status"}

        full = await gateway.describe_tools(db, actor=await _actor(db), registry=registry)
        assert {entry["name"] for entry in full} == {"probe_open", "probe_scoped", "health_status"}
        assert all("arguments" in entry for entry in full)
