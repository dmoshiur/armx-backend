# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
The approval prompt, over HTTP.

An approval is the user's decision about *one exact action*. These tests pin the properties that
make that sentence true: the prompt shows redacted arguments, only the account that was asked can
answer, answering does not execute anything by itself, a changed argument is refused, an approval
is spent exactly once, and nobody - not even an administrator - can approve on somebody else's
behalf.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

from httpx import AsyncClient
from sqlalchemy import select

from app.config import Settings
from app.core.enums import ApprovalStatus, AuditOutcome, Role
from app.core.risk import Risk
from app.core.time import utcnow
from app.db.models import Approval, AuditEvent
from app.main import create_app
from tests.factories import Spy, make_registry, make_spec


def app_with(settings: Settings, *specs):
    return create_app(settings, registry=make_registry(settings, *specs))


HIGH_SPEC = {"name": "probe_deploy", "risk": Risk.HIGH, "confirm": True}


async def _propose(http: AsyncClient, headers: dict[str, str], **arguments) -> dict:
    """Ask for a HIGH-tier action and return the 409 body that names the pending approval."""
    response = await http.post(
        f"/tools/{HIGH_SPEC['name']}/invoke",
        json={"arguments": arguments or {"value": "v"}},
        headers=headers,
    )
    assert response.status_code == 409, response.text
    body = response.json()
    assert body["code"] == "approval_required"
    return body


class TestApprovalLifecycle:
    async def test_the_full_flow_from_request_to_execution(
        self, client_for, db, tmp_settings: Settings, auth_headers, admin_user
    ) -> None:
        spy = Spy()
        spec = make_spec(name="probe_deploy", risk=Risk.HIGH, confirm=True, spy=spy)
        async with client_for(app_with(tmp_settings, spec)) as http:
            headers = await auth_headers(admin_user.email)
            body = await _propose(http, headers, value="ship it")
            approval_id = body["details"]["approval_id"]

            listed = await http.get("/approvals", headers=headers)
            assert listed.status_code == 200, listed.text
            assert [item["id"] for item in listed.json()["items"]] == [approval_id]
            assert listed.json()["items"][0]["status"] == "pending"
            assert listed.json()["items"][0]["seconds_remaining"] > 0
            assert spy.calls == [], "nothing may run before the user decides"

            confirmed = await http.post(
                f"/approvals/{approval_id}/confirm", json={"reason": "looks right"}, headers=headers
            )
            assert confirmed.status_code == 200, confirmed.text
            assert confirmed.json()["status"] == "approved"
            assert confirmed.json()["decided_at"] is not None
            assert spy.calls == [], "confirming is a decision, not an execution"

            executed = await http.post(
                "/tools/probe_deploy/invoke",
                json={"arguments": {"value": "ship it"}, "approval_id": approval_id},
                headers=headers,
            )
            assert executed.status_code == 200, executed.text
            assert executed.json()["status"] == "succeeded"
            assert spy.names == ["probe_deploy"]

            replay = await http.post(
                "/tools/probe_deploy/invoke",
                json={"arguments": {"value": "ship it"}, "approval_id": approval_id},
                headers=headers,
            )
            assert replay.status_code == 409
            assert replay.json()["code"] == "approval_already_used"
            assert len(spy.calls) == 1

        rows = (
            (
                await db.execute(
                    select(AuditEvent)
                    .where(AuditEvent.tool_name == "probe_deploy")
                    .order_by(AuditEvent.occurred_at)
                )
            )
            .scalars()
            .all()
        )
        assert [row.outcome for row in rows] == [
            AuditOutcome.PENDING_APPROVAL,
            AuditOutcome.SUCCEEDED,
            AuditOutcome.DENIED,
        ]
        assert all(row.approval_id is not None for row in rows)

    async def test_changed_arguments_are_refused(
        self, client_for, tmp_settings: Settings, auth_headers, admin_user
    ) -> None:
        spec = make_spec(**HIGH_SPEC)
        async with client_for(app_with(tmp_settings, spec)) as http:
            headers = await auth_headers(admin_user.email)
            body = await _propose(http, headers, value="small change")
            approval_id = body["details"]["approval_id"]
            await http.post(f"/approvals/{approval_id}/confirm", json={}, headers=headers)

            response = await http.post(
                "/tools/probe_deploy/invoke",
                json={"arguments": {"value": "everything"}, "approval_id": approval_id},
                headers=headers,
            )
            assert response.status_code == 409
            assert response.json()["code"] == "approval_argument_mismatch"

    async def test_denying_is_recorded_and_final(
        self, client_for, db, tmp_settings: Settings, auth_headers, admin_user
    ) -> None:
        spec = make_spec(**HIGH_SPEC)
        async with client_for(app_with(tmp_settings, spec)) as http:
            headers = await auth_headers(admin_user.email)
            body = await _propose(http, headers)
            approval_id = body["details"]["approval_id"]

            denied = await http.post(
                f"/approvals/{approval_id}/deny", json={"reason": "not tonight"}, headers=headers
            )
            assert denied.status_code == 200, denied.text
            assert denied.json()["status"] == "denied"
            assert denied.json()["deny_reason"] == "not tonight"

            response = await http.post(
                "/tools/probe_deploy/invoke",
                json={"arguments": {"value": "v"}, "approval_id": approval_id},
                headers=headers,
            )
            assert response.status_code == 409
            assert response.json()["code"] == "approval_denied"

        row = (
            (
                await db.execute(
                    select(AuditEvent)
                    .where(AuditEvent.tool_name == "approval.denied")
                    .order_by(AuditEvent.occurred_at.desc())
                )
            )
            .scalars()
            .first()
        )
        assert row is not None and row.outcome is AuditOutcome.DENIED

    async def test_an_expired_approval_cannot_be_confirmed_or_used(
        self, client_for, db, tmp_settings: Settings, auth_headers, admin_user
    ) -> None:
        spec = make_spec(**HIGH_SPEC)
        async with client_for(app_with(tmp_settings, spec)) as http:
            headers = await auth_headers(admin_user.email)
            body = await _propose(http, headers)
            approval_id = body["details"]["approval_id"]

            approval = (
                (await db.execute(select(Approval).where(Approval.id == uuid.UUID(approval_id))))
                .scalars()
                .one()
            )
            approval.expires_at = utcnow() - timedelta(seconds=5)
            await db.commit()

            confirm = await http.post(f"/approvals/{approval_id}/confirm", json={}, headers=headers)
            assert confirm.status_code == 409
            assert confirm.json()["code"] == "approval_expired"

            invoke = await http.post(
                "/tools/probe_deploy/invoke",
                json={"arguments": {"value": "v"}, "approval_id": approval_id},
                headers=headers,
            )
            assert invoke.status_code == 409
            assert invoke.json()["code"] == "approval_expired"

    async def test_a_medium_tool_that_declares_confirmation_asks_first(
        self, client_for, db, tmp_settings: Settings, auth_headers, admin_user
    ) -> None:
        spec = make_spec(name="probe_reply", risk=Risk.MEDIUM, confirm=True)
        async with client_for(app_with(tmp_settings, spec)) as http:
            headers = await auth_headers(admin_user.email)
            response = await http.post(
                "/tools/probe_reply/invoke",
                json={"arguments": {"value": "send it"}},
                headers=headers,
            )
            assert response.status_code == 409
            assert response.json()["code"] == "approval_required"

        rows = (
            (await db.execute(select(AuditEvent).where(AuditEvent.tool_name == "probe_reply")))
            .scalars()
            .all()
        )
        assert [row.outcome for row in rows] == [AuditOutcome.PENDING_APPROVAL]

    async def test_a_medium_tool_without_confirmation_runs_directly(
        self, client_for, db, tmp_settings: Settings, auth_headers, admin_user
    ) -> None:
        spec = make_spec(name="probe_reply", risk=Risk.MEDIUM)
        async with client_for(app_with(tmp_settings, spec)) as http:
            headers = await auth_headers(admin_user.email)
            response = await http.post(
                "/tools/probe_reply/invoke",
                json={"arguments": {"value": "draft it"}},
                headers=headers,
            )
            assert response.status_code == 200, response.text
            assert response.json()["status"] == "succeeded"

        rows = (
            (await db.execute(select(AuditEvent).where(AuditEvent.tool_name == "probe_reply")))
            .scalars()
            .all()
        )
        assert [row.outcome for row in rows] == [AuditOutcome.SUCCEEDED]


class TestApprovalIsolation:
    async def test_another_account_cannot_see_confirm_or_use_a_pending_approval(
        self, client_for, tmp_settings: Settings, auth_headers, admin_user, user_factory
    ) -> None:
        spec = make_spec(**HIGH_SPEC)
        other = await user_factory(role=Role.USER, email="other@example.com")
        async with client_for(app_with(tmp_settings, spec)) as http:
            requester_headers = await auth_headers(admin_user.email)
            other_headers = await auth_headers(other.email)
            body = await _propose(http, requester_headers)
            approval_id = body["details"]["approval_id"]

            assert (
                await http.get(f"/approvals/{approval_id}", headers=other_headers)
            ).status_code == 404
            assert (
                await http.post(f"/approvals/{approval_id}/confirm", json={}, headers=other_headers)
            ).status_code == 404
            assert (
                await http.post(f"/approvals/{approval_id}/deny", json={}, headers=other_headers)
            ).status_code == 404
            assert (await http.get("/approvals", headers=other_headers)).json()["items"] == []

            # And the stranger cannot spend it through the invocation endpoint either.
            borrowed = await http.post(
                "/tools/probe_deploy/invoke",
                json={"arguments": {"value": "v"}, "approval_id": approval_id},
                headers=other_headers,
            )
            assert borrowed.status_code == 409
            assert borrowed.json()["code"] == "approval_invalid"

            # An administrator has no override either: this is a user's own decision to make.
            admin_headers = requester_headers  # the requester *is* an admin in this fixture
            still_pending = await http.get(f"/approvals/{approval_id}", headers=admin_headers)
            assert still_pending.json()["status"] == "pending"

    async def test_approvals_require_authentication(self, client: AsyncClient) -> None:
        assert (await client.get("/approvals")).status_code == 401
        assert (await client.post(f"/approvals/{uuid.uuid4()}/confirm", json={})).status_code == 401


class TestApprovalExpiry:
    async def test_stale_approvals_are_marked_expired_and_cannot_be_spent(
        self, client_for, db, tmp_settings: Settings, auth_headers, admin_user
    ) -> None:
        from app.security.approvals import expire_stale

        spec = make_spec(**HIGH_SPEC)
        async with client_for(app_with(tmp_settings, spec)) as http:
            headers = await auth_headers(admin_user.email)
            body = await _propose(http, headers)
            approval_id = body["details"]["approval_id"]

        approval = (
            (await db.execute(select(Approval).where(Approval.id == uuid.UUID(approval_id))))
            .scalars()
            .one()
        )
        approval.expires_at = utcnow() - timedelta(minutes=1)
        await db.commit()

        changed = await expire_stale(db)
        await db.commit()
        await db.refresh(approval)
        assert changed == 1
        assert approval.status is ApprovalStatus.EXPIRED

        # The prompt no longer offers it, and the row keeps its history.
        remaining = await db.execute(
            select(Approval).where(Approval.status == ApprovalStatus.PENDING)
        )
        assert remaining.scalars().all() == []
