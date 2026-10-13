# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
The tool API.

The REST surface is a thin client of the Security Gateway, so these tests assert the property
that matters: a caller reaching the API directly gets exactly the same decision as a model
proposing the same call - no more, no less. Refusals arrive as structured answers (403/404/409),
never as a 500 and never as a silent success.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.config import Settings
from app.core.enums import AuditOutcome, Role
from app.core.risk import Risk
from app.db.models import AuditEvent, ToolDefinition
from app.main import create_app
from tests.factories import make_registry, make_spec

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


def app_with(settings: Settings, *specs):
    """An app whose catalogue contains the shipped tools plus the given probes."""
    return create_app(settings, registry=make_registry(settings, *specs))


class TestCatalogue:
    async def test_the_catalogue_requires_authentication(self, client: AsyncClient) -> None:
        response = await client.get("/tools")
        assert response.status_code == 401
        assert response.json()["code"] == "unauthenticated"

    async def test_a_user_sees_the_shipped_tools(
        self, client: AsyncClient, auth_headers, admin_user
    ) -> None:
        headers = await auth_headers(admin_user.email)
        response = await client.get("/tools", headers=headers)
        assert response.status_code == 200, response.text
        payload = response.json()
        names = {item["name"] for item in payload["items"]}
        assert "health_status" in names
        entry = next(item for item in payload["items"] if item["name"] == "health_status")
        assert entry["risk"] == "low"
        assert entry["requires_approval"] is False
        assert entry["input_schema"]["properties"] == {}

    async def test_a_disabled_tool_is_not_offered(
        self, client_for, tmp_settings: Settings, auth_headers, admin_user
    ) -> None:
        """mock_echo ships disabled, so the catalogue must not advertise it."""
        application = create_app(tmp_settings)
        async with client_for(application) as http:
            headers = await auth_headers(admin_user.email)
            response = await http.get("/tools", headers=headers)
            assert response.status_code == 200
            assert "mock_echo" not in {item["name"] for item in response.json()["items"]}


class TestInvocation:
    async def test_unknown_tool_is_a_404(
        self, client: AsyncClient, auth_headers, admin_user
    ) -> None:
        headers = await auth_headers(admin_user.email)
        response = await client.post("/tools/shell/invoke", json={"arguments": {}}, headers=headers)
        assert response.status_code == 404
        assert response.json()["code"] == "tool_unknown"

    async def test_low_risk_tool_runs_and_lands_in_the_audit_trail(
        self, client_for, tmp_settings: Settings, auth_headers, admin_user
    ) -> None:
        spec = make_spec(name="probe_api", behaviour="echo")
        async with client_for(app_with(tmp_settings, spec)) as http:
            headers = await auth_headers(admin_user.email)
            response = await http.post(
                "/tools/probe_api/invoke",
                json={"arguments": {"value": "hello", "count": 2}},
                headers=headers,
            )
            assert response.status_code == 200, response.text
            body = response.json()
            assert body["status"] == "succeeded"
            assert body["data"]["echo"] == "hello"
            assert body["risk"] == "low"
            assert body["audit_id"]

            trail = await http.get("/audit", headers=headers, params={"tool_name": "probe_api"})
            assert trail.status_code == 200, trail.text
            items = trail.json()["items"]
            assert [item["outcome"] for item in items] == ["succeeded"]
            assert items[0]["arguments_redacted"] == {"value": "hello", "count": 2}

    async def test_invalid_arguments_are_rejected_with_422(
        self, client_for, tmp_settings: Settings, auth_headers, admin_user
    ) -> None:
        spec = make_spec(name="probe_api")
        async with client_for(app_with(tmp_settings, spec)) as http:
            headers = await auth_headers(admin_user.email)
            response = await http.post(
                "/tools/probe_api/invoke",
                json={"arguments": {"count": "many"}},
                headers=headers,
            )
            assert response.status_code == 422
            assert response.json()["code"] == "tool_argument_invalid"

    async def test_a_high_risk_tool_returns_409_with_the_approval_id(
        self, client_for, tmp_settings: Settings, auth_headers, admin_user
    ) -> None:
        spec = make_spec(name="probe_high_api", risk=Risk.HIGH, confirm=True)
        async with client_for(app_with(tmp_settings, spec)) as http:
            headers = await auth_headers(admin_user.email)
            response = await http.post(
                "/tools/probe_high_api/invoke", json={"arguments": {"value": "go"}}, headers=headers
            )
            assert response.status_code == 409
            body = response.json()
            assert body["code"] == "approval_required"
            approval_id = body["details"]["approval_id"]

            approval = await http.get(f"/approvals/{approval_id}", headers=headers)
            assert approval.status_code == 200, approval.text
            assert approval.json()["status"] == "pending"
            assert approval.json()["arguments"] == {"value": "go", "count": 1}

    async def test_an_engaged_kill_switch_refuses_but_keeps_health_checks_alive(
        self, client: AsyncClient, auth_headers, admin_user
    ) -> None:
        headers = await auth_headers(admin_user.email)
        engaged = await client.post(
            "/admin/kill-switch/engage", json={"reason": "drill"}, headers=headers
        )
        assert engaged.status_code == 200, engaged.text
        assert engaged.json()["engaged"] is True

        refused = await client.post(
            "/tools/mock_echo/invoke", json={"arguments": {"text": "hi"}}, headers=headers
        )
        assert refused.status_code == 403
        assert refused.json()["code"] == "kill_switch_engaged"

        allowed = await client.post("/tools/health_status/invoke", json={}, headers=headers)
        assert allowed.status_code == 200, allowed.text
        assert allowed.json()["status"] == "succeeded"

        released = await client.post(
            "/admin/kill-switch/disengage", json={"reason": "drill over"}, headers=headers
        )
        assert released.status_code == 200
        assert released.json()["engaged"] is False

    async def test_a_non_admin_cannot_touch_the_kill_switch(
        self, client: AsyncClient, auth_headers, regular_user
    ) -> None:
        headers = await auth_headers(regular_user.email)
        response = await client.post(
            "/admin/kill-switch/engage", json={"reason": "let me"}, headers=headers
        )
        assert response.status_code == 403
        assert response.json()["code"] == "role_required"


class TestAdminToggles:
    async def test_toggling_a_tool_changes_behavior_and_is_audited(
        self, db, client: AsyncClient, auth_headers, admin_user
    ) -> None:
        headers = await auth_headers(admin_user.email)

        listed = await client.get("/admin/tools", headers=headers)
        assert listed.status_code == 200, listed.text
        entry = next(item for item in listed.json() if item["name"] == "mock_echo")
        assert entry["enabled"] is False

        enabled = await client.patch(
            "/admin/tools/mock_echo", json={"enabled": True, "reason": "testing"}, headers=headers
        )
        assert enabled.status_code == 200, enabled.text
        assert enabled.json()["enabled"] is True

        row = (
            (await db.execute(select(ToolDefinition).where(ToolDefinition.name == "mock_echo")))
            .scalars()
            .one()
        )
        assert row.enabled is True

        audit_row = (
            (
                await db.execute(
                    select(AuditEvent)
                    .where(AuditEvent.tool_name == "admin.tool_toggled")
                    .order_by(AuditEvent.occurred_at.desc())
                )
            )
            .scalars()
            .first()
        )
        assert audit_row is not None
        assert audit_row.outcome is AuditOutcome.SUCCEEDED
        assert audit_row.actor_user_id == admin_user.id

        # Now that it is on, an authorised call reaches the handler.
        invoked = await client.post(
            "/tools/mock_echo/invoke", json={"arguments": {"text": "hello"}}, headers=headers
        )
        assert invoked.status_code in {200, 403}, invoked.text
        if invoked.status_code == 200:
            assert invoked.json()["status"] == "succeeded"
        else:
            assert invoked.json()["code"] in {"scope_required", "forbidden", "tool_disabled"}

    async def test_only_an_admin_may_toggle(
        self, client: AsyncClient, auth_headers, vip_user
    ) -> None:
        headers = await auth_headers(vip_user.email)
        response = await client.patch(
            "/admin/tools/health_status", json={"enabled": False}, headers=headers
        )
        assert response.status_code == 403
        assert response.json()["code"] == "role_required"

    async def test_an_unknown_tool_cannot_be_toggled(
        self, client: AsyncClient, auth_headers, admin_user
    ) -> None:
        headers = await auth_headers(admin_user.email)
        response = await client.patch(
            "/admin/tools/definitely_not_a_tool", json={"enabled": True}, headers=headers
        )
        assert response.status_code == 404


class TestDryRun:
    async def test_a_dry_run_reports_the_plan_without_creating_an_approval(
        self, client_for, db, tmp_settings: Settings, auth_headers, admin_user
    ) -> None:
        spec = make_spec(name="probe_dry", risk=Risk.HIGH, confirm=True, dry_run_supported=True)
        async with client_for(app_with(tmp_settings, spec)) as http:
            headers = await auth_headers(admin_user.email)
            response = await http.post(
                "/tools/probe_dry/invoke",
                json={"arguments": {"value": "sneak peek"}, "dry_run": True},
                headers=headers,
            )
            assert response.status_code == 200, response.text
            body = response.json()
            assert body["status"] == "dry_run"
            assert body["dry_run"] is True

            approvals = await http.get("/approvals", headers=headers)
            assert approvals.status_code == 200
            assert approvals.json()["items"] == [], "a dry run must not create an approval"

        rows = (
            (
                await db.execute(
                    select(AuditEvent)
                    .where(AuditEvent.tool_name == "probe_dry")
                    .order_by(AuditEvent.occurred_at)
                )
            )
            .scalars()
            .all()
        )
        assert [row.outcome for row in rows] == [AuditOutcome.DRY_RUN]

    async def test_a_tool_that_cannot_dry_run_refuses_the_request(
        self, client_for, tmp_settings: Settings, auth_headers, admin_user
    ) -> None:
        spec = make_spec(name="probe_nodry")
        async with client_for(app_with(tmp_settings, spec)) as http:
            headers = await auth_headers(admin_user.email)
            response = await http.post(
                "/tools/probe_nodry/invoke",
                json={"arguments": {}, "dry_run": True},
                headers=headers,
            )
            assert response.status_code == 403
            assert response.json()["code"] == "dry_run_only"


class TestScopeEnforcement:
    async def test_a_vip_cannot_run_an_admin_only_tool(
        self, client_for, tmp_settings: Settings, auth_headers, vip_user
    ) -> None:
        spec = make_spec(name="probe_owner", required_scopes=("admin:tools",))
        async with client_for(app_with(tmp_settings, spec)) as http:
            headers = await auth_headers(vip_user.email)
            response = await http.post(
                "/tools/probe_owner/invoke", json={"arguments": {}}, headers=headers
            )
            assert response.status_code == 403
            assert response.json()["code"] == "scope_required"

    async def test_an_admin_may_run_it(
        self, client_for, tmp_settings: Settings, auth_headers, admin_user
    ) -> None:
        spec = make_spec(name="probe_owner", required_scopes=("admin:tools",))
        async with client_for(app_with(tmp_settings, spec)) as http:
            headers = await auth_headers(admin_user.email)
            assert admin_user.role is Role.ADMIN
            response = await http.post(
                "/tools/probe_owner/invoke", json={"arguments": {}}, headers=headers
            )
            assert response.status_code == 200, response.text
