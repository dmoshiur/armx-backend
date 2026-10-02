# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.auth.dependencies import Principal
from app.core.risk_policy import RiskTier
from app.db.models import AuthSession, Device, ToolToggle, User
from app.mcp.tools import available_tool_schemas, derive_risk_tier
from tests.helpers import _harness


@pytest.mark.asyncio
async def test_mcp_tool_availability_is_server_toggle_and_role_scoped() -> None:
    harness = await _harness()
    settings = harness.settings.model_copy(
        update={
            "notes_enabled": True,
            "github_enabled": True,
            "github_token": "fake-test-token",
            "github_repository": "owner/repo",
        }
    )
    async with harness.factory() as session:
        user = await session.scalar(select(User).where(User.username == "owner"))
        device = await session.scalar(select(Device).where(Device.public_id == "device-owner"))
        assert user is not None and device is not None
        user.roles = ["user"]
        session.add_all(
            [ToolToggle(name="DB", enabled=True), ToolToggle(name="GITHUB", enabled=True)]
        )
        auth_session = AuthSession(
            user_id=user.id,
            device_id=device.id,
            refresh_token_hash="a" * 64,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        session.add(auth_session)
        await session.flush()
        principal = Principal(user=user, device=device, auth_session=auth_session)

        normal_user = await available_tool_schemas(session, settings, principal)
        normal_names = {item["function"]["name"] for item in normal_user}
        assert normal_names == {"notes_search", "notes_create"}

        user.roles = ["user", "admin"]
        admin_tools = await available_tool_schemas(session, settings, principal)
        admin_names = {item["function"]["name"] for item in admin_tools}
        assert {"github_list_issues", "github_create_issue"}.issubset(admin_names)
        assert (
            await derive_risk_tier(session, principal, "github_create_issue", {"title": "Test"})
            is RiskTier.HIGH
        )

    await harness.engine.dispose()
