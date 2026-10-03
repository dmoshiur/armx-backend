# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import logging

from sqlalchemy import select

from app.config import Settings
from app.db.models import SystemState, ToolToggle, User
from app.db.session import SessionFactory

logger = logging.getLogger("armx.bootstrap")
_DEFAULT_TOOLS = ("GITHUB", "MAIL", "MQTT", "DB", "SYSTEM", "VISION")


async def initialize_database_state(settings: Settings | None = None) -> None:
    """Create system defaults while leaving a fresh account database empty."""

    async with SessionFactory() as session:
        if await session.get(SystemState, 1) is None:
            session.add(SystemState(id=1, assistant_enabled=True, kill_switch_engaged=False))
        for name in _DEFAULT_TOOLS:
            if await session.get(ToolToggle, name) is None:
                session.add(ToolToggle(name=name, enabled=False))

        # A fresh database stays empty so its first successful registration can claim
        # administrator status atomically. Existing owners are backfilled below, and
        # credentials from legacy BOOTSTRAP_ADMIN_* variables are intentionally ignored.
        existing_owner = await session.scalar(
            select(User.id).where(User.roles.contains(["owner"]))
        )
        if existing_owner is None:
            logger.warning(
                "No administrator exists; the first registered account will receive "
                "the initial administrator role."
            )
        await session.flush()
        system_state = await session.get(SystemState, 1)
        if system_state is not None and system_state.first_admin_user_id is None:
            owners = (
                await session.scalars(select(User).order_by(User.created_at, User.id))
            ).all()
            owner = next(
                (
                    candidate
                    for candidate in owners
                    if {role.lower() for role in candidate.roles}.intersection(
                        {"owner", "admin"}
                    )
                ),
                None,
            )
            if owner is not None:
                system_state.first_admin_user_id = owner.id
                system_state.initial_admin_claimed = True
        await session.commit()
