# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import logging

from sqlalchemy import select

from app.config import Settings, get_settings
from app.core.security import hash_password
from app.db.models import SystemState, ToolToggle, User
from app.db.session import SessionFactory

logger = logging.getLogger("armx.bootstrap")
_DEFAULT_TOOLS = ("GITHUB", "MAIL", "MQTT", "DB", "SYSTEM", "VISION")


async def initialize_database_state(settings: Settings | None = None) -> None:
    """Create singleton system state, safe tool defaults, and optional bootstrap owner."""

    config = settings or get_settings()
    async with SessionFactory() as session:
        if await session.get(SystemState, 1) is None:
            session.add(SystemState(id=1, assistant_enabled=True, kill_switch_engaged=False))
        for name in _DEFAULT_TOOLS:
            if await session.get(ToolToggle, name) is None:
                session.add(ToolToggle(name=name, enabled=False))

        if config.bootstrap_admin_password is not None:
            user = await session.scalar(
                select(User).where(User.username == config.bootstrap_admin_username.strip().lower())
            )
            if user is None:
                session.add(
                    User(
                        public_id=f"user-{config.bootstrap_admin_username.strip().lower()}",
                        username=config.bootstrap_admin_username.strip().lower(),
                        email=config.bootstrap_admin_email.strip().lower(),
                        display_name=config.bootstrap_admin_display_name,
                        password_hash=hash_password(
                            config.bootstrap_admin_password.get_secret_value()
                        ),
                        roles=["owner", "admin"],
                    )
                )
        else:
            existing_owner = await session.scalar(
                select(User.id).where(User.roles.contains(["owner"]))
            )
            if existing_owner is None:
                logger.warning(
                    "No bootstrap owner is configured; set BOOTSTRAP_ADMIN_PASSWORD before login."
                )
        await session.commit()
