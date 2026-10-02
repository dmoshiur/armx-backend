# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import SystemState


async def is_kill_switch_engaged(session: AsyncSession) -> bool:
    """Read the switch from the database instead of a possibly stale identity-map row."""

    value = await session.scalar(select(SystemState.kill_switch_engaged).where(SystemState.id == 1))
    return bool(value)
