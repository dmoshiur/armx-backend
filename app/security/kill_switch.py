# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Kill-switch.

Requirements it must satisfy, in order of importance:

* Engaging it stops every integration **immediately**: the flag is read from the database on
  every tool call (never cached) and an in-process event cancels in-flight harness sessions
  and closes WebSockets.
* It depends on nothing intelligent. No LLM call, no model decision, no biometric check, no
  client cooperation.
* Re-enabling is a separate, explicit, authenticated action - never a side effect of another
  request.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from typing import Any, ClassVar, Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.core.enums import SystemFlagKey
from app.core.logging import get_logger
from app.core.metrics import inc
from app.core.time import utcnow
from app.db.models import SystemFlag

__all__ = ["KillSwitch", "KillSwitchBus", "kill_switch_bus"]

logger = get_logger("security.killswitch")

_TRUTHY: Final = {"true", "1", "yes", "on"}


class KillSwitchBus:
    """
    In-process fan-out for kill-switch state changes.

    Subscribers are harness sessions and WebSocket connections. The bus is notification
    only: authority lives in the database row, so a missed notification can never keep an
    action alive past the next gateway check.
    """

    def __init__(self) -> None:
        self._engaged = False
        self._event = asyncio.Event()
        self._lock = asyncio.Lock()

    @property
    def engaged(self) -> bool:
        return self._engaged

    async def publish(self, *, engaged: bool, actor_id: uuid.UUID | None, reason: str) -> None:
        async with self._lock:
            self._engaged = engaged
            if engaged:
                self._event.set()
            else:
                self._event.clear()
        logger.warning(
            "kill switch %s by actor=%s reason=%s",
            "ENGAGED" if engaged else "released",
            actor_id,
            reason,
        )
        inc("kill_switch_transitions", {"state": "engaged" if engaged else "released"})

    async def wait_for_engagement(self) -> None:
        """Block until the kill-switch is engaged (used by session cancellers)."""
        await self._event.wait()

    async def subscribe(self) -> AsyncIterator[bool]:
        """Yield the current state, then every change."""
        queue: asyncio.Queue[bool] = asyncio.Queue(maxsize=8)
        self._subscribers.add(queue)
        try:
            yield self._engaged
            while True:
                yield await queue.get()
        finally:
            self._subscribers.discard(queue)

    # ---------------------------------------------------------------- internals
    _subscribers: ClassVar[set[asyncio.Queue[bool]]] = set()

    def _notify(self, engaged: bool) -> None:
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(engaged)
            except asyncio.QueueFull:  # pragma: no cover - slow subscriber
                continue


kill_switch_bus = KillSwitchBus()


class KillSwitch:
    """
    Reads and writes the kill-switch flag.

    ``is_engaged`` is called by the Security Gateway before *every* tool call and by the
    WebSocket layer before *every* outbound frame, so it does no caching and no
    cross-request memoisation.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def _flag(self, session: AsyncSession) -> SystemFlag | None:
        return (
            await session.execute(
                select(SystemFlag).where(SystemFlag.key == SystemFlagKey.KILL_SWITCH)
            )
        ).scalar_one_or_none()

    async def is_engaged(self, session: AsyncSession) -> bool:
        flag = await self._flag(session)
        return bool(flag and flag.value.strip().lower() in _TRUTHY)

    async def state(self, session: AsyncSession) -> dict[str, Any]:
        flag = await self._flag(session)
        if flag is None:
            return {"engaged": False, "reason": None, "updated_at": None, "updated_by": None}
        return {
            "engaged": flag.value.strip().lower() in _TRUTHY,
            "reason": flag.reason,
            "updated_at": flag.updated_at,
            "updated_by": flag.updated_by_user_id,
        }

    async def engage(
        self,
        session: AsyncSession,
        *,
        actor_user_id: uuid.UUID | None,
        reason: str,
    ) -> dict[str, Any]:
        """Engage immediately. No tier check, no approval, no biometrics - by design."""
        await self._set(session, engaged=True, actor_user_id=actor_user_id, reason=reason)
        await kill_switch_bus.publish(engaged=True, actor_id=actor_user_id, reason=reason)
        return await self.state(session)

    async def disengage(
        self,
        session: AsyncSession,
        *,
        actor_user_id: uuid.UUID | None,
        reason: str,
    ) -> dict[str, Any]:
        """Explicit re-enable. Only ever called from its own authenticated endpoint."""
        await self._set(session, engaged=False, actor_user_id=actor_user_id, reason=reason)
        await kill_switch_bus.publish(engaged=False, actor_id=actor_user_id, reason=reason)
        return await self.state(session)

    async def _set(
        self,
        session: AsyncSession,
        *,
        engaged: bool,
        actor_user_id: uuid.UUID | None,
        reason: str,
    ) -> None:
        flag = await self._flag(session)
        if flag is None:
            flag = SystemFlag(
                key=SystemFlagKey.KILL_SWITCH,
                value="false",
                updated_at=utcnow(),
            )
            session.add(flag)
        flag.value = "true" if engaged else "false"
        flag.reason = reason[:200]
        flag.updated_at = utcnow()
        flag.updated_by_user_id = actor_user_id
        await session.flush()
