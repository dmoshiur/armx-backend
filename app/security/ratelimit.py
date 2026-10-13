# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Rate limiting.

Counters live in the primary database rather than a separate cache service, so there is exactly
one answer to "how many times has this actor called this tool in this window" and limits cannot
drift between workers. The increment is a single atomic upsert with ``RETURNING``, which is what
makes concurrent requests - and multiple containers - share one accurate count.

Two limits apply to every tool call: the global per-actor default and the tool manifest's own
limit. Auth endpoints use a stricter per-IP limit. A counter key is derived from *actor and
action* and then hashed, never taken from user-supplied text, so a client cannot inflate the
counter table with unbounded keys and a raw IP address never lands in the database.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import case, select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.core.logging import get_logger
from app.core.metrics import inc
from app.core.ratelimit_spec import RateLimitSpec
from app.core.time import utcnow
from app.db.models import RateLimitCounter

__all__ = ["RateLimitResult", "RateLimiter", "limit_key"]

logger = get_logger("security.ratelimit")


@dataclass(frozen=True, slots=True)
class RateLimitResult:
    """Outcome of a single limit check."""

    allowed: bool
    limit: int
    remaining: int
    retry_after_seconds: int
    spec: RateLimitSpec
    key: str

    def headers(self) -> dict[str, str]:
        headers = {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(max(0, self.remaining)),
        }
        if not self.allowed:
            headers["Retry-After"] = str(max(1, self.retry_after_seconds))
        return headers


def limit_key(*parts: str) -> str:
    """
    Build a bounded, non-reversible counter key.

    Inputs are hashed so a raw IP address or user id never lands in the counter table, and the
    key has a fixed length regardless of the input.
    """
    material = "|".join(part for part in parts if part)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:48]


class RateLimiter:
    """Fixed-window rate limiter backed by the primary database."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    @property
    def enabled(self) -> bool:
        return self._settings.rate_limit_enabled

    async def check(
        self,
        session: AsyncSession,
        *,
        key: str,
        spec: RateLimitSpec,
        cost: int = 1,
    ) -> RateLimitResult:
        """
        Consume ``cost`` against ``key`` and report the result.

        When limiting is disabled the check is a no-op that always allows, which is only ever
        configured for local development and the test suite.
        """
        now_epoch = int(time.time())
        bucket = spec.bucket(now_epoch)
        window_start = bucket * spec.window_seconds
        count = 0

        if self.enabled:
            dialect = session.bind.dialect.name if session.bind is not None else "sqlite"
            make_insert = postgresql_insert if dialect == "postgresql" else sqlite_insert
            expires_at = utcnow() + timedelta(seconds=spec.window_seconds * 2)
            statement = (
                make_insert(RateLimitCounter)
                .values(
                    key=key,
                    window_start=window_start,
                    count=cost,
                    expires_at=expires_at,
                )
                .on_conflict_do_update(
                    index_elements=[RateLimitCounter.key],
                    set_={
                        # Same window: increment. New window: start over at ``cost``.
                        "count": case(
                            (
                                RateLimitCounter.window_start == window_start,
                                RateLimitCounter.count + cost,
                            ),
                            else_=cost,
                        ),
                        "window_start": window_start,
                        "expires_at": expires_at,
                    },
                )
                .returning(RateLimitCounter.count)
            )
            count = int((await session.execute(statement)).scalar() or 0)
            await session.commit()

        if count > spec.count:
            retry_after = max(1, (bucket + 1) * spec.window_seconds - now_epoch)
            inc("rate_limit_denied")
            logger.warning("rate limit exceeded for key prefix %s", key[:8])
            return RateLimitResult(
                allowed=False,
                limit=spec.count,
                remaining=0,
                retry_after_seconds=retry_after,
                spec=spec,
                key=key,
            )
        return RateLimitResult(
            allowed=True,
            limit=spec.count,
            remaining=max(0, spec.count - count),
            retry_after_seconds=0,
            spec=spec,
            key=key,
        )

    async def peek(self, session: AsyncSession, *, key: str) -> int:
        """Current count for a key without consuming (admin views and tests)."""
        value = (
            await session.execute(select(RateLimitCounter.count).where(RateLimitCounter.key == key))
        ).scalar()
        return int(value or 0)

    async def reset(self, session: AsyncSession, *, key: str) -> None:
        """Clear one counter (tests, and an audited admin unlock path)."""
        counter = (
            (await session.execute(select(RateLimitCounter).where(RateLimitCounter.key == key)))
            .scalars()
            .one_or_none()
        )
        if counter is not None:
            await session.delete(counter)
            await session.commit()
