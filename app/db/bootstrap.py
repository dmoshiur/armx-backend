# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Startup database preparation.

Runs after ``alembic upgrade head`` and before the first request:

* creates the rows the Security Gateway depends on (notably the kill-switch flag, which must
  exist and be readable even on a brand-new database),
* purges expired operational rows so the tables do not grow without bound,
* reports the dialect and migration revision for the startup log.

It never creates schema: Alembic owns the schema, and an application that silently creates
tables would let an unmigrated production database boot with a schema nobody reviewed.
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.core.enums import SystemFlagKey
from app.core.logging import get_logger
from app.core.time import utcnow
from app.db.models import (
    Approval,
    EmailToken,
    ImageAsset,
    RateLimitCounter,
    Session,
    SystemFlag,
    UsedNonce,
)
from app.db.session import session_scope
from app.db.sql import affected_rows

__all__ = ["initialize_database_state", "purge_expired_rows"]

logger = get_logger("db.bootstrap")

#: Flags that must exist before the first request. ``value`` is a string ("true"/"false")
#: so a new flag can be added without a schema migration.
_REQUIRED_FLAGS: tuple[tuple[SystemFlagKey, str], ...] = (
    (SystemFlagKey.KILL_SWITCH, "false"),
    (SystemFlagKey.MAINTENANCE_MODE, "false"),
    (SystemFlagKey.LLM_ENABLED, "true"),
)


async def _ensure_flags(session: AsyncSession) -> None:
    existing = set((await session.execute(select(SystemFlag.key))).scalars().all())
    now = utcnow()
    for key, default_value in _REQUIRED_FLAGS:
        if key in existing:
            continue
        session.add(
            SystemFlag(
                key=key,
                value=default_value,
                reason="created at startup",
                updated_at=now,
            )
        )
    await session.flush()


async def purge_expired_rows(session: AsyncSession) -> dict[str, int]:
    """
    Delete operational rows that have expired.

    Audit events and approvals are deliberately excluded: audit is retention-managed
    separately (``AUDIT_RETENTION_DAYS``), and an expired approval is evidence of a denied
    action, not garbage.
    """
    now = utcnow()
    removed: dict[str, int] = {}

    result = await session.execute(
        delete(RateLimitCounter).where(RateLimitCounter.expires_at < now)
    )
    removed["rate_limit_counters"] = affected_rows(result)

    result = await session.execute(delete(UsedNonce).where(UsedNonce.expires_at < now))
    removed["used_nonces"] = affected_rows(result)

    result = await session.execute(
        delete(EmailToken).where(EmailToken.expires_at < now - timedelta(days=1))
    )
    removed["email_tokens"] = affected_rows(result)

    result = await session.execute(
        delete(Session).where(
            Session.expires_at < now - timedelta(days=7), Session.revoked_at.is_not(None)
        )
    )
    removed["sessions"] = affected_rows(result)

    result = await session.execute(
        delete(ImageAsset).where(ImageAsset.expires_at.is_not(None), ImageAsset.expires_at < now)
    )
    removed["image_assets"] = affected_rows(result)

    await session.flush()
    return removed


async def initialize_database_state(settings: Settings) -> None:
    """Prepare flags and reclaim expired rows. Raises if the database is unreachable."""
    async with session_scope(settings) as session:
        await _ensure_flags(session)
        purged = await purge_expired_rows(session)
        revision = await current_migration_revision(session)
    logger.info(
        "database state initialised",
        extra={
            "dialect": "postgresql" if not settings.uses_sqlite else "sqlite",
            "revision": revision or "unknown",
            "purged": purged,
        },
    )


async def current_migration_revision(session: AsyncSession) -> str | None:
    """Read ``alembic_version.version_num``; ``None`` when the table does not exist yet."""
    from sqlalchemy import text

    try:
        value = (
            await session.execute(text("SELECT version_num FROM alembic_version LIMIT 1"))
        ).scalar()
    except Exception:
        return None
    return str(value) if value else None


async def pending_approval_count(session: AsyncSession) -> int:
    """Gauge for ``/metrics``: approvals waiting on a human."""
    from app.core.enums import ApprovalStatus

    return int(
        (
            await session.execute(
                select(func.count(Approval.id)).where(Approval.status == ApprovalStatus.PENDING)
            )
        ).scalar()
        or 0
    )
