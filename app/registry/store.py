# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Registry persistence.

The in-process registry is the source of truth for *what exists and what it can do*; these
tables are the source of truth for *what the operator has switched on*, and the versioned
snapshot every audit row points at.

Sync is idempotent and additive: updating a tool's manifest upgrades its row, but the
operator's ``enabled`` choice is preserved. A tool that disappears from the codebase is
disabled rather than deleted, so historical audit rows still resolve to a definition.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import stable_hash
from app.core.logging import get_logger
from app.core.metrics import inc
from app.core.time import utcnow
from app.db.models import RegistrySnapshot, ToolDefinition
from app.registry.core import ToolRegistry

__all__ = ["enabled_tool_names", "sync_registry"]

logger = get_logger("registry.store")


async def sync_registry(
    session: AsyncSession,
    registry: ToolRegistry,
    *,
    actor_user_id: uuid.UUID | None = None,
) -> RegistrySnapshot:
    """
    Mirror the process registry into the database and return the active snapshot.

    ``revision`` is monotonically increasing; ``snapshot_hash`` covers the full manifest, so
    two deployments running identical code share a snapshot and a changed tool description
    produces a new revision.
    """
    manifest: list[dict[str, Any]] = registry.snapshot_manifest()
    snapshot_hash = stable_hash(manifest)
    now = utcnow()

    snapshot = (
        (
            await session.execute(
                select(RegistrySnapshot).where(RegistrySnapshot.snapshot_hash == snapshot_hash)
            )
        )
        .scalars()
        .one_or_none()
    )
    if snapshot is None:
        highest = (await session.execute(select(func.max(RegistrySnapshot.revision)))).scalar() or 0
        snapshot = RegistrySnapshot(
            revision=int(highest) + 1,
            snapshot_hash=snapshot_hash,
            tool_count=len(manifest),
            manifest=manifest,
            created_at=now,
        )
        session.add(snapshot)
        await session.flush()
        inc("registry_snapshots_created")

    existing = {
        row.name: row for row in (await session.execute(select(ToolDefinition))).scalars().all()
    }

    for spec in registry.all():
        row = existing.get(spec.name)
        if row is None:
            session.add(
                ToolDefinition(
                    name=spec.name,
                    version=spec.version,
                    description=spec.description,
                    risk=spec.risk,
                    enabled=spec.enabled,
                    default_enabled=spec.enabled,
                    category=spec.category,
                    integration=spec.integration,
                    required_scopes=list(spec.required_scopes),
                    confirm_required=spec.confirm,
                    rate_limit=spec.rate_limit,
                    dry_run_supported=spec.dry_run_supported,
                    timeout_seconds=spec.timeout_seconds,
                    input_schema=spec.input_json_schema(),
                    output_schema=spec.output_json_schema(),
                    registry_snapshot_id=snapshot.id,
                    registered_at=now,
                    updated_at=now,
                )
            )
            continue
        # Manifest fields are refreshed; operator state (``enabled``) is not touched.
        row.version = spec.version
        row.description = spec.description
        row.risk = spec.risk
        row.default_enabled = spec.enabled
        row.category = spec.category
        row.integration = spec.integration
        row.required_scopes = list(spec.required_scopes)
        row.confirm_required = spec.confirm
        row.rate_limit = spec.rate_limit
        row.dry_run_supported = spec.dry_run_supported
        row.timeout_seconds = spec.timeout_seconds
        row.input_schema = spec.input_json_schema()
        row.output_schema = spec.output_json_schema()
        row.registry_snapshot_id = snapshot.id
        row.updated_at = now

    # Tools that no longer exist in code are disabled, never deleted.
    for name, row in existing.items():
        if name not in registry and row.enabled:
            row.enabled = False
            row.updated_at = now
            logger.warning("tool %s no longer exists in code; disabled", name)

    await session.flush()
    logger.info(
        "registry synced revision=%s tools=%d hash=%s",
        snapshot.revision,
        len(manifest),
        snapshot.snapshot_hash[:12],
    )
    return snapshot


async def enabled_tool_names(session: AsyncSession) -> dict[str, bool]:
    """
    Current operator enable/disable state per tool.

    Read on every gateway decision. It is a single indexed scan of a small table; caching it
    would mean a disabled dangerous tool stays executable for the length of the cache, which is
    exactly the failure mode the toggle exists to prevent.
    """
    rows = (await session.execute(select(ToolDefinition.name, ToolDefinition.enabled))).all()
    return {name: bool(enabled) for name, enabled in rows}
