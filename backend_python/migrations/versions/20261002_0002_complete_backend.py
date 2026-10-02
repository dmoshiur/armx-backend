# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""Expand the bootstrap schema to cover the documented backend API.

Revision ID: 20261002_0002
Revises: 20261002_0001
Create Date: 2026-10-02
"""

import uuid
from collections.abc import Sequence
from secrets import token_urlsafe

import sqlalchemy as sa
from alembic import op

revision: str = "20261002_0002"
down_revision: str | None = "20261002_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _uuid(value: object) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


def _public_id(prefix: str, value: object) -> str:
    return f"{prefix}-{_uuid(value).hex[:8]}"


def upgrade() -> None:
    bind = op.get_bind()

    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("public_id", sa.String(length=96), nullable=True))
        batch.add_column(sa.Column("username", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("display_name", sa.String(length=160), nullable=True))
        batch.add_column(
            sa.Column(
                "roles",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'[\"user\"]'"),
            )
        )
        batch.add_column(
            sa.Column(
                "preferred_language", sa.String(length=8), nullable=False, server_default="en"
            )
        )
        batch.add_column(
            sa.Column("failed_login_count", sa.Integer(), nullable=False, server_default="0")
        )
        batch.add_column(sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True))

    users = sa.table(
        "users",
        sa.column("id", sa.Uuid()),
        sa.column("email", sa.String()),
        sa.column("role", sa.String()),
        sa.column("public_id", sa.String()),
        sa.column("username", sa.String()),
        sa.column("display_name", sa.String()),
        sa.column("roles", sa.JSON()),
    )
    seen_usernames: set[str] = set()
    for row in bind.execute(sa.select(users.c.id, users.c.email, users.c.role)).all():
        email = str(row.email or "")
        base_username = (email.split("@", 1)[0] or "user").lower()[:48]
        username = base_username
        if username in seen_usernames:
            username = f"{base_username[:39]}-{_uuid(row.id).hex[:8]}"
        seen_usernames.add(username)
        old_role = str(row.role or "user").lower()
        roles = ["user"]
        if old_role in {"owner", "admin"}:
            roles = ["user", "owner", "admin"] if old_role == "owner" else ["user", "admin"]
        bind.execute(
            users.update()
            .where(users.c.id == row.id)
            .values(
                public_id=f"user-{_uuid(row.id).hex[:8]}",
                username=username,
                display_name=username,
                roles=roles,
            )
        )

    with op.batch_alter_table("users") as batch:
        batch.alter_column("public_id", existing_type=sa.String(length=96), nullable=False)
        batch.alter_column("username", existing_type=sa.String(length=64), nullable=False)
        batch.alter_column("display_name", existing_type=sa.String(length=160), nullable=False)
        batch.create_unique_constraint("uq_users_public_id", ["public_id"])
        batch.create_unique_constraint("uq_users_username", ["username"])
        batch.drop_column("role")

    with op.batch_alter_table("devices") as batch:
        batch.add_column(sa.Column("public_id", sa.String(length=96), nullable=True))
        batch.add_column(
            sa.Column("platform", sa.String(length=32), nullable=False, server_default="other")
        )
        batch.add_column(
            sa.Column("device_key_hash", sa.String(length=64), nullable=False, server_default="")
        )
        batch.add_column(
            sa.Column("site", sa.String(length=80), nullable=False, server_default="home")
        )
        batch.add_column(
            sa.Column("kind", sa.String(length=24), nullable=False, server_default="OTHER")
        )
        batch.add_column(
            sa.Column("firmware", sa.String(length=48), nullable=False, server_default="unknown")
        )
        batch.add_column(sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(
            sa.Column(
                "paired_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            )
        )
    devices = sa.table(
        "devices",
        sa.column("id", sa.Uuid()),
        sa.column("public_id", sa.String()),
    )
    for row in bind.execute(sa.select(devices.c.id)).all():
        bind.execute(
            devices.update()
            .where(devices.c.id == row.id)
            .values(public_id=_public_id("device", row.id))
        )
    with op.batch_alter_table("devices") as batch:
        batch.alter_column("public_id", existing_type=sa.String(length=96), nullable=False)
        batch.create_unique_constraint("uq_devices_public_id", ["public_id"])

    with op.batch_alter_table("pairing_requests") as batch:
        batch.alter_column(
            "owner_id", existing_type=sa.Uuid(), existing_nullable=False, nullable=True
        )
        batch.add_column(
            sa.Column("platform", sa.String(length=32), nullable=False, server_default="other")
        )
        batch.add_column(
            sa.Column("device_public_id", sa.String(length=96), nullable=False, server_default="")
        )
        batch.add_column(
            sa.Column("poll_challenge", sa.String(length=96), nullable=False, server_default="")
        )
        batch.add_column(
            sa.Column("fingerprint", sa.String(length=64), nullable=False, server_default="")
        )
        batch.add_column(sa.Column("device_id", sa.Uuid(), nullable=True))
        batch.add_column(sa.Column("device_key_ciphertext", sa.Text(), nullable=True))
        batch.create_foreign_key(
            "fk_pairing_requests_device_id_devices",
            "devices",
            ["device_id"],
            ["id"],
            ondelete="SET NULL",
        )
    pairing = sa.table(
        "pairing_requests",
        sa.column("id", sa.Uuid()),
        sa.column("device_name", sa.String()),
        sa.column("device_public_id", sa.String()),
        sa.column("poll_challenge", sa.String()),
    )
    for row in bind.execute(sa.select(pairing.c.id, pairing.c.device_name)).all():
        bind.execute(
            pairing.update()
            .where(pairing.c.id == row.id)
            .values(
                device_public_id=f"device-{_uuid(row.id).hex[:8]}",
                poll_challenge=token_urlsafe(32),
            )
        )
    op.create_index(
        "ix_pairing_requests_public_key_created",
        "pairing_requests",
        ["public_key", "created_at"],
        unique=False,
    )

    with op.batch_alter_table("audit_logs") as batch:
        batch.add_column(sa.Column("subject_user_id", sa.Uuid(), nullable=True))
        batch.add_column(sa.Column("device_id", sa.Uuid(), nullable=True))
        batch.add_column(
            sa.Column("target", sa.String(length=180), nullable=False, server_default="")
        )
        batch.add_column(
            sa.Column("risk_tier", sa.String(length=12), nullable=False, server_default="LOW")
        )
        batch.add_column(
            sa.Column("outcome", sa.String(length=16), nullable=False, server_default="SUCCESS")
        )
        batch.add_column(
            sa.Column("detail", sa.String(length=500), nullable=False, server_default="")
        )
        batch.add_column(
            sa.Column("metadata", sa.JSON(), nullable=False, server_default=sa.text("'{}'"))
        )
        batch.create_foreign_key(
            "fk_audit_logs_subject_user_id_users",
            "users",
            ["subject_user_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch.create_foreign_key(
            "fk_audit_logs_device_id_devices",
            "devices",
            ["device_id"],
            ["id"],
            ondelete="SET NULL",
        )

    legacy_audit = sa.table(
        "audit_logs",
        sa.column("id", sa.Uuid()),
        sa.column("target_type", sa.String()),
        sa.column("target_id", sa.String()),
        sa.column("target", sa.String()),
        sa.column("detail", sa.String()),
    )
    for row in bind.execute(
        sa.select(legacy_audit.c.id, legacy_audit.c.target_type, legacy_audit.c.target_id)
    ).all():
        target_parts = [str(part) for part in (row.target_type, row.target_id) if part]
        bind.execute(
            legacy_audit.update()
            .where(legacy_audit.c.id == row.id)
            .values(
                target=":".join(target_parts)[:180],
                detail="Migrated from the bootstrap audit schema; legacy details were discarded.",
            )
        )
    with op.batch_alter_table("audit_logs") as batch:
        batch.drop_column("target_type")
        batch.drop_column("target_id")
        batch.drop_column("details")
    op.create_index(
        "ix_audit_logs_subject_created_at",
        "audit_logs",
        ["subject_user_id", "created_at"],
        unique=False,
    )

    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("refresh_token_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("refresh_token_hash"),
    )
    op.create_index("ix_auth_sessions_user_device", "auth_sessions", ["user_id", "device_id"])

    op.create_table(
        "system_state",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("assistant_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("kill_switch_engaged", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("updated_by", sa.Uuid(), nullable=True),
        sa.Column("reason", sa.String(length=240), nullable=False, server_default=""),
        sa.ForeignKeyConstraint(["updated_by"], ["users.id"], ondelete="SET NULL"),
    )

    op.create_table(
        "tool_toggles",
        sa.Column("name", sa.String(length=24), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("updated_by", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(["updated_by"], ["users.id"], ondelete="SET NULL"),
    )

    op.create_table(
        "resource_devices",
        sa.Column("id", sa.String(length=96), primary_key=True),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("site", sa.String(length=80), nullable=False, server_default="home"),
        sa.Column("kind", sa.String(length=24), nullable=False, server_default="OTHER"),
        sa.Column("online", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("risk_tier", sa.String(length=12), nullable=False, server_default="MEDIUM"),
        sa.Column("firmware", sa.String(length=48), nullable=False, server_default="unknown"),
        sa.Column(
            "last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("relays", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("sensors", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("tags", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_resource_devices_owner_online", "resource_devices", ["owner_id", "online"], unique=False
    )

    op.create_table(
        "automation_rules",
        sa.Column("id", sa.String(length=80), primary_key=True),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("trigger_type", sa.String(length=32), nullable=False),
        sa.Column("action_type", sa.String(length=32), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("dry_run", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("risk_tier", sa.String(length=12), nullable=False, server_default="MEDIUM"),
        sa.Column("trigger_params", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("action_params", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("geofence_id", sa.String(length=80), nullable=True),
        sa.Column("device_id", sa.String(length=80), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("run_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_automation_rules_owner_enabled",
        "automation_rules",
        ["owner_id", "enabled"],
        unique=False,
    )

    op.create_table(
        "unlock_targets",
        sa.Column("id", sa.String(length=96), primary_key=True),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("kind", sa.String(length=24), nullable=False, server_default="OTHER"),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("online", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "last_seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("risk_tier", sa.String(length=12), nullable=False, server_default="HIGH"),
        sa.Column("paired", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("agent_version", sa.String(length=48), nullable=False, server_default=""),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="CASCADE"),
    )

    op.create_table(
        "used_nonces",
        sa.Column("nonce_hash", sa.String(length=64), primary_key=True),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("scope", sa.String(length=80), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "used_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_used_nonces_expires", "used_nonces", ["expires_at"], unique=False)

    op.create_table(
        "pending_tool_calls",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("tool", sa.String(length=80), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=False),
        sa.Column("risk_tier", sa.String(length=12), nullable=False),
        sa.Column("reason", sa.String(length=500), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="PENDING"),
        sa.Column("result_summary", sa.String(length=500), nullable=False, server_default=""),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_tool_calls_owner_status", "pending_tool_calls", ["user_id", "status"], unique=False
    )

    op.create_table(
        "intercom_consents",
        sa.Column("device_id", sa.Uuid(), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("allow_while_locked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
    )

    op.create_table(
        "intercom_announcements",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("sender_user_id", sa.Uuid(), nullable=False),
        sa.Column("target_user_id", sa.Uuid(), nullable=True),
        sa.Column("target_device_id", sa.Uuid(), nullable=True),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("target_label", sa.String(length=180), nullable=False, server_default=""),
        sa.Column("mime_type", sa.String(length=80), nullable=False, server_default="audio/mp4"),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("audio_bytes", sa.LargeBinary(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="QUEUED"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("played_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["sender_user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["target_device_id"], ["devices.id"], ondelete="SET NULL"),
    )
    op.create_index(
        "ix_intercom_announcements_sender_created",
        "intercom_announcements",
        ["sender_user_id", "created_at"],
        unique=False,
    )

    op.create_table(
        "intercom_deliveries",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("announcement_id", sa.String(length=64), nullable=False),
        sa.Column("target_user_id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("played_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["announcement_id"], ["intercom_announcements.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["target_user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], ondelete="CASCADE"),
        sa.UniqueConstraint(
            "announcement_id", "device_id", name="uq_intercom_delivery_announcement_device"
        ),
    )
    op.create_index(
        "ix_intercom_deliveries_user_created",
        "intercom_deliveries",
        ["target_user_id", "created_at"],
        unique=False,
    )

    op.create_table(
        "notes",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(length=180), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_notes_owner_updated", "notes", ["owner_id", "updated_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_notes_owner_updated", table_name="notes")
    op.drop_table("notes")
    op.drop_index("ix_intercom_deliveries_user_created", table_name="intercom_deliveries")
    op.drop_table("intercom_deliveries")
    op.drop_index("ix_intercom_announcements_sender_created", table_name="intercom_announcements")
    op.drop_table("intercom_announcements")
    op.drop_table("intercom_consents")
    op.drop_index("ix_tool_calls_owner_status", table_name="pending_tool_calls")
    op.drop_table("pending_tool_calls")
    op.drop_index("ix_used_nonces_expires", table_name="used_nonces")
    op.drop_table("used_nonces")
    op.drop_table("unlock_targets")
    op.drop_index("ix_automation_rules_owner_enabled", table_name="automation_rules")
    op.drop_table("automation_rules")
    op.drop_index("ix_resource_devices_owner_online", table_name="resource_devices")
    op.drop_table("resource_devices")
    op.drop_table("tool_toggles")
    op.drop_table("system_state")
    op.drop_index("ix_auth_sessions_user_device", table_name="auth_sessions")
    op.drop_table("auth_sessions")
    op.drop_index("ix_audit_logs_subject_created_at", table_name="audit_logs")
    with op.batch_alter_table("audit_logs") as batch:
        batch.add_column(sa.Column("target_type", sa.String(length=80), nullable=True))
        batch.add_column(sa.Column("target_id", sa.String(length=128), nullable=True))
        batch.add_column(
            sa.Column("details", sa.JSON(), nullable=False, server_default=sa.text("'{}'"))
        )
        batch.drop_column("metadata")
        batch.drop_column("detail")
        batch.drop_column("outcome")
        batch.drop_column("risk_tier")
        batch.drop_column("target")
        batch.drop_column("device_id")
        batch.drop_column("subject_user_id")
    op.drop_index("ix_pairing_requests_public_key_created", table_name="pairing_requests")
    with op.batch_alter_table("pairing_requests") as batch:
        batch.drop_constraint("fk_pairing_requests_device_id_devices", type_="foreignkey")
        batch.drop_column("device_key_ciphertext")
        batch.drop_column("device_id")
        batch.drop_column("fingerprint")
        batch.drop_column("poll_challenge")
        batch.drop_column("device_public_id")
        batch.drop_column("platform")
        batch.alter_column(
            "owner_id", existing_type=sa.Uuid(), existing_nullable=True, nullable=False
        )
    with op.batch_alter_table("devices") as batch:
        batch.drop_constraint("uq_devices_public_id", type_="unique")
        batch.drop_column("paired_at")
        batch.drop_column("revoked_at")
        batch.drop_column("firmware")
        batch.drop_column("kind")
        batch.drop_column("site")
        batch.drop_column("device_key_hash")
        batch.drop_column("platform")
        batch.drop_column("public_id")
    with op.batch_alter_table("users") as batch:
        batch.drop_constraint("uq_users_username", type_="unique")
        batch.drop_constraint("uq_users_public_id", type_="unique")
        batch.add_column(
            sa.Column("role", sa.String(length=32), nullable=False, server_default="user")
        )
        batch.drop_column("locked_until")
        batch.drop_column("failed_login_count")
        batch.drop_column("preferred_language")
        batch.drop_column("roles")
        batch.drop_column("display_name")
        batch.drop_column("username")
        batch.drop_column("public_id")
