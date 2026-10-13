# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
SQLAlchemy models - the complete A.R.M.X AI data model.

Every write path in the application goes through these tables. Two rules shape them:

1. **Nothing secret is stored in a readable form.** Passwords are argon2id hashes, refresh
   tokens and pairing keys are hashes, device owner passwords are hashes scoped to a single
   link record, and ``integration_connections`` stores *references* to secrets (env var
   names), never values.
2. **Every authorization-relevant action is attributable.** ``audit_events`` carries the
   actor, device, session, tool version, canonical argument hash, risk tier and outcome,
   plus the registry snapshot that defined the tool at the time.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import (
    ApprovalStatus,
    AuditOutcome,
    AuditSource,
    DeviceKind,
    DeviceStatus,
    EmailTokenPurpose,
    JobStatus,
    LinkedDeviceStatus,
    MemoryKind,
    MemoryScope,
    MessagingChannel,
    PairingStatus,
    PermissionSubject,
    Role,
    SystemFlagKey,
)
from app.core.risk import Risk
from app.db.base import (
    Base,
    EnumStr,
    JSONType,
    TimestampMixin,
    TimestampType,
    UUIDPrimaryKeyMixin,
)

__all__ = [
    "Approval",
    "AuditEvent",
    "AutomationRule",
    "Device",
    "DeviceKey",
    "DeviceUnlinkEvent",
    "EmailToken",
    "GuestConsent",
    "ImageAsset",
    "IntegrationConnection",
    "Job",
    "LinkedDevice",
    "MailOutboxMessage",
    "MemoryItem",
    "MessagingInboundEvent",
    "MessagingProfile",
    "PairingSession",
    "RateLimitCounter",
    "RefreshToken",
    "RegistrySnapshot",
    "RuleExecutionHistory",
    "Session",
    "SiteBuild",
    "SystemFlag",
    "ToolDefinition",
    "ToolPermission",
    "UsedNonce",
    "User",
]


# =============================================================== accounts & auth
class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """An account. The first Admin is created by ``python -m app.cli.create_admin``."""

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    role: Mapped[Role] = mapped_column(EnumStr(Role, 16), nullable=False, default=Role.USER)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    email_verified_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)
    google_sub: Mapped[str | None] = mapped_column(
        String(255), nullable=True, unique=True, index=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    session_epoch: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )  # bumped to invalidate every access token for the user at once

    __table_args__ = (Index("ix_users_role_active", "role", "is_active"),)

    @property
    def is_email_verified(self) -> bool:
        return self.email_verified_at is not None


class Session(UUIDPrimaryKeyMixin, Base):
    """
    One row per signed-in device.

    Admins can list and revoke any session; a user can revoke their own other sessions.
    Revoking a session immediately invalidates its refresh tokens (cascade) and, via
    ``revoked_at``, every access token minted for it.
    """

    __tablename__ = "sessions"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True
    )
    label: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    user_agent: Mapped[str] = mapped_column(String(400), nullable=False, default="")
    ip_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TimestampType,
        nullable=False,
        default=lambda: __import__("app.core.time", fromlist=["utcnow"]).utcnow(),
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(String(120), nullable=True)

    __table_args__ = (Index("ix_sessions_user_active", "user_id", "revoked_at"),)


class RefreshToken(UUIDPrimaryKeyMixin, Base):
    """
    Rotating refresh token, stored as a hash.

    Reuse of an already-rotated token is treated as theft: the whole session is revoked and
    a ``token_reuse_detected`` audit event is written.
    """

    __tablename__ = "refresh_tokens"

    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    issued_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)
    rotated_from_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("refresh_tokens.id", ondelete="SET NULL"), nullable=True
    )


class EmailToken(UUIDPrimaryKeyMixin, Base):
    """Single-use, short-expiry email verification or password reset token (hash only)."""

    __tablename__ = "email_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    purpose: Mapped[EmailTokenPurpose] = mapped_column(
        EnumStr(EmailTokenPurpose, 32), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)
    ip_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (Index("ix_email_tokens_user_purpose", "user_id", "purpose"),)


# =========================================================== devices and links
class Device(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """
    A registered device: a phone, a desktop agent, an ESP32 node, a kiosk.

    ``public_key`` holds the Ed25519 public key used for signed device assertions and for
    the PC-unlock token protocol. The private key never leaves the device.
    """

    __tablename__ = "devices"

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    kind: Mapped[DeviceKind] = mapped_column(
        EnumStr(DeviceKind, 16), nullable=False, default=DeviceKind.UNKNOWN
    )
    platform: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    public_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[DeviceStatus] = mapped_column(
        EnumStr(DeviceStatus, 16), nullable=False, default=DeviceStatus.PENDING, index=True
    )
    app_version: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    last_active_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)

    __table_args__ = (Index("ix_devices_owner_status", "owner_user_id", "status"),)


class DeviceKey(UUIDPrimaryKeyMixin, Base):
    """
    Long-lived device credential (headless clients that cannot run the signed-assertion
    flow). Only the hash is stored; ``key_prefix`` is the public lookup id.
    """

    __tablename__ = "device_keys"

    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    key_prefix: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    secret_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    label: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    scopes: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)


class LinkedDevice(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """
    A consent-based link between a device owner and an Admin/VIP account.

    The owner sets a password *at pairing time*; only its argon2 hash is stored, scoped to
    this row, and it is verified solely against the same device session that created it.
    There is deliberately no endpoint - admin or otherwise - that can read, reset or
    override it. Unlinking destroys ``pairing_key_hash``, so re-linking requires a fresh
    pairing rather than the old password.
    """

    __tablename__ = "linked_devices"

    device_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    owner_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    linked_to_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[LinkedDeviceStatus] = mapped_column(
        EnumStr(LinkedDeviceStatus, 16),
        nullable=False,
        default=LinkedDeviceStatus.PENDING,
        index=True,
    )
    label: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    pairing_key_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    owner_password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    owner_password_set_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)
    last_active_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)
    unlinked_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)
    unlink_reason: Mapped[str | None] = mapped_column(String(200), nullable=True)

    __table_args__ = (
        # A device can only be actively linked to one account at a time.
        Index(
            "uq_linked_devices_active_device",
            "device_id",
            unique=True,
            postgresql_where=text("status = 'active'"),
            sqlite_where=text("status = 'active'"),
        ),
        Index("ix_linked_devices_owner", "owner_user_id", "status"),
        Index("ix_linked_devices_linked_to", "linked_to_user_id", "status"),
    )


class DeviceUnlinkEvent(UUIDPrimaryKeyMixin, Base):
    """Audit trail for link/unlink attempts, including failed owner-password checks."""

    __tablename__ = "device_unlink_events"

    linked_device_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("linked_devices.id", ondelete="SET NULL"), nullable=True, index=True
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), nullable=True
    )
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    outcome: Mapped[str] = mapped_column(String(48), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(200), nullable=True)
    ip_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False, index=True)


class PairingSession(UUIDPrimaryKeyMixin, Base):
    """
    A one-time pairing exchange started by the device owner (QR code or short code) and
    approved either on the owner's own device or by an admin decision endpoint.
    """

    __tablename__ = "pairing_sessions"

    code_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    device_name: Mapped[str] = mapped_column(String(120), nullable=False)
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), nullable=True
    )
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    status: Mapped[PairingStatus] = mapped_column(
        EnumStr(PairingStatus, 16), nullable=False, default=PairingStatus.PENDING, index=True
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    expires_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False)
    approved_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)
    approved_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    linked_device_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("linked_devices.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False, index=True)


# ========================================================= registry & approvals
class RegistrySnapshot(UUIDPrimaryKeyMixin, Base):
    """Versioned snapshot of the whole tool registry; referenced by every audit row."""

    __tablename__ = "registry_snapshots"

    revision: Mapped[int] = mapped_column(Integer, nullable=False, unique=True, index=True)
    snapshot_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    tool_count: Mapped[int] = mapped_column(Integer, nullable=False)
    manifest: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, nullable=False)
    created_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False, index=True)


class ToolDefinition(UUIDPrimaryKeyMixin, Base):
    """
    The registry's durable mirror of each tool manifest.

    ``enabled`` is the operator switch. A disabled tool is refused by the Security Gateway
    *before* the tool function is ever imported into the call path - the tool itself never
    has to check, and therefore cannot forget to.
    """

    __tablename__ = "tool_definitions"

    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    version: Mapped[str] = mapped_column(String(16), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    risk: Mapped[Risk] = mapped_column(EnumStr(Risk, 16), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    default_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    category: Mapped[str] = mapped_column(String(32), nullable=False, default="general")
    integration: Mapped[str | None] = mapped_column(String(32), nullable=True)
    required_scopes: Mapped[list[str]] = mapped_column(JSONType, nullable=False, default=list)
    confirm_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    rate_limit: Mapped[str] = mapped_column(String(32), nullable=False, default="60/hour")
    dry_run_supported: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    timeout_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    input_schema: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False)
    output_schema: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False)
    registry_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("registry_snapshots.id", ondelete="SET NULL"), nullable=True
    )
    registered_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False)
    updated_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class ToolPermission(UUIDPrimaryKeyMixin, Base):
    """
    Per-tool permission overrides.

    ``subject_type`` is ``global``, a role name, or a user id, so one table covers the
    three levels the admin API exposes (global / per-role / per-user toggles).
    """

    __tablename__ = "tool_permissions"

    tool_name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    subject_type: Mapped[PermissionSubject] = mapped_column(
        EnumStr(PermissionSubject, 16), nullable=False
    )
    subject_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    allowed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    rate_limit_override: Mapped[str | None] = mapped_column(String(32), nullable=True)
    reason: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    __table_args__ = (
        UniqueConstraint(
            "tool_name", "subject_type", "subject_id", name="uq_tool_permissions_subject"
        ),
    )


class Approval(UUIDPrimaryKeyMixin, Base):
    """
    A fresh, exact-action approval.

    ``action_hash`` is the canonical hash of tool name + version + arguments + actor +
    device + session + nonce + expiry. Execution recomputes the hash from the arguments it
    is about to use, so changing a single argument invalidates the approval. Rows are
    single-use: the consume step is an atomic compare-and-set on ``status``.
    """

    __tablename__ = "approvals"

    tool_name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tool_version: Mapped[str] = mapped_column(String(16), nullable=False)
    risk: Mapped[Risk] = mapped_column(EnumStr(Risk, 16), nullable=False)
    action_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    arguments_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    arguments_redacted: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False)
    summary: Mapped[str] = mapped_column(String(400), nullable=False, default="")
    actor_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), nullable=True
    )
    session_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sessions.id", ondelete="SET NULL"), nullable=True
    )
    trace_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    nonce: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    status: Mapped[ApprovalStatus] = mapped_column(
        EnumStr(ApprovalStatus, 16), nullable=False, default=ApprovalStatus.PENDING, index=True
    )
    single_use: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False, index=True)
    decided_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)
    decided_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    deny_reason: Mapped[str | None] = mapped_column(String(200), nullable=True)
    consumed_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(80), nullable=True)
    registry_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("registry_snapshots.id", ondelete="SET NULL"), nullable=True
    )

    __table_args__ = (
        Index("ix_approvals_actor_status", "actor_user_id", "status"),
        Index("ix_approvals_tool_action", "tool_name", "action_hash"),
    )


class AuditEvent(UUIDPrimaryKeyMixin, Base):
    """
    One row per tool call, without exception: allowed, pending, denied, failed, dry-run or
    succeeded. This is the table an incident review reads, so it records the *decision*
    inputs (risk tier, registry snapshot, canonical argument hash) rather than just the
    result.
    """

    __tablename__ = "audit_events"

    occurred_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False, index=True)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    actor_role: Mapped[Role | None] = mapped_column(EnumStr(Role, 16), nullable=True)
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True
    )
    session_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sessions.id", ondelete="SET NULL"), nullable=True
    )
    tool_name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tool_version: Mapped[str] = mapped_column(String(16), nullable=False, default="")
    risk: Mapped[Risk] = mapped_column(EnumStr(Risk, 16), nullable=False)
    source: Mapped[AuditSource] = mapped_column(
        EnumStr(AuditSource, 16), nullable=False, default=AuditSource.API
    )
    dry_run: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    arguments_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    arguments_redacted: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False)
    outcome: Mapped[AuditOutcome] = mapped_column(
        EnumStr(AuditOutcome, 24), nullable=False, index=True
    )
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result_summary: Mapped[str | None] = mapped_column(String(600), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    trace_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    approval_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("approvals.id", ondelete="SET NULL"), nullable=True
    )
    idempotency_key: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    registry_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("registry_snapshots.id", ondelete="SET NULL"), nullable=True
    )
    ip_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index("ix_audit_events_actor_time", "actor_user_id", "occurred_at"),
        Index("ix_audit_events_tool_time", "tool_name", "occurred_at"),
        Index("ix_audit_events_outcome_time", "outcome", "occurred_at"),
    )


# ================================================================= integrations
class IntegrationConnection(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """
    Operator metadata about a configured integration.

    ``secret_ref`` names the environment variable (or secrets-manager path) that holds the
    credential - the credential itself is never stored here, and the API validates that the
    field looks like a reference rather than a secret.
    """

    __tablename__ = "integration_connections"

    provider: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    secret_ref: Mapped[str | None] = mapped_column(String(120), nullable=True)
    config: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_health_check_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)
    last_health_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    notes: Mapped[str | None] = mapped_column(String(400), nullable=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    __table_args__ = (UniqueConstraint("provider", "display_name", name="uq_integration_name"),)


# ===================================================================== memory
class MemoryItem(UUIDPrimaryKeyMixin, Base):
    """
    A single remembered item. Content is encrypted at rest and expires; deletion is a hard
    requirement, not a soft flag alone, so ``deleted_at`` is complemented by a purge job.
    """

    __tablename__ = "memory_items"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scope: Mapped[MemoryScope] = mapped_column(EnumStr(MemoryScope, 16), nullable=False)
    kind: Mapped[MemoryKind] = mapped_column(EnumStr(MemoryKind, 16), nullable=False)
    conversation_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    content_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    content_preview: Mapped[str] = mapped_column(String(160), nullable=False, default="")
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(48), nullable=False, default="user")
    importance: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    created_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True, index=True)
    deleted_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)


# ================================================================== automation
class AutomationRule(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """
    A stored automation rule.

    ``dry_run_only`` defaults to True: rules are evaluated and reported, never actuated,
    until an operator explicitly arms them.
    """

    __tablename__ = "automation_rules"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    trigger: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False)
    action: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    dry_run_only: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)

    __table_args__ = (UniqueConstraint("user_id", "name", name="uq_automation_rules_user_name"),)


class RuleExecutionHistory(UUIDPrimaryKeyMixin, Base):
    """Outcome of a rule evaluation (or dry run)."""

    __tablename__ = "rule_execution_history"

    rule_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("automation_rules.id", ondelete="CASCADE"), nullable=False, index=True
    )
    executed_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False, index=True)
    outcome: Mapped[str] = mapped_column(String(48), nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    audit_event_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("audit_events.id", ondelete="SET NULL"), nullable=True
    )


# ====================================================================== guests
class GuestConsent(UUIDPrimaryKeyMixin, Base):
    """
    Opt-in guest enrolment.

    Only created for a guest who personally opted in through an owner-operated device. There
    is no code path that creates a consent row from an unknown face, and no feature in this
    backend performs face identification of anyone who has not opted in.
    """

    __tablename__ = "guest_consents"

    granted_by_user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True
    )
    guest_label: Mapped[str] = mapped_column(String(120), nullable=False)
    consent_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="greet")
    consent_reference: Mapped[str | None] = mapped_column(String(120), nullable=True)
    notes: Mapped[str | None] = mapped_column(String(400), nullable=True)
    created_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False, index=True)
    expires_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)


# ==================================================================== messaging
class MessagingProfile(UUIDPrimaryKeyMixin, Base):
    """
    Per-contact personality/tone profile and the auto-send switch.

    ``auto_send=false`` (the default) means the assistant may only draft: the reply is
    stored for review and never sent. Sending as the owner is a HIGH-risk tool call and
    still requires its own approval even when ``auto_send`` is true.
    """

    __tablename__ = "messaging_profiles"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    channel: Mapped[MessagingChannel] = mapped_column(EnumStr(MessagingChannel, 24), nullable=False)
    contact_ref: Mapped[str] = mapped_column(String(120), nullable=False)
    contact_display_name: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    tone: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    auto_send: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False)

    __table_args__ = (
        UniqueConstraint("user_id", "channel", "contact_ref", name="uq_messaging_profiles_contact"),
    )


class MessagingInboundEvent(UUIDPrimaryKeyMixin, Base):
    """
    Raw inbound webhook event from WhatsApp/Messenger.

    Stored only after the signature is verified; ``provider_event_id`` is unique so a
    redelivered event cannot trigger a second action.
    """

    __tablename__ = "messaging_inbound_events"

    channel: Mapped[MessagingChannel] = mapped_column(EnumStr(MessagingChannel, 24), nullable=False)
    provider_event_id: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    signature_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    payload_redacted: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    profile_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("messaging_profiles.id", ondelete="SET NULL"), nullable=True
    )
    received_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False, index=True)
    processed_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)
    error: Mapped[str | None] = mapped_column(String(200), nullable=True)


# ==================================================== runtime state & operations
class SystemFlag(UUIDPrimaryKeyMixin, Base):
    """
    Named runtime switches.

    The kill-switch lives here. The Security Gateway reads it from the database on every
    tool call, so engaging it takes effect immediately and does not depend on the LLM, on
    a client, or on any biometric check.
    """

    __tablename__ = "system_flags"

    key: Mapped[SystemFlagKey] = mapped_column(
        EnumStr(SystemFlagKey, 32), nullable=False, unique=True, index=True
    )
    value: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    reason: Mapped[str | None] = mapped_column(String(200), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False)
    updated_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class RateLimitCounter(UUIDPrimaryKeyMixin, Base):
    """
    Fixed-window rate-limit counter.

    Stored in the primary database (Postgres/Supabase) rather than in a separate cache
    service, so there is exactly one source of truth for "how many times has this actor
    called this tool in this window" and rate limiting cannot drift between workers.
    """

    __tablename__ = "rate_limit_counters"

    key: Mapped[str] = mapped_column(String(200), nullable=False, unique=True, index=True)
    window_start: Mapped[int] = mapped_column(BigInteger, nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    expires_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False, index=True)


class Job(UUIDPrimaryKeyMixin, Base):
    """
    Durable background job.

    Slow integration calls (site deploy, n8n invocation, image editing) run in the worker
    process. Workers claim rows with ``SELECT ... FOR UPDATE SKIP LOCKED`` on PostgreSQL, so
    two workers can never run the same job, and a crashed worker's claim expires.
    """

    __tablename__ = "jobs"

    kind: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[JobStatus] = mapped_column(
        EnumStr(JobStatus, 16), nullable=False, default=JobStatus.QUEUED, index=True
    )
    tool_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    risk: Mapped[Risk | None] = mapped_column(EnumStr(Risk, 16), nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(String(400), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    idempotency_key: Mapped[str | None] = mapped_column(
        String(80), nullable=True, unique=True, index=True
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    session_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sessions.id", ondelete="SET NULL"), nullable=True
    )
    trace_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    approval_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("approvals.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False, index=True)
    available_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False, index=True)
    started_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)
    locked_by: Mapped[str | None] = mapped_column(String(80), nullable=True)
    lock_expires_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)

    __table_args__ = (Index("ix_jobs_status_available", "status", "available_at"),)


class MailOutboxMessage(UUIDPrimaryKeyMixin, Base):
    """
    Outbound email.

    With ``EMAIL_DELIVERY_MODE=outbox`` (the default outside production) messages are
    recorded here instead of being sent, which makes signup and password-reset testable end
    to end without an SMTP server. The message body never contains a stored credential: the
    single-use token is in the link the user follows and the row keeps no copy of it beyond
    the delivered text.
    """

    __tablename__ = "mail_outbox"

    to_address: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    subject: Mapped[str] = mapped_column(String(200), nullable=False)
    body_text: Mapped[str] = mapped_column(Text, nullable=False)
    template: Mapped[str] = mapped_column(String(64), nullable=False, default="generic")
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="queued", index=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error: Mapped[str | None] = mapped_column(String(300), nullable=True)
    meta: Mapped[dict[str, Any]] = mapped_column(JSONType, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False, index=True)
    sent_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True)


class UsedNonce(UUIDPrimaryKeyMixin, Base):
    """
    Replay protection for signed assertions, webhook deliveries and approval nonces.

    Insertion is the check: a unique constraint on ``nonce_hash`` means the second use of
    the same nonce fails, even across concurrent requests and workers.
    """

    __tablename__ = "used_nonces"

    nonce_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    scope: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False, index=True)


class ImageAsset(UUIDPrimaryKeyMixin, Base):
    """
    An image that was stored for editing or as an edit result.

    Only metadata and a storage reference are kept: image content is never logged, and the
    asset expires.
    """

    __tablename__ = "image_assets"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source: Mapped[str] = mapped_column(String(24), nullable=False, default="upload")
    provider: Mapped[str] = mapped_column(String(32), nullable=False, default="mock")
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="ready", index=True)
    mime: Mapped[str] = mapped_column(String(64), nullable=False, default="image/png")
    byte_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    width: Mapped[int | None] = mapped_column(Integer, nullable=True)
    height: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    storage_ref: Mapped[str | None] = mapped_column(String(300), nullable=True)
    error: Mapped[str | None] = mapped_column(String(300), nullable=True)
    created_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False, index=True)
    expires_at: Mapped[datetime | None] = mapped_column(TimestampType, nullable=True, index=True)


class SiteBuild(UUIDPrimaryKeyMixin, Base):
    """
    A generated static site inside the sandbox, and its deploy state.

    ``deployment_url`` is only ever written after the provider confirms the deployment, so a
    stored URL means it was verified, not merely requested.
    """

    __tablename__ = "site_builds"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="generated", index=True)
    title: Mapped[str] = mapped_column(String(160), nullable=False, default="")
    prompt_summary: Mapped[str] = mapped_column(String(400), nullable=False, default="")
    sandbox_path: Mapped[str | None] = mapped_column(String(300), nullable=True)
    manifest: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, nullable=False, default=list)
    repo: Mapped[str | None] = mapped_column(String(200), nullable=True)
    branch: Mapped[str | None] = mapped_column(String(120), nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    deployment_url: Mapped[str | None] = mapped_column(String(300), nullable=True)
    deploy_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    deploy_provider: Mapped[str | None] = mapped_column(String(32), nullable=True)
    approved_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("jobs.id", ondelete="SET NULL"), nullable=True
    )
    error: Mapped[str | None] = mapped_column(String(300), nullable=True)
    created_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(TimestampType, nullable=False)
