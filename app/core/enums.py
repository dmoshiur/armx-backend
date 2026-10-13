# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Domain enumerations.

Stored as ``VARCHAR`` (``native_enum=False``) so the same schema works on SQLite for local
development and PostgreSQL/Supabase in production, and so adding a member never requires a
database type migration.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = [
    "ApprovalStatus",
    "AuditOutcome",
    "AuditSource",
    "DeviceKind",
    "DeviceStatus",
    "EmailTokenPurpose",
    "JobStatus",
    "LinkedDeviceStatus",
    "MemoryKind",
    "MemoryScope",
    "MessagingChannel",
    "PairingStatus",
    "PermissionSubject",
    "Role",
    "SystemFlagKey",
]


class Role(StrEnum):
    """Account roles. Order matters for hierarchical checks."""

    USER = "user"
    VIP = "vip"
    ADMIN = "admin"

    @property
    def rank(self) -> int:
        return {"user": 1, "vip": 2, "admin": 3}[self.value]

    def at_least(self, other: Role) -> bool:
        return self.rank >= other.rank


class DeviceKind(StrEnum):
    MOBILE = "mobile"
    DESKTOP = "desktop"
    TABLET = "tablet"
    ESP32 = "esp32"
    KIOSK = "kiosk"
    SERVER = "server"
    UNKNOWN = "unknown"


class DeviceStatus(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    REVOKED = "revoked"


class LinkedDeviceStatus(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    UNLINKED = "unlinked"
    REVOKED = "revoked"


class PairingStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CONSUMED = "consumed"


class AuditOutcome(StrEnum):
    """One row per tool call, whatever happened to it."""

    ALLOWED = "allowed"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    DENIED = "denied"
    FAILED = "failed"
    DRY_RUN = "dry_run"
    SUCCEEDED = "succeeded"
    CANCELLED = "cancelled"


class AuditSource(StrEnum):
    API = "api"
    WORKER = "worker"
    SYSTEM = "system"
    WEBHOOK = "webhook"
    SCHEDULE = "schedule"


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class EmailTokenPurpose(StrEnum):
    VERIFY_EMAIL = "verify_email"
    RESET_PASSWORD = "reset_password"  # noqa: S105 - an enum member, not a credential


class MemoryScope(StrEnum):
    USER = "user"
    CONVERSATION = "conversation"
    TOPIC = "topic"


class MemoryKind(StrEnum):
    FACT = "fact"
    PREFERENCE = "preference"
    NOTE = "note"


class MessagingChannel(StrEnum):
    WHATSAPP = "whatsapp"
    MESSENGER = "messenger"


class PermissionSubject(StrEnum):
    """Who a tool permission row applies to."""

    GLOBAL = "global"
    ROLE = "role"
    USER = "user"


class SystemFlagKey(StrEnum):
    """
    Named runtime switches.

    ``KILL_SWITCH`` is read by the Security Gateway before every single tool call and is
    never consulted through the LLM, so engaging it cannot be talked out of.
    """

    KILL_SWITCH = "kill_switch"
    MAINTENANCE_MODE = "maintenance_mode"
    LLM_ENABLED = "llm_enabled"
