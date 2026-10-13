# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Declarative base, shared column types, and mixins.

Design notes:

* Primary keys are UUIDs, stored natively on PostgreSQL and as ``CHAR(32)`` on SQLite.
  They are generated application-side so a row's identity is known before it is flushed
  (needed for audit rows written alongside a request).
* Timestamps are always timezone-aware UTC.
* Enumerations are stored as short strings via :class:`EnumStr`, which keeps SQLite and
  PostgreSQL schemas identical and lets a new enum member ship without a type migration.
* No ORM ``relationship()`` graphs. Every query is explicit, which removes lazy-loading
  surprises from the async paths and keeps request latency predictable.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any, TypeVar

from sqlalchemy import JSON, DateTime, MetaData, String, TypeDecorator, Uuid
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.core.time import utcnow

__all__ = [
    "Base",
    "EnumStr",
    "JSONType",
    "TimestampMixin",
    "UUIDPrimaryKeyMixin",
    "new_uuid",
]

#: Deterministic names for indexes and constraints, so Alembic autogenerate diffs cleanly
#: and a constraint can be dropped by name on PostgreSQL.
NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

#: JSON on SQLite, JSONB on PostgreSQL (indexable, faster equality).
JSONType = JSON().with_variant(postgresql.JSONB(), "postgresql")


class UtcDateTime(TypeDecorator[datetime]):
    """
    ``timestamp with time zone`` that always returns aware UTC.

    SQLite has no timezone type: values come back naive. Rather than sprinkle "assume UTC"
    through the code - where a single missed comparison becomes a TypeError in development and a
    silent offset bug in production - the conversion happens once, here. Bind values are
    normalised to UTC, and results are tagged as UTC when the dialect drops the offset.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            # Only reachable from raw SQL or a driver that strips tzinfo; treat as UTC.
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


#: Timestamp column type used by every model.
TimestampType = UtcDateTime()

_E = TypeVar("_E", bound=Enum)


class EnumStr(TypeDecorator[_E]):
    """
    Store an enum member as text in a short ``VARCHAR`` column.

    Works for both ``StrEnum`` (role, status) and ``IntEnum`` (risk tiers) because the stored
    representation is always the member's *value* rendered as text; parsing back matches on that
    text, so a PostgreSQL ``TEXT`` column and a SQLite ``VARCHAR`` behave identically.
    """

    impl = String
    cache_ok = True

    def __init__(self, enum_cls: type[_E], length: int = 32) -> None:
        self.enum_cls = enum_cls
        super().__init__(length=length)

    def process_bind_param(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        # Accept a member, or the raw value the client/database produced (int or str).
        if isinstance(value, self.enum_cls):
            return str(value.value)
        try:
            return str(self.enum_cls(value).value)
        except ValueError:
            return str(value)

    def process_result_value(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, self.enum_cls):
            return value
        text = str(value)
        # Match on the rendered value so an IntEnum column survives a round trip through a
        # text column ("1" -> Risk.LOW, never a silent default).
        for member in self.enum_cls:
            if str(member.value) == text:
                return member
        raise ValueError(f"{value!r} is not a valid {self.enum_cls.__qualname__}")

    def copy(self, **kw: Any) -> EnumStr[_E]:  # pragma: no cover - SQLAlchemy plumbing
        return EnumStr(self.enum_cls, self.length)


class Base(DeclarativeBase):
    """Declarative base with deterministic constraint names for Alembic autogenerate."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        identifier = getattr(self, "id", None)
        return f"<{type(self).__name__} id={identifier}>"


def new_uuid() -> uuid.UUID:
    """UUIDv4 primary key generator."""
    return uuid.uuid4()


class UUIDPrimaryKeyMixin:
    """``id`` UUID primary key, application-generated."""

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=new_uuid)


class TimestampMixin:
    """``created_at`` / ``updated_at``, both timezone-aware UTC."""

    created_at: Mapped[datetime] = mapped_column(
        TimestampType, nullable=False, default=utcnow, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        TimestampType, nullable=False, default=utcnow, onupdate=utcnow
    )
