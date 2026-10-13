# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Database URL normalisation.

This file exists because of a production-blocking bug the PostgreSQL CI job caught: the app
normalises an operator's ``DATABASE_URL`` to the async driver it ships, and the normaliser then
rejected its own output. SQLite hid it completely (``sqlite+aiosqlite://`` was an accepted input),
so the whole suite was green while ``ENVIRONMENT=production DATABASE_URL=postgresql://…`` could not
start. The rule these tests enforce is idempotence: normalising an already-normalised URL returns
the same URL, whatever the caller passed in.
"""

from __future__ import annotations

import pytest

from app.db.urls import (
    POSTGRES_DRIVER,
    async_database_url,
    is_postgres,
    is_sqlite,
    redacted_database_url,
    sqlite_file_path,
    sync_database_url,
)

POSTGRES_FORMS = [
    "postgresql://user:pw@host:5432/db",
    "postgres://user:pw@host:5432/db",
    f"postgresql+{POSTGRES_DRIVER}://user:pw@host:5432/db",
    "postgresql+asyncpg://user:pw@host:5432/db",
    "postgresql+psycopg2://user:pw@host:5432/db",
]


@pytest.mark.parametrize("url", POSTGRES_FORMS)
def test_every_postgres_form_normalises_to_the_shipped_driver(url: str) -> None:
    normalised = async_database_url(url)
    assert normalised.startswith(f"postgresql+{POSTGRES_DRIVER}://")
    assert "user:pw@host:5432/db" in normalised


@pytest.mark.parametrize("url", POSTGRES_FORMS)
def test_normalisation_is_idempotent(url: str) -> None:
    once = async_database_url(url)
    assert async_database_url(once) == once


@pytest.mark.parametrize(
    "url",
    ["sqlite:///./data/armx.db", "sqlite+aiosqlite:///./data/armx.db", "sqlite:////srv/armx.db"],
)
def test_sqlite_forms_normalise_and_are_idempotent(url: str) -> None:
    normalised = async_database_url(url)
    assert async_database_url(normalised) == normalised


def test_a_url_without_a_driver_suffix_gains_the_async_one() -> None:
    assert async_database_url("sqlite:///./data/armx.db") == "sqlite+aiosqlite:///./data/armx.db"


def test_a_supabase_transaction_pooler_url_survives_normalisation() -> None:
    """The production shape: a pooler host and port, untouched apart from the driver."""
    # A documented placeholder: the shape of a Supabase pooler URL, with a made-up password.
    url = (
        "postgresql://postgres.abcdefgh:secret"
        "@aws-0-eu-central-1.pooler.supabase.com:6543/postgres"
    )  # secret-scan:allow (a fixture, not a credential)
    normalised = async_database_url(url)
    assert normalised.startswith(f"postgresql+{POSTGRES_DRIVER}://")
    assert ".pooler.supabase.com:6543/postgres" in normalised


def test_the_sync_form_drops_the_async_driver() -> None:
    assert sync_database_url("postgresql+psycopg://u:p@h/db") == "postgresql+psycopg://u:p@h/db"
    assert sync_database_url("sqlite+aiosqlite:///./data/x.db") == "sqlite:///./data/x.db"


def test_dialect_predicates_agree_with_the_normal_form() -> None:
    assert is_postgres("postgresql://u:p@h/db") is True
    assert is_postgres("sqlite:///x.db") is False
    assert is_sqlite("sqlite+aiosqlite:///x.db") is True
    assert is_sqlite("postgresql://u:p@h/db") is False


def test_the_relative_sqlite_path_is_resolved_and_absolute_is_kept() -> None:
    assert str(sqlite_file_path("sqlite:///./data/armx.db")) == "data/armx.db"
    assert str(sqlite_file_path("sqlite:////srv/armx/armx.db")) == "/srv/armx/armx.db"
    assert sqlite_file_path("sqlite:///:memory:") is None


def test_a_redacted_url_never_contains_the_password() -> None:
    redacted = redacted_database_url(
        "postgresql://owner:sup3r-s3cret@host:5432/armx"  # secret-scan:allow (redaction fixture)
    )
    assert "sup3r-s3cret" not in redacted
    assert "owner:***@host:5432" in redacted


@pytest.mark.parametrize(
    "url", ["mysql://user:pw@host/db", "redis://host:6379/0", "not-a-url", "", "://missing"]
)
def test_an_unsupported_url_is_refused_with_a_useful_message(url: str) -> None:
    with pytest.raises(ValueError) as caught:
        async_database_url(url)
    assert str(caught.value), "the error must say what was wrong"
