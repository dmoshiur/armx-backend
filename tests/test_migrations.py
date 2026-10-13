# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Migration tests.

These are the tests that keep the two dialects honest: the suite runs on SQLite while
production runs on PostgreSQL, so the schema must be produced by Alembic (not by
``create_all``) and must match the models exactly. The drift check uses Alembic's own
comparator, which is the same code path ``alembic revision --autogenerate`` uses.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect

import app.db.models  # noqa: F401  (registers every table)
from app.db.base import Base

REPO_ROOT = Path(__file__).resolve().parents[1]
HEAD_REVISION = "0001"


@pytest.fixture
def migrated_database(tmp_path: Path) -> Path:
    """Apply every migration to a fresh SQLite database and return its path."""
    database_path = tmp_path / "migrated.db"
    env = {
        **os.environ,
        "ENVIRONMENT": "development",
        "DATABASE_URL": f"sqlite+aiosqlite:///{database_path}",
        "JWT_SECRET_KEY": "migration-test-secret-key-long-enough-value",
    }
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"alembic upgrade failed:\n{result.stdout}\n{result.stderr}"
    return database_path


def test_migrations_create_every_table(migrated_database: Path) -> None:
    engine = create_engine(f"sqlite:///{migrated_database}")
    try:
        table_names = set(inspect(engine).get_table_names())
    finally:
        engine.dispose()

    expected = set(Base.metadata.tables) | {"alembic_version"}
    assert expected <= table_names, f"tables missing from the migration: {expected - table_names}"


def test_migration_revision_is_recorded(migrated_database: Path) -> None:
    engine = create_engine(f"sqlite:///{migrated_database}")
    try:
        with engine.connect() as connection:
            version = connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar()
    finally:
        engine.dispose()
    assert version == HEAD_REVISION


def test_models_and_migrations_do_not_drift(migrated_database: Path) -> None:
    """A model change without a migration would otherwise reach production unnoticed."""
    engine = create_engine(f"sqlite:///{migrated_database}")
    try:
        with engine.connect() as connection:
            context = MigrationContext.configure(
                connection, opts={"compare_type": True, "compare_server_default": True}
            )
            diff = compare_metadata(context, Base.metadata)
    finally:
        engine.dispose()

    assert diff == [], f"schema drift between models and migrations: {diff}"


def test_core_tables_carry_the_expected_columns(migrated_database: Path) -> None:
    """Spot-check the tables the security guarantees depend on."""
    engine = create_engine(f"sqlite:///{migrated_database}")
    try:
        inspector = inspect(engine)
        audit_columns = {column["name"] for column in inspector.get_columns("audit_events")}
        assert {
            "actor_user_id",
            "device_id",
            "tool_name",
            "risk",
            "arguments_hash",
            "outcome",
            "approval_id",
            "registry_snapshot_id",
        } <= audit_columns

        linked_columns = {column["name"] for column in inspector.get_columns("linked_devices")}
        assert {
            "owner_password_hash",
            "pairing_key_hash",
            "owner_user_id",
            "linked_to_user_id",
        } <= linked_columns

        approval_columns = {column["name"] for column in inspector.get_columns("approvals")}
        assert {
            "action_hash",
            "nonce",
            "expires_at",
            "single_use",
            "consumed_at",
        } <= approval_columns
    finally:
        engine.dispose()


def test_secret_bearing_columns_store_hashes_not_values(migrated_database: Path) -> None:
    """No column may look like it holds a raw credential."""
    engine = create_engine(f"sqlite:///{migrated_database}")
    forbidden = {"password", "token", "secret", "api_key", "refresh_token", "client_secret"}
    try:
        inspector = inspect(engine)
        offenders: list[str] = []
        for table in inspector.get_table_names():
            for column in inspector.get_columns(table):
                name = str(column["name"]).lower()
                if name in forbidden:
                    offenders.append(f"{table}.{name}")
    finally:
        engine.dispose()
    assert offenders == [], f"columns that appear to store raw credentials: {offenders}"
