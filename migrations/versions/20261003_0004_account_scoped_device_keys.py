# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

from collections.abc import Sequence

from alembic import op

revision: str = "20261003_0004"
down_revision: str | None = "20261002_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # A device identity belongs to an account. This permits separate accounts to log in
    # from the same app installation without an admin-mediated device transfer.
    bind = op.get_bind()
    sqlite_family = bind.dialect.name in {"sqlite", "libsql"}
    if sqlite_family:
        # SQLite batch mode rebuilds the devices table. Disable FK enforcement around that
        # rewrite so dependent sessions and pairing records survive the temporary drop.
        bind.exec_driver_sql("PRAGMA foreign_keys=OFF")
    try:
        with op.batch_alter_table("devices") as batch:
            batch.drop_constraint("uq_devices_public_key", type_="unique")
            batch.create_unique_constraint(
                "uq_devices_owner_public_key", ["owner_id", "public_key"]
            )
    finally:
        if sqlite_family:
            bind.exec_driver_sql("PRAGMA foreign_keys=ON")


def downgrade() -> None:
    with op.batch_alter_table("devices") as batch:
        batch.drop_constraint("uq_devices_owner_public_key", type_="unique")
        batch.create_unique_constraint("uq_devices_public_key", ["public_key"])
