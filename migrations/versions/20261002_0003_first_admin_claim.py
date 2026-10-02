# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""Persist the one-time first-administrator election."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20261002_0003"
down_revision: str | None = "20261002_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("system_state") as batch:
        batch.add_column(sa.Column("first_admin_user_id", sa.Uuid(), nullable=True))
        batch.add_column(
            sa.Column(
                "initial_admin_claimed", sa.Boolean(), nullable=False, server_default=sa.false()
            )
        )
        batch.create_foreign_key(
            "fk_system_state_first_admin_user_id_users",
            "users",
            ["first_admin_user_id"],
            ["id"],
            ondelete="SET NULL",
        )

    bind = op.get_bind()
    system_state = sa.table(
        "system_state",
        sa.column("id", sa.Integer()),
        sa.column("first_admin_user_id", sa.Uuid()),
        sa.column("initial_admin_claimed", sa.Boolean()),
    )
    users = sa.table(
        "users",
        sa.column("id", sa.Uuid()),
        sa.column("roles", sa.JSON()),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    rows = bind.execute(sa.select(users.c.id, users.c.roles).order_by(users.c.created_at)).all()
    owner_id = next(
        (
            row.id
            for row in rows
            if isinstance(row.roles, list)
            and {str(role).lower() for role in row.roles}.intersection({"owner", "admin"})
        ),
        None,
    )
    if owner_id is not None:
        bind.execute(
            system_state.update()
            .where(system_state.c.id == 1)
            .values(first_admin_user_id=owner_id, initial_admin_claimed=True)
        )


def downgrade() -> None:
    with op.batch_alter_table("system_state") as batch:
        batch.drop_constraint("fk_system_state_first_admin_user_id_users", type_="foreignkey")
        batch.drop_column("initial_admin_claimed")
        batch.drop_column("first_admin_user_id")
