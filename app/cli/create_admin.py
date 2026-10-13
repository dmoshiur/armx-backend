# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Create or promote an account from the server console.

    python -m app.cli.create_admin --email owner@example.com --name "Owner" --role admin

Why a CLI instead of a signup route: the first Admin cannot come from the public signup form,
or an attacker who reaches an unclaimed deployment simply signs up as the owner. This command
runs on the host, writes the user directly, and records an audit row naming the event.

The password is read interactively by default. ``--password-stdin`` exists for automation and
is the only way to pass a password non-interactively; ``--password`` is deliberately absent so a
credential never lands in shell history or a process listing.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
from collections.abc import Coroutine
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select

from app.audit.service import record_event
from app.config import get_settings
from app.core.enums import AuditOutcome, AuditSource, Role
from app.core.logging import configure_logging, get_logger
from app.core.passwords import hash_password, password_policy_error
from app.core.time import utcnow
from app.db.models import User
from app.db.session import dispose_engines, session_scope

__all__ = ["main", "run"]

logger = get_logger("cli.create_admin")


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create the first A.R.M.X AI admin account.")
    parser.add_argument("--email", required=True, help="account email address")
    parser.add_argument("--name", default="", help="display name")
    parser.add_argument("--role", default="admin", choices=[role.value for role in Role])
    parser.add_argument(
        "--password-stdin", action="store_true", help="read the password from stdin"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="in production this flag is required, because the command mutates live data",
    )
    return parser.parse_args(argv)


def _read_password(args: argparse.Namespace) -> str:
    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            raise SystemExit("passwords do not match")
    return password


async def run(args: argparse.Namespace) -> int:
    settings = get_settings()
    email = args.email.strip().lower()
    role = Role(args.role)

    if settings.is_production and not args.force:
        print(
            "Refusing to modify accounts in production without --force.\n"
            "This command writes directly to the live database.",
            file=sys.stderr,
        )
        return 64

    password = _read_password(args)
    policy_error = password_policy_error(
        password, min_length=settings.password_min_length, email=email
    )
    if policy_error:
        print(f"Password rejected: {policy_error}", file=sys.stderr)
        return 65

    async with session_scope() as session:
        existing = (
            await session.execute(select(User).where(User.email == email))
        ).scalar_one_or_none()
        now = utcnow()
        if existing is not None:
            existing.role = role
            existing.password_hash = hash_password(password)
            existing.email_verified_at = existing.email_verified_at or now
            existing.is_active = True
            existing.failed_login_count = 0
            existing.locked_until = None
            existing.updated_at = now
            action = "updated"
            target = existing
        else:
            target = User(
                email=email,
                display_name=args.name or email.split("@")[0],
                role=role,
                password_hash=hash_password(password),
                email_verified_at=now,
                is_active=True,
            )
            session.add(target)
            action = "created"

        await session.flush()
        # Every explicit account action is attributable to somebody, even from the console.
        await record_event(
            session,
            name=f"admin.cli_{action}",
            outcome=AuditOutcome.SUCCEEDED,
            actor_role=role,
            arguments={"email": email, "role": role.value, "action": action},
            result_summary=f"account {action} from the server console",
            source=AuditSource.SYSTEM,
        )
        count = (await session.execute(select(func.count(User.id)))).scalar() or 0

    print(f"{action} {role.value} account: {email}")
    print(f"total accounts: {count}")
    print(
        "Next: sign in, then turn on Google OAuth / email delivery, and rotate "
        "JWT_SECRET_KEY + ENCRYPTION_KEY away from any test values."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    configure_logging(level="WARNING", fmt="console")
    args = _parse_args(argv)
    started = datetime.now(UTC)
    try:
        code = asyncio.run(_with_cleanup(run(args)))
    except KeyboardInterrupt:  # pragma: no cover
        return 130
    logger.info("cli finished in %.1fs", (datetime.now(UTC) - started).total_seconds())
    return code


async def _with_cleanup(coro: Coroutine[Any, Any, int]) -> int:
    try:
        return await coro
    finally:
        await dispose_engines()


if __name__ == "__main__":
    raise SystemExit(main())
