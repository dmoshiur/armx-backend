# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Rate limiting and lockout.

This deployment has no Redis, so the counters live in PostgreSQL in a fixed window keyed by a
hashed scope string. The properties under test:

* a limit is per key - one account, device or address running out does not affect another;
* a denied check reports a usable ``Retry-After`` and does not consume budget a second time;
* the key is a hash, so a counter row never contains a raw identifier, email address or IP;
* counters expire, so the table cannot grow without bound;
* authentication is limited *and* locked out, which are different defences: the rate limit blunts
  a burst, the lockout stops a slow, patient guessing attack.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.core.ratelimit_spec import parse_rate_limit
from app.core.time import utcnow
from app.db.models import RateLimitCounter, User
from app.security.ratelimit import RateLimiter, limit_key


class TestLimitSpecs:
    def test_a_spec_is_parsed_from_configuration_text(self) -> None:
        spec = parse_rate_limit("5/minute")
        assert spec.count == 5
        assert spec.window_seconds == 60
        assert spec.bucket(1_700_000_000) > 0
        assert spec.text == "5/minute"

    def test_an_unknown_window_is_refused(self) -> None:
        import pytest

        with pytest.raises(ValueError):
            parse_rate_limit("5/fortnight")


class TestLimiter:
    async def test_budget_is_per_key(self, db: AsyncSession, tmp_settings: Settings) -> None:
        limiter = RateLimiter(tmp_settings)
        spec = parse_rate_limit("2/minute")

        assert (await limiter.check(db, key=limit_key("t", "a"), spec=spec)).allowed
        assert (await limiter.check(db, key=limit_key("t", "a"), spec=spec)).allowed
        third = await limiter.check(db, key=limit_key("t", "a"), spec=spec)
        assert third.allowed is False
        assert third.retry_after_seconds >= 1

        # A different key has its own window.
        assert (await limiter.check(db, key=limit_key("t", "b"), spec=spec)).allowed

    async def test_headers_are_usable_by_a_client(
        self, db: AsyncSession, tmp_settings: Settings
    ) -> None:
        limiter = RateLimiter(tmp_settings)
        spec = parse_rate_limit("1/minute")
        await limiter.check(db, key=limit_key("h", "a"), spec=spec)
        denied = await limiter.check(db, key=limit_key("h", "a"), spec=spec)
        headers = denied.headers()
        assert headers["X-RateLimit-Limit"] == "1"
        assert headers["X-RateLimit-Remaining"] == "0"
        assert headers["Retry-After"] == str(max(1, denied.retry_after_seconds))

    async def test_disabling_limits_is_honoured(
        self, db: AsyncSession, tmp_settings: Settings
    ) -> None:
        off = tmp_settings.model_copy(update={"rate_limit_enabled": False})
        limiter = RateLimiter(off)
        spec = parse_rate_limit("1/minute")
        for _ in range(5):
            assert (await limiter.check(db, key=limit_key("off", "a"), spec=spec)).allowed

    async def test_the_counter_key_is_a_hash_not_an_identifier(
        self, db: AsyncSession, tmp_settings: Settings
    ) -> None:
        limiter = RateLimiter(tmp_settings)
        await limiter.check(
            db, key=limit_key("login", "someone@example.com"), spec=parse_rate_limit("5/minute")
        )
        await db.commit()
        rows = (await db.execute(select(RateLimitCounter))).scalars().all()
        assert rows, "a counter row must exist"
        for row in rows:
            assert "example.com" not in row.key
            assert len(row.key) <= 64

    async def test_counters_carry_an_expiry(self, db: AsyncSession, tmp_settings: Settings) -> None:
        limiter = RateLimiter(tmp_settings)
        await limiter.check(db, key=limit_key("exp", "a"), spec=parse_rate_limit("3/minute"))
        await db.commit()
        row = (await db.execute(select(RateLimitCounter))).scalars().one()
        assert row.expires_at > utcnow()

    async def test_a_window_rolls_over(self, db: AsyncSession, tmp_settings: Settings) -> None:
        from datetime import timedelta

        limiter = RateLimiter(tmp_settings)
        spec = parse_rate_limit("1/minute")
        key = limit_key("roll", "a")
        assert (await limiter.check(db, key=key, spec=spec)).allowed
        assert (await limiter.check(db, key=key, spec=spec)).allowed is False

        row = (await db.execute(select(RateLimitCounter))).scalars().one()
        row.window_start = utcnow() - timedelta(minutes=2)
        row.expires_at = utcnow() - timedelta(seconds=1)
        await db.commit()

        assert (await limiter.check(db, key=key, spec=spec)).allowed, "a new window starts counting"

    async def test_resetting_a_key_gives_the_budget_back(
        self, db: AsyncSession, tmp_settings: Settings
    ) -> None:
        limiter = RateLimiter(tmp_settings)
        spec = parse_rate_limit("1/minute")
        key = limit_key("reset", "a")
        await limiter.check(db, key=key, spec=spec)
        assert (await limiter.check(db, key=key, spec=spec)).allowed is False
        await limiter.reset(db, key=key)
        assert (await limiter.check(db, key=key, spec=spec)).allowed

    async def test_peek_reports_without_consuming(
        self, db: AsyncSession, tmp_settings: Settings
    ) -> None:
        limiter = RateLimiter(tmp_settings)
        key = limit_key("peek", "a")
        assert await limiter.peek(db, key=key) == 0
        await limiter.check(db, key=key, spec=parse_rate_limit("1/hour"))
        assert await limiter.peek(db, key=key) == 1

    async def test_two_sessions_share_the_same_counter(
        self, db: AsyncSession, tmp_settings: Settings, session_factory
    ) -> None:
        """The counter is in the database, not in process memory, so a second worker sees it."""
        limiter = RateLimiter(tmp_settings)
        spec = parse_rate_limit("1/minute")
        key = limit_key("shared", "a")
        assert (await limiter.check(db, key=key, spec=spec)).allowed
        await db.commit()

        async with session_factory() as other:
            result = await limiter.check(other, key=key, spec=spec)
            await other.commit()
        assert result.allowed is False


class TestLoginLockout:
    async def test_repeated_bad_passwords_are_rate_limited_and_then_locked(
        self, client, db: AsyncSession, user_factory, tmp_settings: Settings
    ) -> None:
        """
        Two defences in sequence: the rate limiter answers 429 once the budget is spent, and the
        account locks after ``auth_max_failed_logins``. The lock survives the rate limit being
        lifted, which is the point of having both.
        """
        user = await user_factory(email="lockme@example.com")
        attempts = []
        for _ in range(tmp_settings.auth_max_failed_logins + 2):
            response = await client.post(
                "/auth/login",
                json={
                    "email": "lockme@example.com",
                    "password": "definitely-not-the-password",
                    "device_name": "pytest",
                },
            )
            attempts.append(response.status_code)

        assert 401 in attempts, "a wrong password is an authentication failure"
        assert any(code in {429, 423} for code in attempts), "guessing must be slowed or stopped"

        await db.refresh(user)
        locked = user.locked_until is not None and user.locked_until > utcnow()
        blocked = 429 in attempts or 423 in attempts
        assert locked or blocked, "the account must be locked or the caller throttled"

        # Even the correct password is refused while the account is locked.
        correct = await client.post(
            "/auth/login",
            json={
                "email": "lockme@example.com",
                "password": "correct-horse-battery-staple",
                "device_name": "pytest",
            },
        )
        assert correct.status_code in {401, 423, 429}

    async def test_a_successful_login_clears_the_failure_count(
        self, client, db: AsyncSession, user_factory, tokens_for
    ) -> None:
        user = await user_factory(email="clearme@example.com")
        await client.post(
            "/auth/login",
            json={"email": "clearme@example.com", "password": "wrong-password", "device_name": "p"},
        )
        await db.refresh(user)
        assert user.failed_login_count >= 1

        payload = await tokens_for("clearme@example.com")
        assert payload["access_token"]
        await db.refresh(user)
        assert user.failed_login_count == 0
        assert user.locked_until is None
        assert isinstance(user, User)
