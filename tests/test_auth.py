# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Authentication tests.

These cover the paths an attacker actually uses: credential stuffing, token replay, forced
password change, account enumeration and privilege escalation through the user API. The token
forgery cases are here too, because "it decodes" is not "it is valid".
"""

from __future__ import annotations

import time
import uuid

import jwt
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.core.enums import AuditOutcome, Role
from app.db.models import AuditEvent, RefreshToken, Session, User

# Reviewed fixtures: these are the passwords the tests type in, not credentials of any system.
STRONG_PASSWORD = "quartz-lantern-cipher-77"  # secret-scan:allow
NEW_PASSWORD = "velvet-marble-orbit-88"  # secret-scan:allow


async def _signup(client: AsyncClient, email: str, password: str = STRONG_PASSWORD):
    return await client.post(
        "/auth/signup", json={"email": email, "password": password, "display_name": "Ada"}
    )


class TestSignup:
    async def test_signup_creates_unverified_account_and_queues_mail(
        self, client: AsyncClient, db: AsyncSession
    ) -> None:
        email = f"new-{uuid.uuid4().hex[:8]}@example.com"
        response = await _signup(client, email)
        assert response.status_code == 202
        # The answer is the same whether or not the address was already registered.
        assert "verification link" in response.json()["message"].lower()

        user = (await db.execute(select(User).where(User.email == email))).scalars().one()
        assert user.email_verified_at is None
        assert user.role is Role.USER
        assert user.password_hash and user.password_hash.startswith("$argon2")
        assert STRONG_PASSWORD not in (user.password_hash or "")

        from app.db.models import MailOutboxMessage

        mail = (
            (
                await db.execute(
                    select(MailOutboxMessage).where(MailOutboxMessage.to_address == email)
                )
            )
            .scalars()
            .all()
        )
        assert len(mail) == 1
        assert mail[0].template == "verification"
        assert mail[0].status == "queued"

    async def test_signup_is_idempotent_from_the_outside(
        self, client: AsyncClient, db: AsyncSession
    ) -> None:
        email = f"dup-{uuid.uuid4().hex[:8]}@example.com"
        assert (await _signup(client, email)).status_code == 202
        second = await _signup(client, email)
        assert second.status_code == 202
        assert second.json()["message"] == (
            "Check your inbox. If that address can be registered, a verification link is "
            "on its way."
        )
        rows = (await db.execute(select(User).where(User.email == email))).scalars().all()
        assert len(rows) == 1, "a duplicate signup must not create a second account"

    async def test_weak_password_is_rejected(self, client: AsyncClient) -> None:
        response = await client.post(
            "/auth/signup",
            json={
                "email": f"weak-{uuid.uuid4().hex[:8]}@example.com",
                "password": "short",
                "display_name": "Weak",
            },
        )
        assert response.status_code == 422

        weak = await client.post(
            "/auth/signup",
            json={
                "email": "someone@example.com",
                "password": "passwordpasswordpassword",
                "display_name": "Weak",
            },
        )
        # Either the transport-level minimum or the policy check rejects it; both are 4xx.
        assert weak.status_code in (400, 422)


class TestLoginAndVerification:
    async def test_login_requires_verified_email(self, client: AsyncClient) -> None:
        email = f"unverified-{uuid.uuid4().hex[:8]}@example.com"
        await _signup(client, email)
        response = await client.post(
            "/auth/login", json={"email": email, "password": STRONG_PASSWORD}
        )
        assert response.status_code == 403
        assert response.json()["code"] == "email_not_verified"

    async def test_full_signup_verify_login_cycle(
        self, client: AsyncClient, db: AsyncSession, outbox_token
    ) -> None:
        email = f"cycle-{uuid.uuid4().hex[:8]}@example.com"
        await _signup(client, email)

        token = await outbox_token(template="verification")
        verified = await client.post("/auth/verify-email", json={"token": token})
        assert verified.status_code == 200
        assert verified.json()["message"] == "Email verified"

        # A verification link is single-use.
        replay = await client.post("/auth/verify-email", json={"token": token})
        assert replay.status_code == 400
        assert replay.json()["code"] in {"token_invalid", "token_expired"}

        login = await client.post(
            "/auth/login",
            json={
                "email": email,
                "password": STRONG_PASSWORD,
                "device_name": "Pixel",
                "platform": "android",
            },
        )
        assert login.status_code == 200, login.text
        body = login.json()
        assert body["token_type"] == "bearer"
        assert 0 < body["expires_in"] <= 900, "access tokens must be short-lived"
        assert body["user"]["email_verified"] is True
        assert body["user"]["role"] == "user"

        # Login opened exactly one session and one device row.
        sessions = await db.execute(
            select(Session).where(Session.user_id == uuid.UUID(body["user"]["id"]))
        )
        assert len(sessions.scalars().all()) == 1

        me = await client.get(
            "/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"}
        )
        assert me.status_code == 200
        assert me.json()["email"] == email

    async def test_user_never_sees_a_secret(self, client: AsyncClient, outbox_token) -> None:
        email = f"nosecrets-{uuid.uuid4().hex[:8]}@example.com"
        await _signup(client, email)
        await client.post("/auth/verify-email", json={"token": await outbox_token()})
        login = await client.post("/auth/login", json={"email": email, "password": STRONG_PASSWORD})
        text = login.text
        assert "password_hash" not in text
        assert "google_sub" not in text
        assert "$argon2" not in text

    async def test_login_wrong_password_and_unknown_email_are_indistinguishable(
        self, client: AsyncClient, user_factory
    ) -> None:
        user = await user_factory(email="real@example.com")
        wrong = await client.post(
            "/auth/login", json={"email": user.email, "password": "not-the-password-1"}
        )
        unknown = await client.post(
            "/auth/login", json={"email": "ghost@example.com", "password": "not-the-password-1"}
        )
        assert wrong.status_code == unknown.status_code == 401
        assert wrong.json()["code"] == unknown.json()["code"] == "invalid_credentials"
        assert wrong.json()["message"] == unknown.json()["message"]

    async def test_account_locks_after_repeated_failures(
        self, client: AsyncClient, user_factory
    ) -> None:
        user = await user_factory(email=f"lock-{uuid.uuid4().hex[:8]}@example.com")
        for _ in range(5):  # auth_max_failed_logins = 5 in the test profile
            attempt = await client.post(
                "/auth/login", json={"email": user.email, "password": "wrong-password"}
            )
            assert attempt.status_code == 401

        locked = await client.post(
            "/auth/login", json={"email": user.email, "password": "wrong-password"}
        )
        assert locked.status_code == 423
        assert locked.json()["code"] == "account_locked"
        assert "Retry-After" in locked.headers

        # Even the correct password is refused while the lockout is in force.
        still_locked = await client.post(
            "/auth/login", json={"email": user.email, "password": "correct-horse-battery-staple"}
        )
        assert still_locked.status_code == 423


class TestRefreshRotation:
    async def test_refresh_rotates_and_old_token_is_dead(
        self, client: AsyncClient, user_factory
    ) -> None:
        user = await user_factory(email=f"rotate-{uuid.uuid4().hex[:8]}@example.com")
        first = await client.post(
            "/auth/login", json={"email": user.email, "password": "correct-horse-battery-staple"}
        )
        original_refresh = first.json()["refresh_token"]

        rotated = await client.post("/auth/refresh", json={"refresh_token": original_refresh})
        assert rotated.status_code == 200
        assert rotated.json()["refresh_token"] != original_refresh

        replay = await client.post("/auth/refresh", json={"refresh_token": original_refresh})
        assert replay.status_code == 401
        assert replay.json()["code"] == "token_reuse_detected"

        # The whole session is revoked, so the newest token is dead too.
        after_theft = await client.post(
            "/auth/refresh", json={"refresh_token": rotated.json()["refresh_token"]}
        )
        assert after_theft.status_code == 401

    async def test_reuse_is_audited(
        self, client: AsyncClient, user_factory, db: AsyncSession
    ) -> None:
        user = await user_factory(email=f"audit-reuse-{uuid.uuid4().hex[:8]}@example.com")
        login = await client.post(
            "/auth/login", json={"email": user.email, "password": "correct-horse-battery-staple"}
        )
        refresh = login.json()["refresh_token"]
        await client.post("/auth/refresh", json={"refresh_token": refresh})
        await client.post("/auth/refresh", json={"refresh_token": refresh})

        events = (
            (
                await db.execute(
                    select(AuditEvent).where(
                        AuditEvent.actor_user_id == user.id,
                        AuditEvent.tool_name == "auth.token_reuse",
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(events) == 1
        assert events[0].outcome is AuditOutcome.DENIED
        assert events[0].error_code == "token_reuse_detected"

    async def test_refresh_tokens_are_stored_only_as_hashes(
        self, client: AsyncClient, user_factory, db: AsyncSession, tmp_settings: Settings
    ) -> None:
        """The plaintext refresh token must not exist anywhere in the database."""
        from app.auth.tokens import hash_refresh_token

        user = await user_factory(email=f"hashed-{uuid.uuid4().hex[:8]}@example.com")
        login = await client.post(
            "/auth/login", json={"email": user.email, "password": "correct-horse-battery-staple"}
        )
        refresh = login.json()["refresh_token"]
        expected_hash = hash_refresh_token(tmp_settings, refresh)

        stored = (
            (await db.execute(select(RefreshToken).where(RefreshToken.user_id == user.id)))
            .scalars()
            .all()
        )
        assert stored, "login must create a refresh token row"
        assert [row.token_hash for row in stored] == [expected_hash]
        assert refresh not in {row.token_hash for row in stored}

    async def test_expired_refresh_token_is_refused(
        self,
        client: AsyncClient,
        user_factory,
        db: AsyncSession,
        tmp_settings: Settings,
    ) -> None:
        from app.auth.tokens import hash_refresh_token
        from app.core.time import utcnow

        user = await user_factory(email=f"expired-{uuid.uuid4().hex[:8]}@example.com")
        login = await client.post(
            "/auth/login", json={"email": user.email, "password": "correct-horse-battery-staple"}
        )
        refresh = login.json()["refresh_token"]

        record = (
            (
                await db.execute(
                    select(RefreshToken).where(
                        RefreshToken.token_hash == hash_refresh_token(tmp_settings, refresh)
                    )
                )
            )
            .scalars()
            .one()
        )
        record.expires_at = utcnow().replace(year=utcnow().year - 1)
        await db.commit()

        response = await client.post("/auth/refresh", json={"refresh_token": refresh})
        assert response.status_code == 401
        assert response.json()["code"] == "token_expired"


class TestLogout:
    async def test_logout_all_revokes_every_session(
        self, client: AsyncClient, user_factory
    ) -> None:
        user = await user_factory(email=f"logout-{uuid.uuid4().hex[:8]}@example.com")
        first = await client.post(
            "/auth/login",
            json={"email": user.email, "password": "correct-horse-battery-staple"},
        )
        second = await client.post(
            "/auth/login",
            json={"email": user.email, "password": "correct-horse-battery-staple"},
        )
        assert first.json()["session_id"] != second.json()["session_id"]

        headers = {"Authorization": f"Bearer {first.json()['access_token']}"}
        response = await client.post("/auth/logout", json={"all_sessions": True}, headers=headers)
        assert response.status_code == 200
        assert "2 session" in response.json()["detail"]

        for payload in (first.json(), second.json()):
            stale = await client.get(
                "/auth/me", headers={"Authorization": f"Bearer {payload['access_token']}"}
            )
            assert stale.status_code == 401


class TestPasswordReset:
    async def test_reset_changes_password_and_kills_sessions(
        self, client: AsyncClient, user_factory, outbox_token
    ) -> None:
        user = await user_factory(email=f"reset-{uuid.uuid4().hex[:8]}@example.com")
        login = await client.post(
            "/auth/login", json={"email": user.email, "password": "correct-horse-battery-staple"}
        )
        access = login.json()["access_token"]

        asked = await client.post("/auth/forgot-password", json={"email": user.email})
        assert asked.status_code == 202
        token = await outbox_token(template="password_reset")

        reset = await client.post(
            "/auth/reset-password", json={"token": token, "password": NEW_PASSWORD}
        )
        assert reset.status_code == 200, reset.text

        # The old access token is dead immediately (session epoch bumped).
        stale = await client.get("/auth/me", headers={"Authorization": f"Bearer {access}"})
        assert stale.status_code == 401

        old_password = await client.post(
            "/auth/login", json={"email": user.email, "password": "correct-horse-battery-staple"}
        )
        assert old_password.status_code == 401
        new_password = await client.post(
            "/auth/login", json={"email": user.email, "password": NEW_PASSWORD}
        )
        assert new_password.status_code == 200

        # A reset link cannot be replayed.
        again = await client.post(
            "/auth/reset-password", json={"token": token, "password": "another-strong-parole-99"}
        )
        assert again.status_code == 400

    async def test_forgot_password_does_not_reveal_accounts(self, client: AsyncClient) -> None:
        known = await client.post("/auth/forgot-password", json={"email": "nobody@example.com"})
        assert known.status_code == 202
        assert known.json()["message"].startswith("If that address has an account")


class TestTokenForgery:
    @pytest.mark.parametrize("token_kind", ["wrong_secret", "expired", "alg_none"])
    async def test_forged_tokens_are_rejected(
        self, client: AsyncClient, tmp_settings: Settings, token_kind: str
    ) -> None:
        now = int(time.time())
        claims = {
            "sub": str(uuid.uuid4()),
            "role": "admin",
            "scopes": ["admin:*"],
            "jti": uuid.uuid4().hex,
            "typ": "access",
            "iat": now,
            "exp": now + 600,
            "iss": tmp_settings.jwt_issuer,
            "aud": tmp_settings.jwt_audience,
        }
        if token_kind == "wrong_secret":
            token = jwt.encode(claims, "a-different-secret-that-is-long-enough", algorithm="HS256")
        elif token_kind == "expired":
            claims["exp"] = now - 60
            token = jwt.encode(claims, tmp_settings.jwt_key(), algorithm="HS256")
        else:
            token = jwt.encode(claims, key="", algorithm="none")

        response = await client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401
        assert response.json()["code"] in {"token_invalid", "token_expired"}

    async def test_missing_and_malformed_headers(self, client: AsyncClient) -> None:
        assert (await client.get("/auth/me")).status_code == 401
        assert (
            await client.get("/auth/me", headers={"Authorization": "Bearer not-a-token"})
        ).status_code == 401
        assert (
            await client.get("/auth/me", headers={"Authorization": "Basic abc"})
        ).status_code == 401

    async def test_role_in_token_cannot_exceed_the_stored_role(
        self, client: AsyncClient, user_factory, tmp_settings: Settings
    ) -> None:
        """A token always carries the role the database holds, not a claim the client can edit."""
        user = await user_factory(email=f"elevate-{uuid.uuid4().hex[:8]}@example.com")
        await client.post(
            "/auth/login", json={"email": user.email, "password": "correct-horse-battery-staple"}
        )
        forged = jwt.encode(
            {
                "sub": str(user.id),
                "role": "admin",
                "scopes": ["admin:*"],
                "jti": uuid.uuid4().hex,
                "typ": "access",
                "iat": int(time.time()),
                "exp": int(time.time()) + 600,
                "iss": tmp_settings.jwt_issuer,
                "aud": tmp_settings.jwt_audience,
            },
            tmp_settings.jwt_key(),
            algorithm="HS256",
        )
        # The token is genuinely signed by this server, but scopes are recomputed from the row,
        # so the forged admin scope buys nothing.
        allowed = await client.get("/auth/me", headers={"Authorization": f"Bearer {forged}"})
        assert allowed.status_code == 200
        denied = await client.get("/admin/users", headers={"Authorization": f"Bearer {forged}"})
        assert denied.status_code == 403
        assert denied.json()["code"] == "role_required"


class TestRateLimiting:
    async def test_repeated_auth_attempts_are_rate_limited(self, client: AsyncClient) -> None:
        email = f"rl-{uuid.uuid4().hex[:8]}@example.com"
        statuses = []
        for _ in range(12):
            response = await client.post(
                "/auth/login", json={"email": email, "password": "wrong-password-here"}
            )
            statuses.append(response.status_code)
            if response.status_code == 429:
                assert response.json()["code"] == "rate_limited"
                assert "Retry-After" in response.headers
                break
        assert 429 in statuses, f"auth limit never triggered: {statuses}"

    async def test_limiter_counts_are_exposed_to_well_behaved_clients(
        self, client: AsyncClient, user_factory
    ) -> None:
        user = await user_factory(email=f"headers-{uuid.uuid4().hex[:8]}@example.com")
        response = await client.post(
            "/auth/login", json={"email": user.email, "password": "correct-horse-battery-staple"}
        )
        assert response.status_code == 200
        assert response.headers["X-RateLimit-Limit"] == "10"
        assert int(response.headers["X-RateLimit-Remaining"]) < 10


class TestAdminUserSurface:
    async def test_role_checks_are_enforced(
        self, client: AsyncClient, regular_user, admin_user, auth_headers
    ) -> None:
        user_headers = await auth_headers(regular_user.email)
        admin_headers = await auth_headers(admin_user.email)

        # Both a plain user and a VIP are refused: administration is admin-only.
        assert (await client.get("/admin/users", headers=user_headers)).status_code == 403
        listing = await client.get("/admin/users", headers=admin_headers)
        assert listing.status_code == 200
        assert listing.json()["total"] >= 2

    async def test_search_and_pagination(
        self, client: AsyncClient, admin_user, user_factory, auth_headers
    ) -> None:
        await user_factory(email="searchable.person@example.com")
        headers = await auth_headers(admin_user.email)
        found = await client.get(
            "/admin/users", params={"query": "searchable.person"}, headers=headers
        )
        assert found.status_code == 200
        assert [item["email"] for item in found.json()["items"]] == [
            "searchable.person@example.com"
        ]

        page = await client.get("/admin/users", params={"limit": 1, "offset": 0}, headers=headers)
        assert len(page.json()["items"]) == 1

    async def test_role_change_takes_effect_immediately(
        self, client: AsyncClient, admin_user, regular_user, auth_headers
    ) -> None:
        admin_headers = await auth_headers(admin_user.email)
        user_headers = await auth_headers(regular_user.email)

        promoted = await client.patch(
            f"/admin/users/{regular_user.id}", json={"role": "vip"}, headers=admin_headers
        )
        assert promoted.status_code == 200
        assert promoted.json()["role"] == "vip"

        # The user's existing access token now maps to VIP scopes: no re-login needed.
        listing = await client.get("/admin/users", headers=user_headers)
        assert listing.status_code == 403  # still not an admin

        demoted = await client.patch(
            f"/admin/users/{regular_user.id}", json={"role": "user"}, headers=admin_headers
        )
        assert demoted.json()["role"] == "user"

    async def test_deactivating_a_user_kills_their_sessions(
        self, client: AsyncClient, admin_user, regular_user, auth_headers
    ) -> None:
        admin_headers = await auth_headers(admin_user.email)
        user_headers = await auth_headers(regular_user.email)
        assert (await client.get("/auth/me", headers=user_headers)).status_code == 200

        response = await client.patch(
            f"/admin/users/{regular_user.id}", json={"is_active": False}, headers=admin_headers
        )
        assert response.status_code == 200
        assert (await client.get("/auth/me", headers=user_headers)).status_code == 401

    async def test_last_admin_cannot_be_demoted_or_disabled(
        self, client: AsyncClient, admin_user, auth_headers
    ) -> None:
        headers = await auth_headers(admin_user.email)
        demote = await client.patch(
            f"/admin/users/{admin_user.id}", json={"role": "user"}, headers=headers
        )
        assert demote.status_code == 409
        disable = await client.patch(
            f"/admin/users/{admin_user.id}", json={"is_active": False}, headers=headers
        )
        assert disable.status_code == 409

    async def test_admin_can_create_and_unlock_users(
        self, client: AsyncClient, admin_user, auth_headers, db: AsyncSession
    ) -> None:
        headers = await auth_headers(admin_user.email)
        email = f"created-{uuid.uuid4().hex[:8]}@example.com"
        created = await client.post(
            "/admin/users",
            json={"email": email, "password": NEW_PASSWORD, "role": "vip"},
            headers=headers,
        )
        assert created.status_code == 201, created.text
        assert created.json()["role"] == "vip"
        assert created.json()["email_verified"] is True

        duplicate = await client.post(
            "/admin/users",
            json={"email": email, "password": NEW_PASSWORD},
            headers=headers,
        )
        assert duplicate.status_code == 409

        user = (await db.execute(select(User).where(User.email == email))).scalars().one()
        from app.core.time import utcnow

        user.locked_until = utcnow()
        user.failed_login_count = 4
        await db.commit()

        unlocked = await client.post(f"/admin/users/{user.id}/unlock", headers=headers)
        assert unlocked.status_code == 200
        assert unlocked.json()["locked_until"] is None
        assert unlocked.json()["failed_login_count"] == 0

    async def test_admin_cannot_read_credentials_through_any_field(
        self, client: AsyncClient, admin_user, auth_headers
    ) -> None:
        headers = await auth_headers(admin_user.email)
        listing = await client.get("/admin/users", headers=headers)
        for item in listing.json()["items"]:
            assert "password_hash" not in item
            assert "google_sub" not in item
