# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.config import Settings, get_settings
from app.db.session import get_session
from app.main import create_app


class _StubSession:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail

    async def execute(self, statement: object) -> None:
        del statement
        if self.fail:
            raise SQLAlchemyError("sensitive db connection details")


def _make_app(
    *,
    session: _StubSession | None = None,
    insecure: bool = True,
    allow_plain_http_health_probe: bool = False,
):
    settings = Settings(
        _env_file=None,
        environment="demo" if insecure else "production",
        demo_insecure=insecure,
        allow_plain_http_health_probe=allow_plain_http_health_probe,
        database_url=(
            "sqlite+aiosqlite:///./test.db"
            if insecure
            else "sqlite+libsql://armx-demo.turso.io?secure=true"
        ),
        turso_auth_token=None if insecure else "test-turso-token",
        public_api_base_url=None if insecure else "https://api.example.test",
        jwt_secret_key="t" * 32,
    )
    application = create_app(settings)

    async def override_session():
        yield session or _StubSession()

    application.dependency_overrides[get_session] = override_session
    application.dependency_overrides[get_settings] = lambda: settings
    return application


@pytest.mark.asyncio
async def test_health_returns_documented_contract() -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    application = _make_app()

    async def test_session():
        async with session_factory() as session:
            yield session

    application.dependency_overrides[get_session] = test_session
    try:
        async with AsyncClient(
            transport=ASGITransport(app=application), base_url="http://testserver"
        ) as client:
            response = await client.get("/health")
    finally:
        await engine.dispose()

    assert response.status_code == 200
    assert response.json()["server_version"] == "0.1.0"
    assert response.json()["requires_pairing"] is False
    assert response.json()["at"].endswith("Z")


@pytest.mark.asyncio
async def test_health_hides_database_errors_in_standard_envelope(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async with AsyncClient(
        transport=ASGITransport(app=_make_app(session=_StubSession(fail=True))),
        base_url="http://testserver",
    ) as client:
        response = await client.get("/health")

    assert response.status_code == 503
    assert response.json()["code"] == "service_unavailable"
    assert response.json()["message"] == "Service unavailable"
    assert response.json()["retryable"] is True
    assert response.json()["request_id"]
    assert "sensitive db connection details" not in response.text
    assert "sensitive db connection details" not in caplog.text


@pytest.mark.asyncio
async def test_non_demo_profile_rejects_plain_http_with_error_envelope() -> None:
    application = _make_app(insecure=False)
    async with AsyncClient(
        transport=ASGITransport(app=application), base_url="http://testserver"
    ) as client:
        response = await client.get("/health")

    assert response.status_code == 400
    assert response.json()["code"] == "tls_required"
    assert response.json()["message"] == "HTTPS is required"
    assert response.headers["x-request-id"] == response.json()["request_id"]


@pytest.mark.asyncio
async def test_platform_health_probe_is_the_only_plain_http_exception() -> None:
    """Render probes GET /health over plain HTTP; every other request still needs TLS."""

    application = _make_app(insecure=False, allow_plain_http_health_probe=True)
    async with AsyncClient(
        transport=ASGITransport(app=application), base_url="http://testserver"
    ) as client:
        probe = await client.get("/health")
        other_route = await client.get("/devices")
        non_get_probe = await client.post("/health")

    assert probe.status_code == 200
    for rejected in (other_route, non_get_probe):
        assert rejected.status_code == 400
        assert rejected.json()["code"] == "tls_required"


def test_production_cannot_enable_demo_insecure() -> None:
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            environment="production",
            demo_insecure=True,
            jwt_secret_key="a" * 32,
        )


def test_secure_profile_requires_tls_for_database_and_llm() -> None:
    base = {
        "_env_file": None,
        "environment": "production",
        "jwt_secret_key": "b" * 32,
        "public_api_base_url": "https://api.example.test",
        "database_url": "sqlite+libsql://armx.turso.io",
        "turso_auth_token": "test-turso-token",
    }
    with pytest.raises(ValidationError):
        Settings(**base)  # remote libSQL without an explicit TLS flag

    with pytest.raises(ValidationError):
        # A local libSQL file is still an ephemeral-disk database in deployed profiles.
        Settings(**{**base, "database_url": "sqlite+libsql:///./armx.db"})

    with pytest.raises(ValidationError):
        Settings(
            **{
                **base,
                "database_url": "libsql://armx.turso.io?secure=true",
                "ollama_base_url": "http://model.example.test:11434",
            }
        )

    with pytest.raises(ValidationError):
        Settings(**{**base, "database_url": "libsql://armx.turso.io?secure=false"})

    with pytest.raises(ValidationError):
        Settings(
            **{
                **base,
                "database_url": "libsql://armx.turso.io?secure=true",
                "ollama_base_url": "http://model.example.test:11434",
            }
        )
