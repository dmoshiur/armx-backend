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


def _make_app(*, session: _StubSession | None = None, insecure: bool = True):
    settings = Settings(
        _env_file=None,
        environment="demo" if insecure else "production",
        demo_insecure=insecure,
        database_url=(
            "sqlite+aiosqlite:///./test.db"
            if insecure
            else "postgresql+asyncpg://user:pass@localhost/armx?ssl=require"
        ),
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
    assert response.json()["requires_pairing"] is True
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
        "database_url": "postgresql+asyncpg://user:pass@db.example.test/armx",
    }
    with pytest.raises(ValidationError):
        Settings(**base)

    with pytest.raises(ValidationError):
        Settings(
            **{
                **base,
                "database_url": "postgresql+asyncpg://user:pass@db.example.test/armx?ssl=require",
                "ollama_base_url": "http://model.example.test:11434",
            }
        )
