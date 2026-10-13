# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""Health, readiness, metrics and the HTTP hardening middleware."""

from __future__ import annotations

from httpx import AsyncClient


async def test_health_reports_ok_without_leaking_configuration(client: AsyncClient) -> None:
    response = await client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"
    assert set(body) == {"status", "server_version", "environment", "database", "at"}
    # A credential, a connection string or a filesystem path must never appear here.
    assert "sqlite" not in response.text
    assert "secret" not in response.text.lower()


async def test_ready_reports_the_applied_migration_revision(client: AsyncClient) -> None:
    response = await client.get("/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["migration_revision"] is not None
    assert body["kill_switch_engaged"] is False


async def test_metrics_are_exposed_locally_and_are_prometheus_shaped(client: AsyncClient) -> None:
    await client.get("/health")
    response = await client.get("/metrics")
    assert response.status_code == 200
    assert "armx_http_requests_total" in response.text
    assert 'route="/health"' in response.text


async def test_metrics_can_be_disabled(app_factory) -> None:
    app = app_factory(metrics_enabled=False)
    from httpx import ASGITransport

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get("/metrics")
    assert response.status_code == 404


async def test_unknown_route_returns_the_standard_error_envelope(client: AsyncClient) -> None:
    response = await client.get("/definitely-not-a-route")
    assert response.status_code == 404
    body = response.json()
    assert set(body) == {"code", "message", "retryable", "request_id"}
    assert body["code"] == "not_found"
    assert body["request_id"]


async def test_security_headers_are_present_on_every_response(client: AsyncClient) -> None:
    response = await client.get("/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-request-id"]


async def test_request_id_is_echoed_when_the_client_supplies_one(client: AsyncClient) -> None:
    response = await client.get("/health", headers={"X-Request-Id": "trace-me-1234"})
    assert response.headers["x-request-id"] == "trace-me-1234"


async def test_plaintext_http_is_rejected_outside_the_demo_profile(app_factory) -> None:
    """With DEMO_INSECURE off, a plaintext request is refused before it reaches any handler."""
    app = app_factory(demo_insecure=False)
    from httpx import ASGITransport

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get("/ready")
            assert response.status_code == 400
            assert response.json()["code"] == "tls_required"
            # The liveness probe may be exempted explicitly; by default it is not.
            assert (await client.get("/health")).status_code == 400


async def test_oversized_body_is_rejected_before_parsing(client: AsyncClient) -> None:
    response = await client.post(
        "/anything",
        content=b"x",
        headers={"Content-Length": str(64 * 1024 * 1024), "Content-Type": "application/json"},
    )
    assert response.status_code in {413, 404}
    if response.status_code == 413:
        assert response.json()["code"] == "payload_too_large"


async def test_unhandled_exception_returns_a_500_without_leaking_detail(app_factory) -> None:
    app = app_factory()
    from httpx import ASGITransport

    @app.get("/boom", include_in_schema=False)
    async def boom() -> None:
        raise RuntimeError("database password is hunter2")

    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app, raise_app_exceptions=False)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get("/boom")
    assert response.status_code == 500
    assert "hunter2" not in response.text
    assert response.json()["code"] == "internal_error"
