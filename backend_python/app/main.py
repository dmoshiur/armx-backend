# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from uuid import uuid4

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.auth.routes import router as auth_router
from app.config import Settings, get_settings
from app.core.errors import APIError
from app.db.bootstrap import initialize_database_state
from app.db.session import dispose_engine, get_session
from app.pairing.routes import router as pairing_router
from app.ws.routes import router as websocket_router

logger = logging.getLogger("armx")
_SERVER_VERSION = "0.1.0"


class HealthResponse(BaseModel):
    server_version: str
    requires_pairing: bool
    at: datetime


def _request_id(request: Request) -> str:
    value = getattr(request.state, "request_id", None)
    if not isinstance(value, str):
        value = uuid4().hex[:16]
        request.state.request_id = value
    return value


def _error_body(request: Request, code: str, message: str, retryable: bool) -> dict[str, object]:
    return {
        "code": code,
        "message": message,
        "retryable": retryable,
        "request_id": _request_id(request),
    }


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build a minimal ASGI service with database health and a stable error envelope."""

    configured = settings or get_settings()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if configured.demo_insecure:
            logger.warning(
                "DEMO_INSECURE=true: HTTP is unencrypted; use only on a local/demo network."
            )
        await initialize_database_state(configured)
        try:
            yield
        finally:
            await dispose_engine()

    application = FastAPI(
        title=configured.app_name,
        version=_SERVER_VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    @application.middleware("http")
    async def enforce_tls_and_request_id(request: Request, call_next):  # type: ignore[no-untyped-def]
        request.state.request_id = uuid4().hex[:16]
        is_secure = request.url.scheme.lower() == "https"
        if not configured.demo_insecure and not is_secure:
            response = JSONResponse(
                status_code=400,
                content=_error_body(request, "tls_required", "HTTPS is required", False),
            )
        else:
            response = await call_next(request)
        response.headers["X-Request-Id"] = _request_id(request)
        response.headers["Cache-Control"] = response.headers.get("Cache-Control", "no-store")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @application.exception_handler(APIError)
    async def api_error_handler(request: Request, exc: APIError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body(request, exc.code, exc.message, exc.retryable),
        )

    @application.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        del exc
        return JSONResponse(
            status_code=422,
            content=_error_body(request, "invalid_request", "Request validation failed", False),
        )

    @application.exception_handler(StarletteHTTPException)
    async def http_error_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code, message = (
            ("not_found", "Resource was not found")
            if exc.status_code == 404
            else ("http_error", "Request could not be completed")
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body(request, code, message, exc.status_code >= 500),
        )

    @application.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
        del exc
        request_id = _request_id(request)
        logger.error("Unhandled API error request_id=%s", request_id)
        return JSONResponse(
            status_code=500,
            content=_error_body(request, "internal_error", "An internal error occurred", True),
        )

    @application.get("/health", response_model=HealthResponse, tags=["health"])
    async def health(session: AsyncSession = Depends(get_session)) -> HealthResponse:
        try:
            await session.execute(text("SELECT 1"))
        except SQLAlchemyError:
            logger.warning("health check failed: database unavailable")
            raise APIError(
                "service_unavailable", "Service unavailable", status_code=503, retryable=True
            ) from None
        return HealthResponse(
            server_version=_SERVER_VERSION,
            requires_pairing=True,
            at=datetime.now(UTC),
        )

    application.include_router(auth_router)
    application.include_router(pairing_router)
    application.include_router(websocket_router)
    return application


app = create_app()
