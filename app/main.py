# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
A.R.M.X AI backend entrypoint.

The LLM is an untrusted planner in this system: it can *ask* for a named tool with
arguments, and nothing else. Everything that decides whether an action happens - risk tier,
scopes, rate limits, approvals, the kill-switch - lives behind the Security Gateway
(``app/security``). This module wires the HTTP surface and the process lifecycle; it makes no
authorization decisions of its own.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import __version__
from app.api.middleware import register_middleware
from app.api.routes_health import router as health_router
from app.config import Settings, get_settings
from app.core.alerts import AlertSeverity, send_alert
from app.core.errors import APIError, ErrorCode
from app.core.logging import configure_logging, get_logger
from app.core.time import utcnow
from app.db.bootstrap import initialize_database_state
from app.db.session import dispose_engines, get_sessionmaker
from app.db.urls import redacted_database_url
from app.llm.base import LLMProvider
from app.registry.core import ToolRegistry
from app.registry.discovery import discover_tools
from app.registry.store import sync_registry

logger = get_logger("main")


def _install_error_handlers(application: FastAPI) -> None:
    """Uniform error envelope: ``{code, message, retryable, request_id}``."""

    def body(request: Request, code: str, message: str, retryable: bool) -> dict[str, object]:
        request_id = getattr(request.state, "request_id", None)
        return {
            "code": code,
            "message": message,
            "retryable": retryable,
            "request_id": request_id or "",
        }

    @application.exception_handler(APIError)
    async def api_error_handler(request: Request, exc: APIError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                **body(request, exc.code, exc.message, exc.retryable),
                **({"details": exc.details} if exc.details else {}),
            },
            headers=exc.headers,
        )

    @application.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Field names are echoed, values are not: a rejected password must never be logged.
        fields = sorted({str(error.get("loc", ("",))[-1]) for error in exc.errors()})
        return JSONResponse(
            status_code=422,
            content={
                **body(request, ErrorCode.INVALID_REQUEST, "Request validation failed", False),
                "details": {"fields": fields[:20]},
            },
        )

    @application.exception_handler(StarletteHTTPException)
    async def http_error_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        if exc.status_code == 404:
            code, message = ErrorCode.NOT_FOUND, "Resource was not found"
        elif exc.status_code == 405:
            code, message = "method_not_allowed", "Method not allowed"
        else:
            code, message = "http_error", "Request could not be completed"
        return JSONResponse(
            status_code=exc.status_code,
            content=body(request, code, message, exc.status_code >= 500),
            headers=getattr(exc, "headers", None) or {},
        )

    @application.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "")
        # Log the type, never the message: SQL values and user input can end up in
        # exception text, and this log line is the one that fires when something is wrong.
        logger.error(
            "unhandled error request_id=%s exception_type=%s path=%s",
            request_id,
            type(exc).__name__,
            request.url.path,
        )
        if type(exc).__name__ in {"OperationalError", "InterfaceError", "DBAPIError"}:
            send_alert(
                "Database error in request path",
                severity=AlertSeverity.CRITICAL,
                detail={"exception": type(exc).__name__, "request_id": request_id},
            )
        return JSONResponse(
            status_code=500,
            content=body(request, ErrorCode.INTERNAL_ERROR, "An internal error occurred", True),
        )


def create_app(
    settings: Settings | None = None,
    *,
    registry: ToolRegistry | None = None,
    llm_provider: LLMProvider | None = None,
) -> FastAPI:
    """
    Build the ASGI application.

    Accepts an explicit ``Settings`` so tests can construct an isolated app (separate database
    file, mock LLM, rate limits on) without touching process environment variables. ``registry``
    and ``llm_provider`` override the discovered tool set and the model provider, which is how
    the test suite pins a scripted model and a known catalogue without mutating process state.
    """
    configured = settings or get_settings()

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        configure_logging(level=configured.log_level, fmt=configured.log_format)
        logger.info("starting %s v%s", configured.app_name, __version__)
        logger.info("configuration: %s", configured.safe_summary())
        logger.info("database: %s", redacted_database_url(configured.database_url))

        if configured.demo_insecure:
            logger.warning(
                "DEMO_INSECURE=true: plaintext HTTP is allowed. Never use this profile on a "
                "network you do not control."
            )
        if configured.jwt_secret_was_generated or configured.encryption_key_was_generated:
            logger.warning(
                "An ephemeral development secret was generated. Sessions and encrypted memory "
                "will not survive a restart. Set JWT_SECRET_KEY and ENCRYPTION_KEY."
            )
        if configured.email_delivery_mode == "outbox":
            logger.warning(
                "EMAIL_DELIVERY_MODE=outbox: verification and reset mail is stored in "
                "mail_outbox and never delivered (read it via GET /admin/mail)."
            )

        # 1. Registry first: the tool manifests are the allowlist every later step uses.
        tools = registry if registry is not None else discover_tools(configured)
        logger.info("tool registry: %d tools registered", len(tools))

        # 2. Then database state (flags, cleanup, migration revision).
        await initialize_database_state(configured)

        # 3. Mirror the registry into the database: the tool rows are what an operator toggles,
        #    and the snapshot they belong to is what every audit row references.
        try:
            factory = await get_sessionmaker(configured)
            async with factory() as session:
                await sync_registry(session, tools)
                await session.commit()
        except Exception:
            # A degraded catalogue must not stop the API serving: /health and the admin console
            # stay reachable, and the next restart (or the maintenance loop) retries the sync.
            logger.exception("registry sync failed; the tool catalogue is stale")

        stop = asyncio.Event()
        tasks: list[asyncio.Task[None]] = []

        from app.jobs.maintenance import maintenance_loop

        tasks.append(asyncio.create_task(maintenance_loop(configured, stop), name="maintenance"))

        if configured.worker_enabled and configured.worker_in_api:
            from app.jobs.worker import worker_loop

            for index in range(max(1, configured.worker_concurrency)):
                tasks.append(
                    asyncio.create_task(
                        worker_loop(configured, stop, worker_name=f"api-{index}"),
                        name=f"worker-api-{index}",
                    )
                )
        elif configured.worker_enabled:
            logger.info("worker loop delegated to the dedicated worker container")

        application.state.settings = configured
        application.state.registry = tools
        if llm_provider is not None:
            application.state.llm_provider = llm_provider

        try:
            yield
        finally:
            stop.set()
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            provider = getattr(application.state, "llm_provider", None)
            if provider is not None:
                await provider.aclose()
            await dispose_engines()
            logger.info("shutdown complete")

    application = FastAPI(
        title=configured.app_name,
        version=__version__,
        description=(
            "Tool-driven assistant backend. The LLM proposes; the Security Gateway decides."
        ),
        docs_url="/docs" if configured.is_local_dev else None,
        redoc_url=None,
        openapi_url="/openapi.json" if configured.is_local_dev else None,
        lifespan=lifespan,
    )

    register_middleware(application, configured)
    _install_error_handlers(application)

    @application.get("/", include_in_schema=False)
    async def root() -> dict[str, str]:
        return {
            "name": configured.app_name,
            "version": __version__,
            "status": "ok",
            "time": utcnow().isoformat(),
        }

    application.include_router(health_router)

    for include in _FEATURE_ROUTERS:
        include(application)

    return application


def _include_auth(application: FastAPI) -> None:
    from app.auth.routes import router as auth_router

    application.include_router(auth_router)


def _include_users(application: FastAPI) -> None:
    from app.users.routes import router as users_router

    application.include_router(users_router)


def _include_devices(application: FastAPI) -> None:
    from app.devices.routes import router as devices_router

    application.include_router(devices_router)


def _include_approvals(application: FastAPI) -> None:
    from app.approvals.routes import router as approvals_router

    application.include_router(approvals_router)


def _include_assistant(application: FastAPI) -> None:
    from app.assistant.routes import router as assistant_router
    from app.assistant.ws import router as assistant_stream_router

    application.include_router(assistant_router)
    application.include_router(assistant_stream_router)


def _include_tools(application: FastAPI) -> None:
    from app.tools.routes import router as tools_router

    application.include_router(tools_router)


def _include_audit(application: FastAPI) -> None:
    from app.audit.routes import router as audit_router

    application.include_router(audit_router)


def _include_admin(application: FastAPI) -> None:
    from app.admin.routes import router as admin_router

    application.include_router(admin_router)


def _include_memory(application: FastAPI) -> None:
    from app.memory.routes import router as memory_router

    application.include_router(memory_router)


def _include_automation(application: FastAPI) -> None:
    from app.automation.routes import router as automation_router

    application.include_router(automation_router)


def _include_guest(application: FastAPI) -> None:
    from app.guest.routes import router as guest_router

    application.include_router(guest_router)


def _include_messaging(application: FastAPI) -> None:
    from app.messaging.routes import router as messaging_router

    application.include_router(messaging_router)


def _include_webhooks(application: FastAPI) -> None:
    from app.integrations.webhooks import router as webhooks_router

    application.include_router(webhooks_router)


def _include_jobs(application: FastAPI) -> None:
    from app.jobs.routes import router as jobs_router

    application.include_router(jobs_router)


def _include_web_builder(application: FastAPI) -> None:
    from app.web_builder.routes import router as web_builder_router

    application.include_router(web_builder_router)


#: Feature routers are included through explicit functions rather than a dynamic scan, so the
#: API surface is greppable and a broken module fails loudly at startup instead of silently
#: dropping routes. Entries are appended as each build phase lands. (`_include_*` functions for
#: phases that have not landed yet exist but are deliberately not listed below, and pyproject
#: narrows mypy's `import-not-found` to this module until they do.)
_FEATURE_ROUTERS: tuple[Callable[[FastAPI], None], ...] = (
    _include_auth,
    _include_users,
    _include_tools,
    _include_approvals,
    _include_audit,
    _include_admin,
    _include_assistant,
)


app = create_app()
