# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""``health_status`` - report backend and integration health without exposing any secret."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app import __version__
from app.core.risk import Risk
from app.core.time import utcnow
from app.db.session import check_database
from app.registry import ToolContext, ToolResult, tool
from app.registry.core import registry as process_registry
from app.security.kill_switch import KillSwitch


class HealthStatusInput(BaseModel):
    """No arguments: health is never parameterised by the caller."""

    model_config = {"extra": "forbid"}


class HealthStatusOutput(BaseModel):
    status: str
    server_version: str
    environment: str
    database: str
    kill_switch_engaged: bool
    llm_provider: str
    registered_tools: int
    enabled_tools: int
    integrations: dict[str, bool] = Field(default_factory=dict)
    secrets_are_ephemeral: bool
    at: datetime


@tool(
    name="health_status",
    version="1.0",
    description=(
        "Report backend status: database reachability, kill-switch state, and which "
        "integrations are switched on. Contains no secrets and requires no arguments."
    ),
    risk=Risk.LOW,
    enabled=True,
    input_schema=HealthStatusInput,
    output_schema=HealthStatusOutput,
    required_scopes=[],
    confirm=False,
    rate_limit="60/minute",
    dry_run_supported=False,
    category="system",
)
async def health_status(args: HealthStatusInput, ctx: ToolContext) -> ToolResult:
    del args
    settings = ctx.settings
    database_ok, _ = await check_database(ctx.session)
    engaged = False
    if ctx.session is not None:
        engaged = await KillSwitch(settings).is_engaged(ctx.session)

    summary = settings.safe_summary()
    output = HealthStatusOutput(
        status="ok" if database_ok else "degraded",
        server_version=__version__,
        environment=settings.environment,
        database="ok" if database_ok else "unavailable",
        kill_switch_engaged=engaged,
        llm_provider=settings.llm_provider,
        registered_tools=len(process_registry),
        enabled_tools=len(process_registry.enabled()),
        integrations=summary["integrations"],
        secrets_are_ephemeral=bool(
            settings.jwt_secret_was_generated or settings.encryption_key_was_generated
        ),
        at=utcnow(),
    )
    return ToolResult(
        ok=database_ok,
        summary=(
            f"status={output.status} database={output.database} "
            f"kill_switch={'engaged' if engaged else 'released'} "
            f"integrations_on={sum(1 for value in output.integrations.values() if value)}"
        ),
        data=output.model_dump(mode="json"),
        error_code=None if database_ok else "service_unavailable",
    )
