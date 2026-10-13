# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
The tool catalogue and direct invocation.

Two surfaces:

* ``/tools`` - what *this* caller may run, with the JSON Schema of each tool's arguments. The
  list is filtered by the same rules the gateway applies (scope, enablement, permission
  overrides), so a client can never discover a capability it cannot use.
* ``/admin/tools`` - the operator's view: every registered tool, its risk tier, whether it is
  enabled, and a toggle. Disabling a tool takes effect on the next call, including for the
  assistant, because the gateway reads the toggle on every decision.

``POST /tools/{name}/invoke`` runs a tool through the Security Gateway - the same path the
assistant uses, with the same approvals, rate limits and audit rows. It exists so the mobile app
can offer a direct button ("unlock the door", "deploy the site") without inventing a second
execution path.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import actor_for, app_gateway, app_registry, db_session
from app.audit.service import record_event
from app.auth.dependencies import CurrentPrincipal, Principal, require_admin
from app.core.enums import AuditOutcome, AuditSource
from app.core.errors import APIError, ErrorCode
from app.core.risk import requires_approval
from app.core.time import utcnow
from app.db.models import RegistrySnapshot, ToolDefinition
from app.registry.core import ToolRegistry, ToolSpec
from app.registry.schemas import (
    AdminToolSummary,
    InvocationResponse,
    InvokeRequest,
    ToggleToolRequest,
    ToolListResponse,
    ToolSummary,
)
from app.security.gateway import InvocationOutcome, SecurityGateway

router = APIRouter(tags=["tools"])


def _summary(spec: ToolSpec) -> ToolSummary:
    return ToolSummary(
        name=spec.name,
        version=spec.version,
        description=spec.description,
        risk=spec.risk.label,
        category=spec.category,
        integration=spec.integration,
        required_scopes=list(spec.required_scopes),
        requires_approval=requires_approval(spec.risk, confirm=spec.confirm),
        dry_run_supported=spec.dry_run_supported,
        rate_limit=spec.rate_limit,
        input_schema=spec.input_json_schema(),
        output_schema=spec.output_json_schema(),
    )


def _invocation_response(outcome: InvocationOutcome) -> InvocationResponse:
    result = outcome.result
    return InvocationResponse(
        status=outcome.status,
        tool=outcome.tool_name,
        tool_version=outcome.tool_version,
        risk=outcome.risk.label if outcome.risk else None,
        dry_run=outcome.dry_run,
        summary=(result.summary if result else "") or outcome.message,
        data=(result.data if result else {}) or {},
        error_code=outcome.error_code or (result.error_code if result else None),
        message=outcome.message or (result.error_message if result else "") or "",
        approval_id=outcome.approval_id,
        audit_id=outcome.audit_id,
        duration_ms=outcome.duration_ms,
        retry_after=outcome.retry_after,
    )


@router.get("/tools", response_model=ToolListResponse)
async def list_tools(
    principal: CurrentPrincipal,
    session: AsyncSession = Depends(db_session),
    gateway: SecurityGateway = Depends(app_gateway),
    registry: ToolRegistry = Depends(app_registry),
) -> ToolListResponse:
    """Tools this caller may invoke, with their argument schemas."""
    catalogue = await gateway.describe_tools(session, actor=actor_for(principal), registry=registry)
    allowed = {entry["name"] for entry in catalogue}
    items = [_summary(spec) for spec in registry.all() if spec.name in allowed]
    return ToolListResponse(items=items, total=len(items))


@router.post("/tools/{tool_name}/invoke", response_model=InvocationResponse)
async def invoke_tool(
    tool_name: str,
    payload: InvokeRequest,
    request: Request,
    principal: CurrentPrincipal,
    session: AsyncSession = Depends(db_session),
    gateway: SecurityGateway = Depends(app_gateway),
    registry: ToolRegistry = Depends(app_registry),
) -> InvocationResponse:
    """
    Run one tool.

    A refusal is a normal, structured answer - ``403`` for a permission problem, ``409`` when an
    approval is missing, expired or was granted for different arguments, ``429`` when a limit is
    reached - and every one of those outcomes has already been written to the audit trail.
    """
    outcome = await gateway.invoke(
        session,
        tool_name=tool_name,
        arguments=payload.arguments,
        actor=actor_for(principal),
        device_id=principal.device_id,
        session_id=principal.session_id,
        source=AuditSource.API,
        trace_id=getattr(request.state, "trace_id", None),
        ip_address=request.client.host if request.client else None,
        idempotency_key=payload.idempotency_key,
        dry_run=payload.dry_run,
        approval_id=payload.approval_id,
        registry=registry,
    )

    if outcome.status == "denied":
        status_code, retryable = _status_for(outcome.error_code)
        headers = {"Retry-After": str(outcome.retry_after)} if outcome.retry_after else None
        raise APIError(
            outcome.error_code or ErrorCode.FORBIDDEN,
            outcome.message or "The action was refused",
            status_code=status_code,
            retryable=retryable,
            headers=headers,
        )
    if outcome.needs_approval:
        raise APIError(
            ErrorCode.APPROVAL_REQUIRED,
            outcome.message or "This action needs your approval",
            status_code=409,
            details={"approval_id": str(outcome.approval_id)},
        )
    return _invocation_response(outcome)


def _status_for(error_code: str | None) -> tuple[int, bool]:
    """Map a gateway refusal onto an HTTP status, keeping the error code stable."""
    if error_code in {ErrorCode.RATE_LIMITED}:
        return 429, True
    if error_code in {
        ErrorCode.UNAUTHENTICATED,
        ErrorCode.TOKEN_INVALID,
        ErrorCode.TOKEN_EXPIRED,
    }:
        return 401, False
    if error_code in {
        ErrorCode.APPROVAL_REQUIRED,
        ErrorCode.APPROVAL_INVALID,
        ErrorCode.APPROVAL_EXPIRED,
        ErrorCode.APPROVAL_ALREADY_USED,
        ErrorCode.APPROVAL_DENIED,
        ErrorCode.APPROVAL_ARGUMENT_MISMATCH,
    }:
        return 409, False
    if error_code in {ErrorCode.TOOL_UNKNOWN}:
        return 404, False
    if error_code in {
        ErrorCode.TOOL_DISABLED,
        ErrorCode.FORBIDDEN,
        ErrorCode.SCOPE_REQUIRED,
        ErrorCode.KILL_SWITCH_ENGAGED,
        ErrorCode.DRY_RUN_ONLY,
    }:
        return 403, False
    if error_code in {ErrorCode.TOOL_ARGUMENT_INVALID}:
        return 422, False
    return 400, False


@router.get("/admin/tools", response_model=list[AdminToolSummary])
async def admin_list_tools(
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(db_session),
    registry: ToolRegistry = Depends(app_registry),
    q: str | None = Query(default=None, max_length=64),
    category: str | None = Query(default=None, max_length=40),
) -> list[AdminToolSummary]:
    """Every registered tool with its operator state, including disabled and unavailable ones."""
    del principal
    rows = {
        row.name: row for row in (await session.execute(select(ToolDefinition))).scalars().all()
    }
    revisions = {
        row.id: row.revision
        for row in (await session.execute(select(RegistrySnapshot))).scalars().all()
    }
    needle = (q or "").strip().lower()
    items: list[AdminToolSummary] = []
    for spec in registry.all():
        if needle and needle not in spec.name.lower() and needle not in spec.description.lower():
            continue
        if category and spec.category != category:
            continue
        row = rows.get(spec.name)
        items.append(
            AdminToolSummary(
                **_summary(spec).model_dump(),
                enabled=bool(row.enabled) if row else spec.enabled,
                default_enabled=bool(row.default_enabled) if row else spec.enabled,
                available=spec.enabled,
                timeout_seconds=spec.timeout_seconds,
                registered_at=row.registered_at if row else None,
                updated_at=row.updated_at if row else None,
                registry_snapshot_revision=(
                    revisions.get(row.registry_snapshot_id)
                    if row and row.registry_snapshot_id
                    else None
                ),
            )
        )
    return items


@router.patch("/admin/tools/{tool_name}", response_model=AdminToolSummary)
async def toggle_tool(
    tool_name: str,
    payload: ToggleToolRequest,
    principal: Principal = Depends(require_admin),
    session: AsyncSession = Depends(db_session),
    registry: ToolRegistry = Depends(app_registry),
) -> AdminToolSummary:
    """
    Enable or disable a tool.

    Disabling is immediate: the gateway reads this table on every call, so the very next request -
    from the app, the assistant, or a scheduled rule - is refused.
    """
    spec = registry.get(tool_name)
    if spec is None:
        raise APIError.not_found(f"There is no tool named {tool_name!r}")
    row = (
        (await session.execute(select(ToolDefinition).where(ToolDefinition.name == tool_name)))
        .scalars()
        .one_or_none()
    )
    if row is None:
        raise APIError(
            ErrorCode.SERVICE_UNAVAILABLE,
            "The tool catalogue has not been synced yet; retry in a moment",
            status_code=503,
            retryable=True,
        )

    row.enabled = payload.enabled
    row.updated_at = utcnow()
    await record_event(
        session,
        name="admin.tool_toggled",
        outcome=AuditOutcome.SUCCEEDED,
        actor_user_id=principal.user_id,
        actor_role=principal.role,
        arguments={"tool": tool_name, "enabled": payload.enabled, "reason": payload.reason},
    )
    await session.commit()
    return AdminToolSummary(
        **_summary(spec).model_dump(),
        enabled=row.enabled,
        default_enabled=row.default_enabled,
        available=spec.enabled,
        timeout_seconds=spec.timeout_seconds,
        registered_at=row.registered_at,
        updated_at=row.updated_at,
    )
