# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
The Security Gateway.

Every tool call in the system - from the assistant, from the REST API, from a schedule, from a
webhook, from the worker - goes through :meth:`SecurityGateway.invoke`. Nothing else executes a
tool handler. That single choke point is what makes the following statements true:

* The LLM cannot do anything except ask for a tool by name with arguments. It has no database
  handle, no network client and no authority: a request it produces is validated here exactly
  like a request typed into the app.
* Risk tier, scopes, rate limits, the kill-switch and approval requirements are read from
  server-side state on every call. None of them can be set by a client, a model or a tool result.
* The kill-switch is checked first and cannot be opted out of. While it is engaged only the tools
  on the explicit allowlist (health checks, by default) run.
* Every call produces exactly one audit row, including the ones that were denied, the ones that
  were only dry runs, and the ones that failed.

Ordering is deliberate. Cheap, decisive checks come first (kill-switch, enablement, scopes) so a
denied call never reaches a rate-limit write, and the approval is consumed as late as possible -
immediately before execution - so an approval is never spent on a call refused for another reason.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import record_event
from app.auth.scopes import has_all_scopes, missing_scopes
from app.config import Settings
from app.core.enums import ApprovalStatus, AuditOutcome, AuditSource, PermissionSubject, Role
from app.core.errors import APIError, ErrorCode
from app.core.logging import get_logger
from app.core.metrics import inc, observe
from app.core.privacy import hash_ip
from app.core.risk import Risk, requires_approval
from app.core.time import isoformat_z, utcnow
from app.db.models import Approval, ToolPermission
from app.registry.core import (
    ToolContext,
    ToolInvocationError,
    ToolRegistry,
    ToolResult,
    ToolSpec,
)
from app.registry.store import enabled_tool_names
from app.security.approvals import (
    ApprovalPolicy,
    action_hash,
    consume,
    create_approval,
    get_approval,
)
from app.security.kill_switch import KillSwitch
from app.security.ratelimit import RateLimiter, RateLimitResult, limit_key

__all__ = ["ActorRef", "InvocationOutcome", "SecurityGateway", "ToolDecision"]

logger = get_logger("security.gateway")

#: Sources that are allowed to assert an approval they already obtained themselves. Everything
#: else must present an approval row the user confirmed.
_SELF_APPROVING_SOURCES = frozenset({AuditSource.SCHEDULE, AuditSource.WEBHOOK})


@dataclass(slots=True)
class ActorRef:
    """
    Who is asking.

    ``user_id`` may be ``None`` for a device or a scheduled automation, which is why HIGH-tier
    tools cannot be invoked by such a principal: there is nobody to approve the action.
    """

    user_id: uuid.UUID | None = None
    role: Role | None = None
    scopes: frozenset[str] = field(default_factory=frozenset)
    label: str = "user"


@dataclass(slots=True)
class ToolDecision:
    """The authorization verdict for one proposed tool call."""

    allowed: bool
    spec: ToolSpec | None = None
    arguments: dict[str, Any] = field(default_factory=dict)
    error_code: str | None = None
    message: str = ""
    approval_id: uuid.UUID | None = None
    approved_row: Approval | None = None
    retry_after: int = 0
    rate_limit: RateLimitResult | None = None

    @property
    def risk(self) -> Risk | None:
        return self.spec.risk if self.spec else None


@dataclass(slots=True)
class InvocationOutcome:
    """What happened, in the shape the API, the harness and the audit trail all use."""

    status: str  # succeeded | failed | denied | pending_approval | dry_run
    tool_name: str
    tool_version: str = ""
    risk: Risk | None = None
    result: ToolResult | None = None
    error_code: str | None = None
    message: str = ""
    approval_id: uuid.UUID | None = None
    audit_id: uuid.UUID | None = None
    duration_ms: int = 0
    dry_run: bool = False
    retry_after: int = 0

    @property
    def ok(self) -> bool:
        return self.status in {"succeeded", "dry_run"}

    @property
    def denied(self) -> bool:
        return self.status == "denied"

    @property
    def needs_approval(self) -> bool:
        return self.status == "pending_approval"


class SecurityGateway:
    """Authorize, execute and audit a single tool call."""

    def __init__(self, settings: Settings, registry: ToolRegistry | None = None) -> None:
        self._settings = settings
        self._registry = registry
        self._limiter = RateLimiter(settings)
        self._kill_switch = KillSwitch(settings)

    # ------------------------------------------------------------------ public
    async def invoke(
        self,
        session: AsyncSession,
        *,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        actor: ActorRef,
        device_id: uuid.UUID | None = None,
        session_id: uuid.UUID | None = None,
        source: AuditSource = AuditSource.API,
        trace_id: str | None = None,
        ip_address: str | None = None,
        idempotency_key: str | None = None,
        dry_run: bool = False,
        approval_id: uuid.UUID | None = None,
        facts: dict[str, Any] | None = None,
        self_approved: bool = False,
        registry: ToolRegistry | None = None,
    ) -> InvocationOutcome:
        """
        The only way a tool runs.

        ``self_approved`` is honoured only for scheduled and webhook sources, where the trigger
        itself carries the owner's standing consent; the value is ignored (and logged) for an
        interactive request, so a client cannot skip the approval prompt.
        """
        started = time.perf_counter()
        registry = registry or self._registry
        arguments = _coerce_arguments(arguments)
        if self_approved and source not in _SELF_APPROVING_SOURCES:
            logger.warning(
                "ignoring self_approved for interactive source=%s tool=%s", source.value, tool_name
            )
            self_approved = False

        decision = await self._authorize(
            session,
            tool_name=tool_name,
            arguments=arguments,
            actor=actor,
            device_id=device_id,
            session_id=session_id,
            dry_run=dry_run,
            approval_id=approval_id,
            idempotency_key=idempotency_key,
            registry=registry,
            self_approved=self_approved,
        )

        if not decision.allowed:
            return await self._deny(
                session,
                decision=decision,
                tool_name=tool_name,
                arguments=arguments,
                actor=actor,
                device_id=device_id,
                session_id=session_id,
                source=source,
                trace_id=trace_id,
                ip_address=ip_address,
                idempotency_key=idempotency_key,
                dry_run=dry_run,
                started=started,
            )

        if decision.spec is None:  # pragma: no cover - _authorize always sets it when allowed
            raise APIError(ErrorCode.INTERNAL_ERROR, "Gateway returned no tool for an allowed call")
        return await self._execute(
            session,
            spec=decision.spec,
            arguments=decision.arguments,
            actor=actor,
            device_id=device_id,
            session_id=session_id,
            source=source,
            trace_id=trace_id,
            ip_address=ip_address,
            idempotency_key=idempotency_key,
            dry_run=dry_run,
            approval=decision.approved_row,
            facts=facts or {},
            started=started,
        )

    async def describe_tools(
        self,
        session: AsyncSession,
        *,
        actor: ActorRef,
        registry: ToolRegistry | None = None,
    ) -> list[dict[str, Any]]:
        """
        The tool catalogue this actor may use, in prompt-ready form.

        Disabled tools and tools the actor lacks a scope for are omitted: the model is never told
        about a capability that would be refused, which keeps it from proposing one and burning a
        turn. The list is rebuilt from server state on every call, so revoking a scope or
        disabling a tool takes effect immediately.
        """
        registry = registry or self._registry
        if registry is None:
            return []
        enabled_map = await enabled_tool_names(session)
        overrides = await self._permission_overrides(session, actor)
        catalogue: list[dict[str, Any]] = []
        for spec in registry.all():
            if not spec.enabled or enabled_map.get(spec.name) is False:
                continue
            if not self._override_allows(spec.name, overrides):
                continue
            if not has_all_scopes(actor.scopes, spec.required_scopes):
                continue
            catalogue.append(
                {
                    "name": spec.name,
                    "description": spec.description,
                    "risk": spec.risk.label,
                    "requires_approval": _needs_approval(spec),
                    "dry_run_supported": spec.dry_run_supported,
                    "arguments": spec.input_json_schema(),
                }
            )
        return catalogue

    # --------------------------------------------------------------- authorize
    async def _authorize(
        self,
        session: AsyncSession,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        actor: ActorRef,
        device_id: uuid.UUID | None,
        session_id: uuid.UUID | None,
        dry_run: bool,
        approval_id: uuid.UUID | None,
        idempotency_key: str | None,
        registry: ToolRegistry | None,
        self_approved: bool,
    ) -> ToolDecision:
        # 1. The kill-switch. Nothing runs while it is engaged except the allowlist.
        engaged = await self._kill_switch.is_engaged(session)
        if engaged and tool_name not in self._settings.kill_switch_allowed_tool_set:
            return ToolDecision(
                allowed=False,
                error_code=ErrorCode.KILL_SWITCH_ENGAGED,
                message=(
                    "The kill-switch is engaged: every action is stopped until it is "
                    "released in the admin console"
                ),
            )

        # 2. The tool must exist in the registry and be enabled.
        spec = registry.get(tool_name) if registry else None
        if spec is None:
            return ToolDecision(
                allowed=False,
                error_code=ErrorCode.TOOL_UNKNOWN,
                message=f"There is no tool named {tool_name!r}",
            )
        enabled_map = await enabled_tool_names(session)
        if enabled_map.get(spec.name) is False or not spec.enabled:
            return ToolDecision(
                allowed=False,
                spec=spec,
                error_code=ErrorCode.TOOL_DISABLED,
                message=f"The tool {tool_name!r} is disabled",
            )

        # 3. Operator permission overrides (user beats role beats global).
        overrides = await self._permission_overrides(session, actor)
        if not self._override_allows(spec.name, overrides):
            return ToolDecision(
                allowed=False,
                spec=spec,
                error_code=ErrorCode.FORBIDDEN,
                message=f"The tool {tool_name!r} is not permitted for this account",
            )

        # 4. Scopes, taken from the actor's stored role.
        missing = missing_scopes(actor.scopes, spec.required_scopes)
        if missing:
            return ToolDecision(
                allowed=False,
                spec=spec,
                error_code=ErrorCode.SCOPE_REQUIRED,
                message="Missing scope: " + ", ".join(missing),
            )

        # 5. Arguments are validated against the manifest schema before anything uses them.
        try:
            validated = spec.input_schema.model_validate(arguments)
        except ValidationError as exc:
            fields = sorted({str(err.get("loc", ("",))[-1]) for err in exc.errors()})
            return ToolDecision(
                allowed=False,
                spec=spec,
                error_code=ErrorCode.TOOL_ARGUMENT_INVALID,
                message=f"Invalid arguments for {spec.name}: {', '.join(fields[:8])}",
            )
        effective = validated.model_dump(mode="json")

        # 6. Rate limits: the tool's own limit, then the global per-actor default.
        limited = await self._rate_limit(session, spec=spec, actor=actor, device_id=device_id)
        if limited is not None:
            return ToolDecision(
                allowed=False,
                spec=spec,
                error_code=ErrorCode.RATE_LIMITED,
                message=f"Rate limit reached for {tool_name!r}",
                retry_after=limited.retry_after_seconds,
                rate_limit=limited,
            )

        # 7. A dry run explains what would happen without doing it, so it needs no approval.
        if dry_run:
            if not spec.dry_run_supported:
                return ToolDecision(
                    allowed=False,
                    spec=spec,
                    error_code=ErrorCode.DRY_RUN_ONLY,
                    message=f"{tool_name!r} cannot be run as a dry run",
                )
            return ToolDecision(allowed=True, spec=spec, arguments=effective)

        # 8. Approvals.
        if not _needs_approval(spec):
            return ToolDecision(allowed=True, spec=spec, arguments=effective)

        if actor.user_id is None:
            # There is nobody to approve it, so this is a refusal rather than a pending decision -
            # recording it as pending would claim an approval exists that never can.
            return ToolDecision(
                allowed=False,
                spec=spec,
                error_code=ErrorCode.FORBIDDEN,
                message="This action needs a signed-in user to approve it",
            )

        if approval_id is None:
            if self_approved:
                return ToolDecision(allowed=True, spec=spec, arguments=effective)
            created = await create_approval(
                session,
                self._settings,
                tool_name=spec.name,
                tool_version=spec.version,
                risk=spec.risk,
                arguments=effective,
                actor_user_id=actor.user_id,
                device_id=device_id,
                session_id=session_id,
                idempotency_key=idempotency_key,
            )
            await session.commit()
            return ToolDecision(
                allowed=False,
                spec=spec,
                error_code=ErrorCode.APPROVAL_REQUIRED,
                message="This action needs your explicit approval before it runs",
                approval_id=created.id,
            )

        approval = await get_approval(session, approval_id)
        if approval is None or approval.actor_user_id != actor.user_id:
            return ToolDecision(
                allowed=False,
                spec=spec,
                error_code=ErrorCode.APPROVAL_INVALID,
                message="That approval does not exist for this account",
            )
        if approval.consumed_at is not None:
            return ToolDecision(
                allowed=False,
                spec=spec,
                error_code=ErrorCode.APPROVAL_ALREADY_USED,
                message="That approval has already been used",
                approval_id=approval.id,
            )
        if approval.status is ApprovalStatus.DENIED:
            return ToolDecision(
                allowed=False,
                spec=spec,
                error_code=ErrorCode.APPROVAL_DENIED,
                message="That action was denied",
                approval_id=approval.id,
            )
        if approval.status is ApprovalStatus.EXPIRED or approval.expires_at <= utcnow():
            return ToolDecision(
                allowed=False,
                spec=spec,
                error_code=ErrorCode.APPROVAL_EXPIRED,
                message="That approval has expired; ask again",
                approval_id=approval.id,
            )
        if approval.status is ApprovalStatus.PENDING:
            return ToolDecision(
                allowed=False,
                spec=spec,
                error_code=ErrorCode.APPROVAL_REQUIRED,
                message="Confirm the action first",
                approval_id=approval.id,
            )
        if approval.tool_name != spec.name:
            return ToolDecision(
                allowed=False,
                spec=spec,
                error_code=ErrorCode.APPROVAL_ARGUMENT_MISMATCH,
                message="That approval was granted for a different action",
                approval_id=approval.id,
            )

        expected = action_hash(
            ApprovalPolicy(
                tool_name=spec.name,
                tool_version=spec.version,
                arguments=effective,
                actor_user_id=actor.user_id,
                device_id=device_id,
                session_id=session_id,
                nonce=approval.nonce,
                expires_at=isoformat_z(approval.expires_at),
            )
        )
        if approval.action_hash != expected:
            return ToolDecision(
                allowed=False,
                spec=spec,
                error_code=ErrorCode.APPROVAL_ARGUMENT_MISMATCH,
                message="The arguments changed after approval; request a new one",
                approval_id=approval.id,
            )
        return ToolDecision(
            allowed=True,
            spec=spec,
            arguments=effective,
            approval_id=approval.id,
            approved_row=approval,
        )

    # ----------------------------------------------------------------- helpers
    async def _permission_overrides(
        self, session: AsyncSession, actor: ActorRef
    ) -> dict[str, dict[str, bool]]:
        """
        Explicit allow/deny rows, keyed by tool name.

        The table is small (an operator sets a handful of exceptions), so it is read on every
        decision rather than cached: a denial must take effect immediately.
        """
        rows = (await session.execute(select(ToolPermission))).scalars().all()
        resolved: dict[str, dict[str, bool]] = {}
        role = actor.role.value if actor.role else ""
        user_id = str(actor.user_id) if actor.user_id else ""
        for row in rows:
            if row.subject_type is PermissionSubject.GLOBAL:
                resolved.setdefault(row.tool_name, {}).setdefault("global", row.allowed)
            elif row.subject_type is PermissionSubject.ROLE and row.subject_id == role:
                resolved.setdefault(row.tool_name, {})["role"] = row.allowed
            elif row.subject_type is PermissionSubject.USER and row.subject_id == user_id:
                resolved.setdefault(row.tool_name, {})["user"] = row.allowed
        return resolved

    @staticmethod
    def _override_allows(tool_name: str, overrides: dict[str, dict[str, bool]]) -> bool:
        buckets = overrides.get(tool_name)
        if not buckets:
            return True
        for level in ("user", "role", "global"):
            if level in buckets:
                return bool(buckets[level])
        return True

    async def _rate_limit(
        self,
        session: AsyncSession,
        *,
        spec: ToolSpec,
        actor: ActorRef,
        device_id: uuid.UUID | None,
    ) -> RateLimitResult | None:
        """
        Apply the tool's own limit and then the global per-actor default.

        The device is part of the key: a compromised phone cannot spend the desktop's budget.
        """
        counters: list[tuple[str, Any]] = [
            (
                limit_key(
                    "tool", spec.name, str(actor.user_id or "anon"), str(device_id or "nodevice")
                ),
                spec.rate_limit_spec,
            ),
            (
                limit_key("tool-global", str(actor.user_id or "anon")),
                self._settings.default_rate_limit_spec,
            ),
        ]
        for key, rate_spec in counters:
            result = await self._limiter.check(session, key=key, spec=rate_spec)
            if not result.allowed:
                return result
        return None

    async def _deny(
        self,
        session: AsyncSession,
        *,
        decision: ToolDecision,
        tool_name: str,
        arguments: dict[str, Any],
        actor: ActorRef,
        device_id: uuid.UUID | None,
        session_id: uuid.UUID | None,
        source: AuditSource,
        trace_id: str | None,
        ip_address: str | None,
        idempotency_key: str | None,
        dry_run: bool,
        started: float,
    ) -> InvocationOutcome:
        pending = decision.error_code == ErrorCode.APPROVAL_REQUIRED
        outcome = AuditOutcome.PENDING_APPROVAL if pending else AuditOutcome.DENIED
        event = await record_event(
            session,
            name=tool_name,
            outcome=outcome,
            risk=decision.risk,
            tool_version=decision.spec.version if decision.spec else "",
            actor_user_id=actor.user_id,
            actor_role=actor.role,
            device_id=device_id,
            session_id=session_id,
            arguments=arguments,
            error_code=decision.error_code,
            result_summary=decision.message,
            duration_ms=int((time.perf_counter() - started) * 1000),
            trace_id=trace_id,
            approval_id=decision.approval_id,
            idempotency_key=idempotency_key,
            ip_hash=hash_ip(ip_address, salt=self._settings.jwt_key()),
            source=source,
            dry_run=dry_run,
        )
        await session.commit()
        inc("tool_calls", {"tool": tool_name, "outcome": outcome.value})
        return InvocationOutcome(
            status="pending_approval" if pending else "denied",
            tool_name=tool_name,
            tool_version=decision.spec.version if decision.spec else "",
            risk=decision.risk,
            error_code=decision.error_code,
            message=decision.message,
            approval_id=decision.approval_id,
            audit_id=event.id,
            duration_ms=int((time.perf_counter() - started) * 1000),
            dry_run=dry_run,
            retry_after=decision.retry_after,
        )

    async def _execute(
        self,
        session: AsyncSession,
        *,
        spec: ToolSpec,
        arguments: dict[str, Any],
        actor: ActorRef,
        device_id: uuid.UUID | None,
        session_id: uuid.UUID | None,
        source: AuditSource,
        trace_id: str | None,
        ip_address: str | None,
        idempotency_key: str | None,
        dry_run: bool,
        approval: Approval | None,
        facts: dict[str, Any],
        started: float,
    ) -> InvocationOutcome:
        context = ToolContext(
            settings=self._settings,
            session=session,
            actor_id=actor.user_id,
            actor_role=actor.role,
            device_id=device_id,
            session_id=session_id,
            trace_id=trace_id or "",
            dry_run=dry_run,
            approval_id=approval.id if approval else None,
            idempotency_key=idempotency_key,
            ip_address=ip_address,
            started_at=utcnow(),
            facts={**facts, "arguments": arguments},
        )

        error_code: str | None = None
        message = ""
        if approval is not None:
            # Spend the approval last: an action refused for any other reason must not cost the
            # user their approval. This is also the single moment the approval becomes unusable.
            try:
                await consume(
                    session,
                    approval,
                    expected_action_hash=approval.action_hash,
                    expected_tool=spec.name,
                )
            except APIError as exc:
                await session.commit()
                event = await record_event(
                    session,
                    name=spec.name,
                    outcome=AuditOutcome.DENIED,
                    risk=spec.risk,
                    tool_version=spec.version,
                    actor_user_id=actor.user_id,
                    actor_role=actor.role,
                    device_id=device_id,
                    session_id=session_id,
                    arguments=arguments,
                    error_code=exc.code,
                    result_summary=exc.message,
                    trace_id=trace_id,
                    approval_id=approval.id,
                    idempotency_key=idempotency_key,
                    source=source,
                )
                await session.commit()
                return InvocationOutcome(
                    status="denied",
                    tool_name=spec.name,
                    tool_version=spec.version,
                    risk=spec.risk,
                    error_code=exc.code,
                    message=exc.message,
                    approval_id=approval.id,
                    audit_id=event.id,
                    duration_ms=int((time.perf_counter() - started) * 1000),
                )

        timeout = spec.timeout_seconds or self._settings.harness_tool_timeout_seconds
        try:
            async with asyncio.timeout(timeout):
                raw = await spec.handler(spec.input_schema.model_validate(arguments), context)
            result = _normalise_result(raw, spec=spec, dry_run=dry_run)
        except TimeoutError:
            error_code = ErrorCode.TOOL_TIMEOUT
            message = f"{spec.name} did not finish within {timeout:g}s"
            result = ToolResult(ok=False, error_code=error_code, error_message=message)
        except ToolInvocationError as exc:
            error_code = exc.code
            message = exc.message
            result = ToolResult(ok=False, error_code=exc.code, error_message=exc.message)
        except ValidationError as exc:
            error_code = ErrorCode.TOOL_FAILED
            message = f"{spec.name} returned a result that does not match its manifest"
            logger.error(
                "tool %s output validation failed (%d errors)", spec.name, exc.error_count()
            )
            result = ToolResult(ok=False, error_code=error_code, error_message=message)
        except Exception as exc:
            error_code = ErrorCode.TOOL_FAILED
            message = f"{spec.name} failed"
            logger.exception("tool %s raised %s", spec.name, type(exc).__name__)
            result = ToolResult(ok=False, error_code=error_code, error_message=message)

        if not result.ok and error_code is None:
            # The handler reported a failure without raising: keep its own code and wording so
            # the audit trail distinguishes "the tool said no" from "the tool broke".
            error_code = result.error_code or ErrorCode.TOOL_FAILED
            message = result.error_message or result.summary

        duration_ms = int((time.perf_counter() - started) * 1000)
        if dry_run:
            audit_outcome = AuditOutcome.DRY_RUN
        else:
            audit_outcome = AuditOutcome.SUCCEEDED if result.ok else AuditOutcome.FAILED

        event = await record_event(
            session,
            name=spec.name,
            outcome=audit_outcome,
            risk=spec.risk,
            tool_version=spec.version,
            actor_user_id=actor.user_id,
            actor_role=actor.role,
            device_id=device_id,
            session_id=session_id,
            arguments=arguments,
            error_code=error_code,
            result_summary=result.summary or message,
            duration_ms=duration_ms,
            trace_id=trace_id,
            approval_id=approval.id if approval else None,
            idempotency_key=idempotency_key,
            ip_hash=hash_ip(ip_address, salt=self._settings.jwt_key()),
            source=source,
            dry_run=dry_run,
        )
        await session.commit()

        inc("tool_calls", {"tool": spec.name, "outcome": audit_outcome.value})
        observe("tool_duration", duration_ms / 1000.0, {"tool": spec.name})
        if not result.ok:
            logger.warning(
                "tool %s failed code=%s duration_ms=%d", spec.name, error_code, duration_ms
            )

        return InvocationOutcome(
            status="dry_run" if dry_run else ("succeeded" if result.ok else "failed"),
            tool_name=spec.name,
            tool_version=spec.version,
            risk=spec.risk,
            result=result,
            error_code=error_code,
            message=message or result.summary,
            approval_id=approval.id if approval else None,
            audit_id=event.id,
            duration_ms=duration_ms,
            dry_run=dry_run,
        )


def _needs_approval(spec: ToolSpec) -> bool:
    return requires_approval(spec.risk, confirm=spec.confirm)


def _coerce_arguments(arguments: dict[str, Any] | None) -> dict[str, Any]:
    """
    Accept only a JSON object as the argument bag.

    A list, string or number is a programming error on the caller's side and is treated as an
    invalid argument set rather than being coerced into one.
    """
    if arguments is None:
        return {}
    if isinstance(arguments, dict):
        return arguments
    return {"__invalid__": True}


def _normalise_result(raw: Any, *, spec: ToolSpec, dry_run: bool) -> ToolResult:
    """
    Turn whatever a handler returned into a :class:`ToolResult`.

    A handler may return the declared output model, a plain dict matching it, or a ``ToolResult``
    when it has something to say about trust, dry runs or external effects.
    """
    if isinstance(raw, ToolResult):
        result = raw
    else:
        payload = raw.model_dump(mode="json") if isinstance(raw, BaseModel) else raw
        validated = spec.output_schema.model_validate(payload)
        result = ToolResult(data=validated.model_dump(mode="json"))
        summary = getattr(validated, "summary", None)
        if isinstance(summary, str) and summary:
            result.summary = summary
    if dry_run:
        result.dry_run = True
    return result
