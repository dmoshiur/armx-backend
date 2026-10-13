# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
The tool registry.

A tool is a small, typed, auditable capability:

```python
@tool(
    name="set_light",
    version="1.0",
    description="Turn a named light/relay on or off through Home Assistant.",
    risk=Risk.LOW,
    enabled=True,
    input_schema=SetLightInput,
    output_schema=SetLightOutput,
    required_scopes=["smart_home:write"],
    confirm=False,
    rate_limit="30/hour",
    dry_run_supported=True,
)
async def set_light(args: SetLightInput, ctx: ToolContext) -> SetLightOutput:
    ...
```

Invariants enforced here:

* Registration rejects duplicate names, non-pydantic schemas, unparseable rate limits, and
  HIGH-risk tools that do not declare ``confirm=True``.
* A tool function never decides its own risk tier, rate limit or approval requirement - those
  are manifest properties read by the Security Gateway.
* Tools are discovered from first-party code only (:mod:`app.registry.discovery`). Nothing
  uploads or hot-loads a tool at runtime.
"""

from __future__ import annotations

import inspect
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final

from pydantic import BaseModel, ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.core.enums import Role
from app.core.ratelimit_spec import RateLimitSpec, parse_rate_limit
from app.core.risk import Risk
from app.core.time import utcnow

__all__ = [
    "ToolContext",
    "ToolInvocationError",
    "ToolRegistry",
    "ToolResult",
    "ToolSpec",
    "collected_specs",
    "tool",
]


class ToolInvocationError(Exception):
    """Raised by a tool when it cannot complete; carries a stable error code."""

    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable


@dataclass(slots=True)
class ToolContext:
    """
    Everything a tool is allowed to know about its caller.

    Deliberately does not include the raw request, the LLM conversation, or any credential.
    Tools receive an already-authorized call: the Security Gateway has checked scopes, rate
    limits, the kill-switch and (where required) a fresh approval before this object exists.
    """

    settings: Settings
    session: AsyncSession | None = None
    actor_id: uuid.UUID | None = None
    actor_role: Role | None = None
    device_id: uuid.UUID | None = None
    session_id: uuid.UUID | None = None
    trace_id: str = ""
    dry_run: bool = False
    approval_id: uuid.UUID | None = None
    idempotency_key: str | None = None
    ip_address: str | None = None
    registry_snapshot_id: uuid.UUID | None = None
    started_at: datetime = field(default_factory=utcnow)
    #: Extra, gateway-verified facts (never client-supplied). For example the resolved
    #: destination of a deploy, or the owner of a linked device.
    facts: dict[str, Any] = field(default_factory=dict)


class ToolResult(BaseModel):
    """
    Normalised tool output.

    ``untrusted`` marks content that came from outside the trust boundary (web pages, email
    bodies, repository files, MCP results). The harness forwards such content to the model
    wrapped in data-only delimiters, so it can never be read as instructions.
    """

    ok: bool = True
    summary: str = ""
    data: dict[str, Any] = {}
    error_code: str | None = None
    error_message: str | None = None
    untrusted: bool = False
    dry_run: bool = False
    external_effects: bool = False
    job_id: uuid.UUID | None = None


ToolHandler = Callable[[Any, ToolContext], Awaitable[Any]]


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """Immutable manifest for one registered tool."""

    name: str
    version: str
    description: str
    risk: Risk
    enabled: bool
    input_schema: type[BaseModel]
    output_schema: type[BaseModel]
    handler: ToolHandler
    required_scopes: tuple[str, ...] = ()
    confirm: bool = False
    rate_limit: str = "60/hour"
    dry_run_supported: bool = False
    category: str = "general"
    integration: str | None = None
    timeout_seconds: float | None = None

    def __post_init__(self) -> None:
        # Validate eagerly so a broken manifest fails at import, not on first user request.
        if not self.name or not self.name.replace("_", "").replace(".", "").isalnum():
            raise ValueError(f"tool name must be alphanumeric/underscore: {self.name!r}")
        if len(self.name) > 64:
            raise ValueError(f"tool name too long: {self.name!r}")
        if "." in self.name:
            raise ValueError(f"tool name must be a bare identifier, not namespaced: {self.name!r}")
        if not isinstance(self.risk, Risk):
            raise ValueError(f"tool {self.name!r} must declare a Risk value")
        if not (isinstance(self.input_schema, type) and issubclass(self.input_schema, BaseModel)):
            raise ValueError(f"tool {self.name!r} input_schema must be a pydantic model")
        if not (isinstance(self.output_schema, type) and issubclass(self.output_schema, BaseModel)):
            raise ValueError(f"tool {self.name!r} output_schema must be a pydantic model")
        if not callable(self.handler):
            raise ValueError(f"tool {self.name!r} handler must be callable")
        if not inspect.iscoroutinefunction(self.handler):
            raise ValueError(f"tool {self.name!r} handler must be async")
        parse_rate_limit(self.rate_limit)
        if self.risk is Risk.HIGH and not self.confirm:
            raise ValueError(
                f"tool {self.name!r} is HIGH risk and must declare confirm=True "
                "(a HIGH action always requires a fresh approval)"
            )

    @property
    def rate_limit_spec(self) -> RateLimitSpec:
        return parse_rate_limit(self.rate_limit)

    def input_json_schema(self) -> dict[str, Any]:
        return self.input_schema.model_json_schema()

    def output_json_schema(self) -> dict[str, Any]:
        return self.output_schema.model_json_schema()

    def manifest(self) -> dict[str, Any]:
        """Serialisable description used for the registry snapshot and the database mirror."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "risk": self.risk.label,
            "enabled": self.enabled,
            "required_scopes": list(self.required_scopes),
            "confirm": self.confirm,
            "rate_limit": self.rate_limit,
            "dry_run_supported": self.dry_run_supported,
            "category": self.category,
            "integration": self.integration,
            "timeout_seconds": self.timeout_seconds,
            "input_schema": self.input_json_schema(),
            "output_schema": self.output_json_schema(),
        }


class ToolRegistry:
    """An immutable-after-registration collection of tool specs."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}
        self._frozen = False

    def register(self, spec: ToolSpec) -> ToolSpec:
        if self._frozen:
            raise RuntimeError("the tool registry is frozen; registration happens at startup only")
        if spec.name in self._tools:
            existing = self._tools[spec.name]
            raise ValueError(
                f"duplicate tool name {spec.name!r}: already registered at version "
                f"{existing.version}"
            )
        self._tools[spec.name] = spec
        return spec

    def freeze(self) -> None:
        """Called once discovery completes; nothing may register afterwards."""
        self._frozen = True

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, name: object) -> bool:
        return name in self._tools

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def all(self) -> tuple[ToolSpec, ...]:
        return tuple(self._tools[name] for name in sorted(self._tools))

    def enabled(self) -> tuple[ToolSpec, ...]:
        return tuple(spec for spec in self.all() if spec.enabled)

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))

    def snapshot_manifest(self) -> list[dict[str, Any]]:
        return [spec.manifest() for spec in self.all()]


#: Specs collected by the decorator at first import. This mapping lives for the whole
#: process: Python imports each tool module exactly once, so a second discovery pass must
#: read what the first pass collected rather than expecting the decorators to run again.
_COLLECTED: dict[str, ToolSpec] = {}

#: The process-wide registry, populated by :func:`app.registry.discovery.discover_tools`.
registry: Final[ToolRegistry] = ToolRegistry()


def collected_specs() -> tuple[ToolSpec, ...]:
    """Every spec declared by :func:`tool` so far, in declaration order."""
    return tuple(_COLLECTED.values())


def tool(
    *,
    name: str,
    version: str,
    description: str,
    risk: Risk,
    enabled: bool = True,
    input_schema: type[BaseModel],
    output_schema: type[BaseModel],
    required_scopes: list[str] | tuple[str, ...] = (),
    confirm: bool = False,
    rate_limit: str = "60/hour",
    dry_run_supported: bool = False,
    category: str = "general",
    integration: str | None = None,
    timeout_seconds: float | None = None,
) -> Callable[[ToolHandler], ToolHandler]:
    """
    Declare a tool.

    Returns the handler unchanged, so the module-level function stays directly callable and
    importable (typed, testable, and reviewable with a plain editor jump-to-definition).
    """

    def decorator(handler: ToolHandler) -> ToolHandler:
        spec = ToolSpec(
            name=name,
            version=version,
            description=description,
            risk=risk,
            enabled=enabled,
            input_schema=input_schema,
            output_schema=output_schema,
            handler=handler,
            required_scopes=tuple(required_scopes),
            confirm=confirm,
            rate_limit=rate_limit,
            dry_run_supported=dry_run_supported,
            category=category,
            integration=integration,
            timeout_seconds=timeout_seconds,
        )
        _COLLECTED[spec.name] = spec
        return handler

    return decorator


def validate_arguments(spec: ToolSpec, arguments: Any) -> Any:
    """
    Validate raw arguments against the tool's schema.

    Raises :class:`ToolInvocationError` with a stable code so the gateway can audit a rejected
    call without echoing the client's payload back.
    """
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        raise ToolInvocationError("tool_argument_invalid", "Tool arguments must be a JSON object")
    try:
        return spec.input_schema.model_validate(arguments)
    except ValidationError as exc:
        fields = sorted({str(error["loc"][0]) for error in exc.errors() if error.get("loc")})
        raise ToolInvocationError(
            "tool_argument_invalid",
            f"Invalid arguments for {spec.name}: {', '.join(fields[:10])}",
        ) from exc
