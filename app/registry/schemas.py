# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""API models for the tool catalogue, direct invocation and the admin toggles."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "AdminToolSummary",
    "InvocationResponse",
    "InvokeRequest",
    "ToggleToolRequest",
    "ToolListResponse",
    "ToolSummary",
]


class ToolSummary(BaseModel):
    """A tool as a client may see it: what it does, what it costs, what it needs."""

    name: str
    version: str
    description: str
    risk: str
    category: str
    integration: str | None = None
    required_scopes: list[str] = Field(default_factory=list)
    requires_approval: bool
    dry_run_supported: bool
    rate_limit: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]


class AdminToolSummary(ToolSummary):
    """The administrative view adds operator state and expiry-relevant metadata."""

    enabled: bool
    default_enabled: bool
    available: bool
    timeout_seconds: float | None = None
    registered_at: datetime | None = None
    updated_at: datetime | None = None
    registry_snapshot_revision: int | None = None


class ToolListResponse(BaseModel):
    items: list[ToolSummary]
    total: int


class InvokeRequest(BaseModel):
    """
    Direct invocation of one tool.

    The API is a thin client of exactly the same path the assistant uses, which is deliberate:
    anything the app can do, the model can only *propose*, and both go through the same checks.
    """

    model_config = ConfigDict(extra="forbid")

    arguments: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = False
    approval_id: uuid.UUID | None = None
    idempotency_key: str | None = Field(default=None, max_length=80)


class InvocationResponse(BaseModel):
    status: str
    tool: str
    tool_version: str = ""
    risk: str | None = None
    dry_run: bool = False
    summary: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    error_code: str | None = None
    message: str = ""
    approval_id: uuid.UUID | None = None
    audit_id: uuid.UUID | None = None
    duration_ms: int = 0
    retry_after: int = 0


class ToggleToolRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool
    reason: str = Field(default="", max_length=200)
