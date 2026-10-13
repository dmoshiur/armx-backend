# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""API models for the approval prompt."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["ApprovalDecisionRequest", "ApprovalListResponse", "ApprovalSummary"]


class ApprovalSummary(BaseModel):
    """
    What the user is being asked to approve.

    ``arguments`` is the redacted argument set: the prompt shows what will happen, and a password
    or token that happens to be an argument is never rendered back to the client.
    """

    id: uuid.UUID
    tool: str
    tool_version: str
    risk: str
    status: str
    summary: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    expires_at: datetime
    seconds_remaining: int
    single_use: bool = True
    decided_at: datetime | None = None
    deny_reason: str | None = None
    consumed_at: datetime | None = None
    trace_id: str | None = None


class ApprovalListResponse(BaseModel):
    items: list[ApprovalSummary]
    total: int


class ApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(default="", max_length=200)
