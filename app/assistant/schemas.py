# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""API models for the assistant surface."""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "AssistantEvent",
    "AssistantMessageRequest",
    "AssistantMessageResponse",
    "HistoryMessage",
]


class HistoryMessage(BaseModel):
    """
    One earlier turn supplied by the client.

    Only ``user`` and ``assistant`` roles are accepted; the system prompt and every tool result
    are generated server-side on each request, so a client cannot inject either.
    """

    model_config = ConfigDict(extra="forbid")

    role: str = Field(pattern="^(user|assistant)$")
    content: str = Field(min_length=1, max_length=8000)


class AssistantMessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=8000)
    history: list[HistoryMessage] = Field(default_factory=list, max_length=40)
    dry_run: bool = False
    device_name: str = Field(default="", max_length=120)


class AssistantEvent(BaseModel):
    """One step of the turn, as it happened."""

    type: str
    data: dict[str, Any] = Field(default_factory=dict)


class AssistantMessageResponse(BaseModel):
    status: str
    reply: str = ""
    events: list[AssistantEvent] = Field(default_factory=list)
    tool_calls: int = 0
    model_turns: int = 0
    pending_approvals: list[uuid.UUID] = Field(default_factory=list)
    error_code: str | None = None
    duration_ms: int = 0
    usage: dict[str, int] = Field(default_factory=dict)
