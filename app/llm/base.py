# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
The model adapter contract.

A provider is a pure text-in/text-out component. It cannot call a tool, cannot touch the
database, and is never given a credential beyond its own API key. It returns either prose or a
*request* to call a named tool - a request the harness then hands to the Security Gateway, which
is free to refuse it.

Keeping the contract this small is what makes the LLM replaceable (OpenAI, Anthropic, Ollama,
any OpenAI-compatible endpoint) and keeps the untrusted part of the system genuinely untrusted.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

__all__ = [
    "LLMError",
    "LLMMessage",
    "LLMProvider",
    "LLMReply",
    "LLMToolCall",
    "LLMUnavailable",
    "Role",
]

Role = Literal["system", "user", "assistant", "tool"]


@dataclass(slots=True)
class LLMMessage:
    """One turn of the conversation handed to the model."""

    role: Role
    content: str
    tool_call_id: str | None = None
    name: str | None = None
    #: Present on an assistant turn that requested tools, so providers that require the request
    #: to be echoed in the transcript receive it unchanged.
    tool_calls: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.tool_call_id:
            payload["tool_call_id"] = self.tool_call_id
        if self.name:
            payload["name"] = self.name
        if self.tool_calls:
            payload["tool_calls"] = self.tool_calls
        return payload


@dataclass(slots=True)
class LLMToolCall:
    """A request from the model to call a tool. Nothing more than a request."""

    id: str
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class LLMReply:
    """What the model produced: prose, tool requests, or both."""

    text: str = ""
    tool_calls: list[LLMToolCall] = field(default_factory=list)
    finish_reason: str = "stop"
    usage: dict[str, int] = field(default_factory=dict)

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_calls)


class LLMError(Exception):
    """The provider returned an error that is the caller's fault (bad request, bad key)."""

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


class LLMUnavailable(LLMError):
    """The provider could not be reached, timed out, or returned a server error."""

    def __init__(self, message: str = "The model provider is unavailable") -> None:
        super().__init__(message, retryable=True)


class LLMProvider(Protocol):
    """What the harness needs from a model provider."""

    name: str

    async def complete(
        self,
        messages: Sequence[LLMMessage],
        *,
        tools: Sequence[dict[str, Any]] = (),
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMReply:
        """Produce the next assistant turn."""
        ...  # pragma: no cover - protocol definition

    async def aclose(self) -> None:
        """Release pooled connections."""
        ...  # pragma: no cover - protocol definition
