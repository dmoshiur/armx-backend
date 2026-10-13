# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Deterministic providers used by the default configuration, the tests and the demo profile.

``LLM_PROVIDER=mock`` is the default everywhere except an operator's real deployment, which is
why the whole assistant is testable without an API key, without network access and without a
model that behaves differently on every run.

Two providers live here:

* :class:`MockLLMProvider` - a small script interpreter. It answers a user turn with prose, and
  it will emit a tool *request* when the user turn asks for one in a simple, documented syntax
  (``call <tool_name> {json}``). It never executes anything.
* :class:`ScriptedLLMProvider` - replays a fixed list of replies, so a test can pin an exact
  multi-step conversation (call a tool, get refused, apologise, finish) and assert on it.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Sequence
from typing import Any

from app.llm.base import LLMMessage, LLMProvider, LLMReply, LLMToolCall

__all__ = ["CALL_PATTERN", "MockLLMProvider", "ScriptedLLMProvider"]

#: ``call set_light {"entity_id": "light.desk", "on": true}``
CALL_PATTERN = re.compile(
    r"^\s*call\s+(?P<name>[a-z][a-z0-9_]{0,63})\s*(?P<args>\{.*\})?\s*$", re.I
)


class MockLLMProvider(LLMProvider):
    """Deterministic, offline provider."""

    name = "mock"

    def __init__(self, *, model: str = "mock-planner", announce: bool = True) -> None:
        self.model = model
        self._announce = announce

    async def complete(
        self,
        messages: Sequence[LLMMessage],
        *,
        tools: Sequence[dict[str, Any]] = (),
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMReply:
        del temperature, max_tokens
        last_user = next(
            (message for message in reversed(messages) if message.role == "user"), None
        )
        pending_tool_results = [message for message in messages if message.role == "tool"]

        if pending_tool_results:
            summary = pending_tool_results[-1]
            body = summary.content.strip()
            if len(body) > 600:
                body = body[:600] + "..."
            return LLMReply(text=f"Here is what came back from the tool:\n{body}")

        text = (last_user.content if last_user else "").strip()
        match = CALL_PATTERN.match(text)
        if match:
            arguments: dict[str, Any] = {}
            raw_arguments = match.group("args")
            if raw_arguments:
                try:
                    parsed = json.loads(raw_arguments)
                    if isinstance(parsed, dict):
                        arguments = parsed
                except json.JSONDecodeError:
                    return LLMReply(
                        text=(
                            "I could not read that argument list as JSON. "
                            "Send it as a JSON object and I will try again."
                        )
                    )
            return LLMReply(
                text="",
                tool_calls=[
                    LLMToolCall(
                        id=f"call_{uuid.uuid4().hex[:12]}",
                        name=match.group("name").lower(),
                        arguments=arguments,
                    )
                ],
                finish_reason="tool_calls",
            )

        if pending_tool_results:
            summary = pending_tool_results[-1]
            body = summary.content.strip()
            if len(body) > 600:
                body = body[:600] + "..."
            return LLMReply(text=f"Here is what came back from the tool:\n{body}")

        offered = ", ".join(sorted(tool.get("name", "?") for tool in tools)[:12])
        if not text:
            return LLMReply(text="I did not receive a message.")
        if self._announce:
            return LLMReply(
                text=(
                    "I am the offline mock planner, so I can only describe what I would do. "
                    f"Available tools: {offered or 'none'}. "
                    'To make me request one, send: call <tool_name> {"argument": "value"}.'
                )
            )
        return LLMReply(text=text)

    async def aclose(self) -> None:
        return None


class ScriptedLLMProvider(LLMProvider):
    """
    Replay a fixed sequence of replies.

    Used by tests to pin a multi-turn conversation exactly. If the script runs out, the last
    reply is repeated - a test that needs a different script supplies one.
    """

    name = "scripted"

    def __init__(self, replies: Sequence[LLMReply]) -> None:
        if not replies:
            raise ValueError("a scripted provider needs at least one reply")
        self._replies = list(replies)
        self._index = 0
        self.calls: list[list[LLMMessage]] = []

    async def complete(
        self,
        messages: Sequence[LLMMessage],
        *,
        tools: Sequence[dict[str, Any]] = (),
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMReply:
        del tools, temperature, max_tokens
        self.calls.append(list(messages))
        reply = self._replies[min(self._index, len(self._replies) - 1)]
        self._index += 1
        return reply

    async def aclose(self) -> None:
        return None
