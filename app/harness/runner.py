# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
The bounded assistant loop.

One turn of the assistant is: build the system prompt from server state, let the model reply,
and - if it asked for tools - hand each request to the Security Gateway, then feed the *result*
back to the model and repeat, until the model answers without asking for a tool or a limit stops
it.

Limits are not decoration. They bound the blast radius of a model that loops, of a tool that
hangs, and of a prompt-injection attempt that tries to make the assistant call tools forever:

* ``harness_max_model_turns``  - round trips to the provider
* ``harness_max_tool_calls``   - executed tool calls per turn
* ``harness_deadline_seconds`` - wall-clock budget for the whole turn
* ``harness_max_result_chars`` - how much tool output the model ever sees

The loop treats the model's output as a *proposal* throughout. A tool request for something
unknown or disabled is refused and reported back as an error result - it is never executed, and
the refusal is audited like any other denied call.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.core.enums import AuditSource, Role
from app.core.errors import ErrorCode
from app.core.logging import get_logger
from app.core.metrics import inc
from app.harness.prompts import build_system_prompt, format_tool_result, tool_definitions
from app.llm.base import LLMError, LLMMessage, LLMProvider, LLMReply, LLMUnavailable
from app.registry.core import ToolRegistry, ToolResult
from app.security.gateway import ActorRef, InvocationOutcome, SecurityGateway

__all__ = ["HarnessEvent", "HarnessLimits", "HarnessTurn", "run_turn"]

logger = get_logger("harness.runner")

EventSink = Callable[[str, dict[str, Any]], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class HarnessLimits:
    """Per-turn budgets, taken from settings."""

    max_model_turns: int = 6
    max_tool_calls: int = 8
    deadline_seconds: float = 120.0
    max_result_chars: int = 8000
    max_history_messages: int = 40
    temperature: float = 0.2
    max_tokens: int = 1024
    model_timeout_seconds: float = 45.0

    @classmethod
    def from_settings(cls, settings: Settings) -> HarnessLimits:
        return cls(
            max_model_turns=settings.harness_max_model_turns,
            max_tool_calls=settings.harness_max_tool_calls,
            deadline_seconds=settings.harness_deadline_seconds,
            max_result_chars=settings.harness_max_result_chars,
            max_history_messages=settings.harness_max_history_messages,
            temperature=settings.llm_temperature,
            max_tokens=settings.llm_max_tokens,
            model_timeout_seconds=settings.llm_timeout_seconds,
        )


@dataclass(slots=True)
class HarnessEvent:
    """One step of the turn, in the order the client should display them."""

    type: str  # text | tool_call | tool_result | approval_required | error | final
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class HarnessTurn:
    """The complete result of one assistant turn."""

    status: str  # completed | needs_approval | limit_exceeded | deadline_exceeded | llm_error
    reply: str = ""
    events: list[HarnessEvent] = field(default_factory=list)
    tool_calls: int = 0
    model_turns: int = 0
    pending_approvals: list[uuid.UUID] = field(default_factory=list)
    error_code: str | None = None
    duration_ms: int = 0
    usage: dict[str, int] = field(default_factory=dict)


def _history_messages(history: Sequence[dict[str, Any]], *, limit: int) -> list[LLMMessage]:
    """
    Convert and cap client-supplied history.

    The client is not trusted, so only the two roles that make sense from a client are accepted
    and the count is bounded; the system prompt and tool results are always server-generated.
    """
    messages: list[LLMMessage] = []
    for entry in list(history)[-limit:]:
        if not isinstance(entry, dict):
            continue
        role = str(entry.get("role", "")).lower()
        content = entry.get("content")
        if role not in {"user", "assistant"} or not isinstance(content, str) or not content.strip():
            continue
        messages.append(LLMMessage(role=role, content=content[:8000]))  # type: ignore[arg-type]
    return messages


def _result_text(outcome: InvocationOutcome, *, max_chars: int) -> tuple[str, bool]:
    """
    Render the outcome for the model, and report whether the content is untrusted.

    A denied or pending call is described precisely, because the model has to be able to tell the
    user what happened. A successful call's payload is only marked untrusted when the tool said so.
    """
    if outcome.needs_approval:
        payload = json.dumps(
            {
                "status": "pending_approval",
                "approval_id": str(outcome.approval_id),
                "message": outcome.message,
                "risk": outcome.risk.label if outcome.risk else None,
            },
            separators=(",", ":"),
        )
        return payload, False
    if outcome.denied:
        payload = json.dumps(
            {"status": "denied", "code": outcome.error_code, "message": outcome.message},
            separators=(",", ":"),
        )
        return payload, False
    result: ToolResult | None = outcome.result
    if result is None:
        return json.dumps({"status": outcome.status}, separators=(",", ":")), False
    body = {
        "status": outcome.status,
        "summary": result.summary[:1000],
        "data": result.data,
    }
    if result.error_code:
        body["error"] = {"code": result.error_code, "message": (result.error_message or "")[:500]}
    rendered = json.dumps(body, separators=(",", ":"), default=str)
    if len(rendered) > max_chars:
        rendered = rendered[: max_chars - 3] + "..."
    return rendered, bool(result.untrusted)


async def run_turn(
    session: AsyncSession,
    *,
    settings: Settings,
    provider: LLMProvider,
    registry: ToolRegistry,
    actor: ActorRef,
    user_message: str,
    history: Sequence[dict[str, Any]] | None = None,
    device_id: uuid.UUID | None = None,
    session_id: uuid.UUID | None = None,
    trace_id: str | None = None,
    ip_address: str | None = None,
    dry_run: bool = False,
    emit: EventSink | None = None,
    limits: HarnessLimits | None = None,
) -> HarnessTurn:
    """
    Run one assistant turn to completion (or to a limit).

    ``emit`` is called for every event as it happens, which is what the WebSocket endpoint streams.
    The same events are returned in the final result, so a non-streaming caller sees exactly the
    same transcript.
    """
    started = time.perf_counter()
    limits = limits or HarnessLimits.from_settings(settings)
    gateway = SecurityGateway(settings, registry)
    turn = HarnessTurn(status="completed")
    events: list[HarnessEvent] = []

    async def publish(event_type: str, data: dict[str, Any]) -> None:
        events.append(HarnessEvent(type=event_type, data=data))
        if emit is not None:
            await emit(event_type, data)

    catalogue = await gateway.describe_tools(session, actor=actor, registry=registry)
    system_prompt = build_system_prompt(
        actor_label=actor.label,
        role=(actor.role.value if actor.role else "user"),
        catalogue=catalogue,
        dry_run=dry_run,
        extra_context={"risk notice": "high-risk actions require the user's approval"},
    )
    messages: list[LLMMessage] = [LLMMessage(role="system", content=system_prompt)]
    messages.extend(_history_messages(history or (), limit=limits.max_history_messages))
    messages.append(LLMMessage(role="user", content=user_message[:8000]))
    tool_definitions_payload = tool_definitions(catalogue)

    deadline = started + limits.deadline_seconds

    for model_turn in range(1, limits.max_model_turns + 1):
        turn.model_turns = model_turn
        if time.perf_counter() > deadline:
            turn.status = "deadline_exceeded"
            turn.error_code = ErrorCode.HARNESS_DEADLINE_EXCEEDED
            await publish(
                "error",
                {
                    "code": ErrorCode.HARNESS_DEADLINE_EXCEEDED,
                    "message": "This turn took too long; try a narrower question.",
                },
            )
            break

        try:
            async with asyncio.timeout(limits.model_timeout_seconds):
                reply: LLMReply = await provider.complete(
                    messages,
                    tools=tool_definitions_payload,
                    temperature=limits.temperature,
                    max_tokens=limits.max_tokens,
                )
        except TimeoutError:
            turn.status = "llm_error"
            turn.error_code = ErrorCode.LLM_UNAVAILABLE
            await publish(
                "error", {"code": ErrorCode.LLM_UNAVAILABLE, "message": "The model timed out"}
            )
            inc("harness_model_errors", {"reason": "timeout"})
            break
        except LLMUnavailable as exc:
            turn.status = "llm_error"
            turn.error_code = ErrorCode.LLM_UNAVAILABLE
            await publish("error", {"code": ErrorCode.LLM_UNAVAILABLE, "message": str(exc)})
            inc("harness_model_errors", {"reason": "unavailable"})
            break
        except LLMError as exc:
            # A provider-side rejection (bad key, bad request). Reported to the client as an
            # unavailable model: the deployment needs attention, the user can retry.
            turn.status = "llm_error"
            turn.error_code = ErrorCode.LLM_UNAVAILABLE
            logger.warning("provider rejected a turn: %s", type(exc).__name__)
            await publish(
                "error",
                {"code": ErrorCode.LLM_UNAVAILABLE, "message": str(exc) or "The model failed"},
            )
            inc("harness_model_errors", {"reason": "error"})
            break

        for key, value in reply.usage.items():
            turn.usage[key] = turn.usage.get(key, 0) + int(value)

        if reply.text:
            await publish("text", {"text": reply.text})

        if not reply.wants_tools:
            turn.reply = reply.text
            await publish("final", {"text": reply.text, "status": "completed"})
            break

        assistant_calls = [
            {
                "id": call.id,
                "type": "function",
                "function": {"name": call.name, "arguments": json.dumps(call.arguments)},
            }
            for call in reply.tool_calls
        ]
        # The assistant turn carries its own tool requests so every provider sees a coherent
        # transcript (OpenAI wants ``tool_calls``, Anthropic wants ``tool_use`` blocks).
        messages.append(
            LLMMessage(role="assistant", content=reply.text, tool_calls=assistant_calls)
        )

        pending_ids: list[uuid.UUID] = []
        for call in reply.tool_calls:
            if turn.tool_calls >= limits.max_tool_calls:
                turn.status = "limit_exceeded"
                turn.error_code = ErrorCode.HARNESS_LIMIT_EXCEEDED
                await publish(
                    "error",
                    {
                        "code": ErrorCode.HARNESS_LIMIT_EXCEEDED,
                        "message": "I hit the limit on actions for one message.",
                    },
                )
                break

            await publish(
                "tool_call",
                {
                    "tool": call.name,
                    "arguments": call.arguments,
                    "call_id": call.id,
                },
            )
            inc("harness_tool_requests")

            outcome = await gateway.invoke(
                session,
                tool_name=call.name,
                arguments=call.arguments,
                actor=actor,
                device_id=device_id,
                session_id=session_id,
                source=AuditSource.API,
                trace_id=trace_id,
                ip_address=ip_address,
                dry_run=dry_run,
                registry=registry,
            )
            turn.tool_calls += 1

            if outcome.needs_approval and outcome.approval_id is not None:
                pending_ids.append(outcome.approval_id)
                await publish(
                    "approval_required",
                    {
                        "approval_id": str(outcome.approval_id),
                        "tool": call.name,
                        "risk": outcome.risk.label if outcome.risk else None,
                        "message": outcome.message,
                    },
                )
            else:
                await publish(
                    "tool_result",
                    {
                        "tool": call.name,
                        "status": outcome.status,
                        "error_code": outcome.error_code,
                        "summary": (outcome.result.summary if outcome.result else outcome.message)[
                            :500
                        ],
                        "audit_id": str(outcome.audit_id) if outcome.audit_id else None,
                    },
                )

            rendered, untrusted = _result_text(outcome, max_chars=limits.max_result_chars)
            messages.append(
                LLMMessage(
                    role="tool",
                    content=format_tool_result(
                        tool_name=call.name,
                        payload=rendered,
                        untrusted=untrusted,
                        max_chars=limits.max_result_chars,
                        error_code=outcome.error_code,
                    ),
                    tool_call_id=call.id,
                    name=call.name,
                )
            )

        if pending_ids:
            turn.pending_approvals.extend(pending_ids)
            if turn.status == "completed":
                turn.status = "needs_approval"
                turn.reply = (
                    "That action needs your approval first. Confirm it in the prompt and I will "
                    "carry it out."
                )
            break

        if turn.status == "limit_exceeded":
            break
    else:
        turn.status = "limit_exceeded"
        turn.error_code = ErrorCode.HARNESS_LIMIT_EXCEEDED
        await publish(
            "error",
            {
                "code": ErrorCode.HARNESS_LIMIT_EXCEEDED,
                "message": (
                    "I stopped after several steps without finishing; try a narrower request."
                ),
            },
        )

    turn.events = events
    turn.duration_ms = int((time.perf_counter() - started) * 1000)
    inc("harness_turns", {"status": turn.status})
    return turn


async def describe_actor(actor: ActorRef) -> str:
    """Short label used in prompts and logs (never an email address or a raw identifier)."""
    role = actor.role.value if isinstance(actor.role, Role) else "user"
    kind = "account" if actor.user_id else "device"
    return f"{kind}:{role}"
