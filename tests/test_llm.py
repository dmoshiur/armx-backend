# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Model providers.

The adapters are the only part of the system that talks to a vendor, so the tests here work
against a stubbed HTTP transport: no network, no keys, and every failure mode (400, 429, 500,
timeout, a malformed body) is exercised deterministically. What matters is that a provider always
returns the same internal shape - text, tool requests, usage - or raises one of exactly two
errors, and never leaks the response body into a client-visible message.
"""

from __future__ import annotations

import json

import httpx
import pytest

from app.config import Settings
from app.llm.anthropic import AnthropicProvider
from app.llm.base import LLMError, LLMMessage, LLMUnavailable
from app.llm.factory import build_provider, provider_label
from app.llm.mock import MockLLMProvider, ScriptedLLMProvider
from app.llm.ollama import OllamaProvider
from app.llm.openai_compatible import OpenAICompatibleProvider

MESSAGES = [LLMMessage(role="user", content="turn on the desk light")]
TOOLS = [
    {
        "name": "set_light",
        "description": "Turn a light on or off",
        "parameters": {"type": "object", "properties": {"entity_id": {"type": "string"}}},
    }
]


def transport(handler) -> httpx.MockTransport:
    """A stubbed transport: no network is touched by any test in this file."""
    return httpx.MockTransport(handler)


def json_response(status: int, payload: object) -> httpx.Response:
    return httpx.Response(status, json=payload)


class TestOpenAICompatible:
    def provider(self, handler, **kwargs) -> OpenAICompatibleProvider:
        return OpenAICompatibleProvider(
            api_key="test-key",
            model="gpt-test",
            base_url="https://example.invalid/v1",
            transport=transport(handler),
            **kwargs,
        )

    async def test_a_plain_answer_is_returned(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path.endswith("/chat/completions")
            assert request.headers["authorization"] == "Bearer test-key"
            return json_response(
                200,
                {
                    "choices": [
                        {"message": {"content": "The light is on."}, "finish_reason": "stop"}
                    ],
                    "usage": {"prompt_tokens": 12, "completion_tokens": 5},
                },
            )

        provider = self.provider(handler)
        reply = await provider.complete(MESSAGES, tools=TOOLS, temperature=0.1, max_tokens=64)
        assert reply.text == "The light is on."
        assert reply.wants_tools is False
        assert reply.usage == {"prompt_tokens": 12, "completion_tokens": 5}
        await provider.aclose()

    async def test_a_tool_call_is_parsed_into_the_internal_shape(self) -> None:
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured.update(json.loads(request.content))
            return json_response(
                200,
                {
                    "choices": [
                        {
                            "message": {
                                "content": "",
                                "tool_calls": [
                                    {
                                        "id": "call_1",
                                        "type": "function",
                                        "function": {
                                            "name": "set_light",
                                            "arguments": json.dumps(
                                                {"entity_id": "light.desk", "on": True}
                                            ),
                                        },
                                    }
                                ],
                            },
                            "finish_reason": "tool_calls",
                        }
                    ]
                },
            )

        provider = self.provider(handler)
        reply = await provider.complete(MESSAGES, tools=TOOLS, max_tokens=64)
        assert reply.wants_tools is True
        assert reply.tool_calls[0].name == "set_light"
        assert reply.tool_calls[0].arguments == {"entity_id": "light.desk", "on": True}
        # The tool definitions were sent in the provider's own shape.
        assert captured["tools"] == [{"type": "function", "function": TOOLS[0]}]
        assert captured["tool_choice"] == "auto"
        assert captured["max_tokens"] == 64
        await provider.aclose()

    async def test_malformed_tool_arguments_do_not_crash_the_turn(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return json_response(
                200,
                {
                    "choices": [
                        {
                            "message": {
                                "content": "",
                                "tool_calls": [
                                    {
                                        "id": "call_1",
                                        "function": {"name": "set_light", "arguments": "not json"},
                                    }
                                ],
                            },
                            "finish_reason": "tool_calls",
                        }
                    ]
                },
            )

        provider = self.provider(handler)
        reply = await provider.complete(MESSAGES, tools=TOOLS)
        assert reply.tool_calls[0].arguments == {}
        await provider.aclose()

    @pytest.mark.parametrize(
        ("status", "expected"),
        [(429, LLMUnavailable), (500, LLMUnavailable), (503, LLMUnavailable), (400, LLMError)],
    )
    async def test_http_failures_map_onto_two_errors(
        self, status: int, expected: type[Exception]
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            # A body that would be dangerous to echo: it contains the request we sent.
            return json_response(status, {"error": {"message": "turn on the desk light"}})

        provider = self.provider(handler)
        with pytest.raises(expected) as caught:
            await provider.complete(MESSAGES, tools=TOOLS)
        assert "turn on the desk light" not in str(caught.value)
        await provider.aclose()

    async def test_a_transport_error_is_unavailable_not_a_crash(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("no route to host")

        provider = self.provider(handler)
        with pytest.raises(LLMUnavailable):
            await provider.complete(MESSAGES, tools=TOOLS)
        await provider.aclose()

    async def test_a_timeout_is_unavailable(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("too slow")

        provider = self.provider(handler)
        with pytest.raises(LLMUnavailable):
            await provider.complete(MESSAGES, tools=TOOLS)
        await provider.aclose()

    async def test_an_empty_choices_array_is_unavailable(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return json_response(200, {"choices": []})

        provider = self.provider(handler)
        with pytest.raises(LLMUnavailable):
            await provider.complete(MESSAGES, tools=TOOLS)
        await provider.aclose()

    async def test_the_transcript_carries_tool_calls_back_to_the_model(self) -> None:
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured.update(json.loads(request.content))
            return json_response(200, {"choices": [{"message": {"content": "ok"}}]})

        provider = self.provider(handler)
        await provider.complete(
            [
                LLMMessage(role="user", content="hello"),
                LLMMessage(
                    role="assistant",
                    content="",
                    tool_calls=[
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "set_light", "arguments": "{}"},
                        }
                    ],
                ),
                LLMMessage(role="tool", content="done", tool_call_id="call_1", name="set_light"),
            ],
            tools=TOOLS,
        )
        sent = captured["messages"]
        assert sent[1]["tool_calls"][0]["function"]["name"] == "set_light"
        assert sent[2] == {
            "role": "tool",
            "content": "done",
            "tool_call_id": "call_1",
            "name": "set_light",
        }
        await provider.aclose()


class TestAnthropic:
    def provider(self, handler, **kwargs) -> AnthropicProvider:
        return AnthropicProvider(
            api_key="test-key",
            model="claude-test",
            base_url="https://example.invalid",
            transport=transport(handler),
            **kwargs,
        )

    async def test_text_and_tool_use_blocks_are_both_handled(self) -> None:
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured.update(json.loads(request.content))
            assert request.headers["x-api-key"] == "test-key"
            return json_response(
                200,
                {
                    "content": [
                        {"type": "text", "text": "Turning it on."},
                        {
                            "type": "tool_use",
                            "id": "toolu_1",
                            "name": "set_light",
                            "input": {"entity_id": "light.desk", "on": True},
                        },
                    ],
                    "stop_reason": "tool_use",
                    "usage": {"input_tokens": 20, "output_tokens": 9},
                },
            )

        provider = self.provider(handler)
        reply = await provider.complete(
            [LLMMessage(role="user", content="turn on the light")], tools=TOOLS, max_tokens=128
        )
        assert reply.text == "Turning it on."
        assert reply.tool_calls[0].name == "set_light"
        assert reply.usage == {"prompt_tokens": 20, "completion_tokens": 9}
        # The system prompt is a top-level field, not a message: Anthropic has no system role.
        assert captured["max_tokens"] == 128
        assert captured["tools"][0]["name"] == "set_light"
        assert captured["tools"][0]["input_schema"] == TOOLS[0]["parameters"]
        await provider.aclose()

    async def test_the_system_message_is_hoisted_out_of_the_transcript(self) -> None:
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured.update(json.loads(request.content))
            return json_response(200, {"content": [{"type": "text", "text": "ok"}]})

        provider = self.provider(handler)
        await provider.complete(
            [
                LLMMessage(role="system", content="You are a planner."),
                LLMMessage(role="user", content="hello"),
            ]
        )
        assert captured["system"] == "You are a planner."
        assert all(message["role"] != "system" for message in captured["messages"])
        await provider.aclose()

    async def test_a_tool_result_is_sent_as_a_tool_result_block(self) -> None:
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured.update(json.loads(request.content))
            return json_response(200, {"content": [{"type": "text", "text": "ok"}]})

        provider = self.provider(handler)
        await provider.complete(
            [
                LLMMessage(role="user", content="turn on the light"),
                LLMMessage(
                    role="assistant",
                    content="",
                    tool_calls=[
                        {"id": "toolu_1", "type": "tool_use", "name": "set_light", "input": {}}
                    ],
                ),
                LLMMessage(role="tool", content="done", tool_call_id="toolu_1", name="set_light"),
            ]
        )
        messages = captured["messages"]
        assistant_blocks = messages[1]["content"]
        assert assistant_blocks[0]["type"] == "tool_use"
        assert messages[2]["content"][0]["type"] == "tool_result"
        assert messages[2]["content"][0]["tool_use_id"] == "toolu_1"
        await provider.aclose()

    @pytest.mark.parametrize(
        ("status", "expected"), [(429, LLMUnavailable), (529, LLMUnavailable), (401, LLMError)]
    )
    async def test_http_failures_map_onto_two_errors(
        self, status: int, expected: type[Exception]
    ) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return json_response(status, {"error": {"message": "turn on the desk light"}})

        provider = self.provider(handler)
        with pytest.raises(expected):
            await provider.complete(MESSAGES, tools=TOOLS)
        await provider.aclose()

    async def test_an_overloaded_error_event_is_reported_as_unavailable(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return json_response(200, {"type": "error", "error": {"type": "overloaded_error"}})

        provider = self.provider(handler)
        with pytest.raises(LLMUnavailable):
            await provider.complete(MESSAGES, tools=TOOLS)
        await provider.aclose()


class TestOllama:
    def provider(self, handler, **kwargs) -> OllamaProvider:
        return OllamaProvider(
            base_url="http://localhost:11434",
            transport=transport(handler),
            model="llama3",
            **kwargs,
        )

    async def test_an_answer_is_read_from_the_chat_endpoint(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path.endswith("/api/chat")
            return json_response(
                200,
                {
                    "message": {"role": "assistant", "content": "The desk light is on."},
                    "prompt_eval_count": 30,
                    "eval_count": 12,
                    "done": True,
                },
            )

        provider = self.provider(handler)
        reply = await provider.complete(MESSAGES)
        assert reply.text == "The desk light is on."
        assert reply.usage == {"prompt_tokens": 30, "completion_tokens": 12}
        await provider.aclose()

    async def test_a_local_model_that_is_not_running_is_unavailable(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

        provider = self.provider(handler)
        with pytest.raises(LLMUnavailable):
            await provider.complete(MESSAGES)
        await provider.aclose()


class TestFactory:
    def test_the_default_profile_is_offline(self, tmp_settings: Settings) -> None:
        provider = build_provider(tmp_settings)
        assert isinstance(provider, MockLLMProvider)
        assert provider_label(tmp_settings).startswith("mock")

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("mock", MockLLMProvider),
            ("openai", OpenAICompatibleProvider),
            ("anthropic", AnthropicProvider),
            ("ollama", OllamaProvider),
            ("openai_compatible", OpenAICompatibleProvider),
        ],
    )
    def test_every_configured_provider_resolves(
        self, tmp_settings: Settings, name: str, expected: type
    ) -> None:
        settings = tmp_settings.model_copy(update={"llm_provider": name})
        provider = build_provider(settings)
        assert isinstance(provider, expected)

    def test_an_unknown_provider_name_is_refused_before_it_can_be_built(
        self, tmp_settings: Settings
    ) -> None:
        """
        The provider name is a typed setting, so a typo is caught when settings are validated (at
        boot) instead of on the first user message.
        """
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            Settings(
                environment=tmp_settings.environment,
                database_url=tmp_settings.database_url,
                llm_provider="definitely-not-a-vendor",  # type: ignore[arg-type]
            )


class TestMockProvider:
    async def test_the_call_directive_is_understood(self) -> None:
        provider = MockLLMProvider()
        reply = await provider.complete(
            [LLMMessage(role="user", content='call set_light {"on": true}')], tools=TOOLS
        )
        assert reply.tool_calls[0].name == "set_light"
        assert reply.tool_calls[0].arguments == {"on": True}

    async def test_malformed_json_gets_a_helpful_sentence_instead_of_a_tool_call(self) -> None:
        provider = MockLLMProvider()
        reply = await provider.complete(
            [LLMMessage(role="user", content="call set_light {oops}")], tools=TOOLS
        )
        assert reply.tool_calls == []
        assert "JSON" in reply.text

    async def test_prose_is_echoed_when_nothing_is_offered(self) -> None:
        provider = MockLLMProvider(announce=False)
        reply = await provider.complete([LLMMessage(role="user", content="what time is it?")])
        assert reply.text == "what time is it?"

    async def test_the_scripted_provider_repeats_its_last_reply(self) -> None:
        from app.llm.base import LLMReply

        provider = ScriptedLLMProvider([LLMReply(text="one"), LLMReply(text="two")])
        assert (await provider.complete([])).text == "one"
        assert (await provider.complete([])).text == "two"
        assert (await provider.complete([])).text == "two"
        assert len(provider.calls) == 3

    def test_a_scripted_provider_needs_a_script(self) -> None:
        with pytest.raises(ValueError):
            ScriptedLLMProvider([])
