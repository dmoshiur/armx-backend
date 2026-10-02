# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

from app.chat.llm import _parse_arguments, _tool_calls
from app.core.privacy import contains_raw_biometric_data
from app.ws.routes import _message_id, _send_text
from app.ws.schemas import ChatSendFrame


def test_llm_tool_arguments_are_bounded_and_validated() -> None:
    assert _parse_arguments('{"query":"light"}') == {"query": "light"}
    assert _parse_arguments("not-json") is None
    assert _parse_arguments("x" * 8_193) is None
    assert _parse_arguments(["not", "an", "object"]) is None

    calls = _tool_calls(
        [
            {
                "id": "call-1",
                "function": {"name": "notes_search", "arguments": '{"query":"x"}'},
            },
            {"id": "bad", "function": {"name": "ignored", "arguments": "[]"}},
        ]
    )
    assert len(calls) == 1
    assert calls[0].call_id == "call-1"
    assert calls[0].arguments == {"query": "x"}


def test_chat_frame_and_stream_event_helpers_are_bounded() -> None:
    frame = ChatSendFrame.model_validate({"type": "chat.send", "text": "hello"})
    assert frame.conversation_id == "main"
    assert _message_id("message-1") == "message-1"
    assert _message_id("invalid id") != "invalid id"
    tokens = _send_text("a" * 49, "message-1", "main")
    assert len(tokens) == 2
    assert tokens[0]["index"] == 0
    assert tokens[1]["index"] == 1
    assert contains_raw_biometric_data({"profile": {"face_template": "sensitive"}})
    assert not contains_raw_biometric_data({"message": "Please turn off the hallway light."})
