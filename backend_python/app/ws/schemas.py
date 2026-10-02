# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ChatSendFrame(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["chat.send"]
    text: str = Field(min_length=1, max_length=8_000)
    conversation_id: str = Field(default="main", min_length=1, max_length=96)
    message_id: str | None = Field(default=None, max_length=96)
