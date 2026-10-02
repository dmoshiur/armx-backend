# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ConsentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool
    allow_while_locked: bool = False


class ConsentResponse(BaseModel):
    enabled: bool
    allow_while_locked: bool
    updated_at: datetime | None = None


class RecipientResponse(BaseModel):
    id: str
    device_id: str
    name: str
    user_id: str
    user_display_name: str
    consented: bool
    online: bool
    last_seen_at: datetime | None = None


class AnnouncementResponse(BaseModel):
    id: str
    from_user_id: str
    from_name: str
    scope: Literal["USER", "BROADCAST"]
    target_user_id: str | None = None
    target_label: str
    audio_url: str
    duration_ms: int
    status: Literal["QUEUED", "DELIVERED", "PLAYED", "MISSED", "REVOKED"]
    created_at: datetime
    delivered_at: datetime | None = None
    played_at: datetime | None = None


class OutcomeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["DELIVERED", "PLAYED", "MISSED", "REVOKED"]


class IntercomOwnerAssertion(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=1, max_length=8192)
    scope: str = "owner_verified"
    single_use: bool = True
    iat: datetime | None = None
    exp: datetime | None = None
