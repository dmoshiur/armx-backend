# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.core.verification import OwnerAssertionInput


class RequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class UnlockRequest(RequestModel):
    device_id: str = Field(min_length=1, max_length=96)
    nonce: str = Field(min_length=16, max_length=128)
    exp: str = Field(min_length=20, max_length=40)
    issued_at: str = Field(min_length=20, max_length=40)
    action: Literal["unlock"]
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key: str = Field(min_length=40, max_length=256)
    signature: str = Field(min_length=40, max_length=256)
    assertion: OwnerAssertionInput | None = None


class UnlockTargetResponse(BaseModel):
    id: str
    name: str
    kind: str = "OTHER"
    online: bool = False
    last_seen_at: datetime
    risk_tier: Literal["LOW", "MEDIUM", "HIGH"] = "HIGH"
    paired: bool = True
    agent_version: str = ""


class UnlockOutcomeResponse(BaseModel):
    status: Literal["UNLOCKED", "FAILED", "EXPIRED"]
    request_id: str
    target_id: str
    message: str = ""
