# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class RequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class KillSwitchRequest(RequestModel):
    engaged: bool
    reason: str = Field(default="", max_length=240)


class ToolToggleRequest(RequestModel):
    tool: Literal["GITHUB", "MAIL", "MQTT", "DB", "SYSTEM", "VISION"]
    enabled: bool


class RevokeDeviceRequest(RequestModel):
    device_id: str = Field(min_length=1, max_length=96)


class ToolToggleResponse(BaseModel):
    id: str
    label: str
    description: str = ""
    enabled: bool
    connected: bool = False
    max_risk_tier: Literal["LOW", "MEDIUM", "HIGH"] = "MEDIUM"
    requires_approval: bool = True


class AdminStateResponse(BaseModel):
    assistant_enabled: bool = True
    kill_switch_engaged: bool = False
    tools: list[ToolToggleResponse]
    updated_at: datetime
    engaged_by: str = ""
    engaged_reason: str = ""
    revoked_devices: int = 0


class KillSwitchResponse(BaseModel):
    engaged: bool
    at: datetime
    reason: str = ""
    actor: str = ""
    sockets_closed: int = 0
