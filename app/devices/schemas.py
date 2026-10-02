# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import json
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.privacy import contains_raw_biometric_data
from app.core.verification import OwnerAssertionInput


class RequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RelayResponse(BaseModel):
    id: str
    label: str
    state: Literal["ON", "OFF", "UNKNOWN"] = "UNKNOWN"
    last_changed_at: datetime
    risk_tier: Literal["LOW", "MEDIUM", "HIGH"] = "MEDIUM"
    is_momentary: bool = False


class SensorResponse(BaseModel):
    id: str
    label: str
    kind: str
    value: float
    unit: str
    updated_at: datetime
    is_stale: bool = False


class DeviceResponse(BaseModel):
    id: str
    name: str
    site: str
    kind: str = "OTHER"
    online: bool = False
    risk_tier: str = "MEDIUM"
    firmware: str = "unknown"
    last_seen_at: datetime
    relays: list[dict[str, Any]] = Field(default_factory=list)
    sensors: list[dict[str, Any]] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)


class DeviceCommandRequest(RequestModel):
    command: str = Field(min_length=1, max_length=200)
    parameters: dict[str, Any] = Field(default_factory=dict)
    risk_tier: str | None = None
    owner_verified: OwnerAssertionInput | None = None

    @field_validator("parameters")
    @classmethod
    def validate_parameters(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            if len(json.dumps(value, ensure_ascii=False).encode("utf-8")) > 4096:
                raise ValueError("Command parameters are too large")
        except (TypeError, ValueError) as exc:
            raise ValueError("Command parameters are invalid") from exc
        if contains_raw_biometric_data(value):
            raise ValueError("Raw biometric or audio data is not accepted")
        return value


class UnpairRequest(RequestModel):
    device_id: str = Field(min_length=1, max_length=96)


class SceneActivateRequest(RequestModel):
    owner_verified: OwnerAssertionInput | None = None


class DeviceCommandResponse(BaseModel):
    device_id: str
    accepted: bool
    command_id: str | None = None
    at: datetime
    message: str = ""
