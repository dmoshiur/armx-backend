# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import json
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.privacy import contains_raw_biometric_data


class RequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RulePayload(RequestModel):
    id: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=160)
    trigger_type: Literal[
        "ACTIVITY_IS", "GEOFENCE_ENTER", "GEOFENCE_EXIT", "TIME_WINDOW", "DEVICE_STATE"
    ]
    action_type: Literal["DEVICE_COMMAND", "SCENE", "NOTIFY", "UNLOCK_PREPARE", "ASSISTANT_PROMPT"]
    enabled: bool = True
    dry_run: bool = False
    risk_tier: Literal["LOW", "MEDIUM", "HIGH"] = "MEDIUM"
    trigger_params: dict[str, Any] = Field(default_factory=dict)
    action_params: dict[str, Any] = Field(default_factory=dict)
    geofence_id: str | None = None
    device_id: str | None = None
    last_run_at: datetime | None = None
    run_count: int = 0

    @field_validator("trigger_params", "action_params")
    @classmethod
    def validate_parameters(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            if len(json.dumps(value, ensure_ascii=False).encode("utf-8")) > 16_384:
                raise ValueError("Rule parameters are too large")
        except (TypeError, ValueError) as exc:
            raise ValueError("Rule parameters are invalid") from exc
        if contains_raw_biometric_data(value):
            raise ValueError("Raw biometric or audio data is not accepted")
        return value


class RuleResponse(RulePayload):
    pass


class RuleDryRunResponse(BaseModel):
    rule_id: str
    would_fire: bool
    blocked_reason: str = ""
    steps: list[str] = Field(default_factory=list)
    at: datetime
