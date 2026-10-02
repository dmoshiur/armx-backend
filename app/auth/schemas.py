# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator


class RequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class UserProfileResponse(BaseModel):
    id: str
    display_name: str
    email: str
    roles: list[str]


class LoginRequest(RequestModel):
    username: str = Field(min_length=1, max_length=64)
    password: SecretStr = Field(min_length=1, max_length=256)
    device_key: SecretStr = Field(min_length=16, max_length=256)
    platform: str = Field(min_length=1, max_length=32)
    client_version: str = Field(min_length=1, max_length=48)


class RegisterRequest(RequestModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    email: str = Field(min_length=5, max_length=254)
    display_name: str = Field(min_length=1, max_length=160)
    password: SecretStr = Field(min_length=12, max_length=256)
    public_key: str = Field(min_length=40, max_length=256)
    device_name: str = Field(min_length=1, max_length=120)
    platform: str = Field(min_length=1, max_length=32)
    client_version: str = Field(min_length=1, max_length=48)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        import re

        normalized = value.strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", normalized):
            raise ValueError("A valid email address is required")
        return normalized


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    expires_at: datetime
    device_id: str
    user: UserProfileResponse


class RegisterResponse(LoginResponse):
    device_key: str


class RefreshRequest(RequestModel):
    refresh_token: SecretStr = Field(min_length=16, max_length=512)


class RefreshResponse(BaseModel):
    access_token: str
    refresh_token: str
    expires_at: datetime


class PairRequest(RequestModel):
    public_key: str = Field(min_length=40, max_length=256)
    device_name: str = Field(min_length=1, max_length=120)
    platform: str = Field(min_length=1, max_length=32)
    challenge: str | None = Field(default=None, max_length=96)
    challenge_signature: str | None = Field(default=None, max_length=256)


class PairPendingResponse(BaseModel):
    status: Literal["pending"] = "pending"
    device_id: str
    challenge: str
    message: str = "Awaiting owner approval"


class PairApprovedResponse(BaseModel):
    device_id: str
    device_key: str
    site: str = "home"
    paired_at: datetime


class UnpairRequest(RequestModel):
    device_id: str = Field(min_length=1, max_length=96)
