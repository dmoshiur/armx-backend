# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""Request and response models for the auth and user surfaces."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

__all__ = [
    "AccountSummary",
    "ForgotPasswordRequest",
    "GenericMessage",
    "LoginRequest",
    "LogoutRequest",
    "PatchUserRequest",
    "RefreshRequest",
    "ResendVerificationRequest",
    "ResetPasswordRequest",
    "SessionSummary",
    "SignupRequest",
    "TokenResponse",
    "VerifyEmailRequest",
]


class SignupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: str = Field(min_length=8, max_length=256)
    display_name: str = Field(default="", max_length=120)

    @field_validator("display_name")
    @classmethod
    def _strip(cls, value: str) -> str:
        return value.strip()


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    device_name: str = Field(default="", max_length=120)
    platform: str = Field(default="", max_length=80)


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(min_length=16, max_length=512)


class LogoutRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refresh_token: str | None = Field(default=None, max_length=512)
    all_sessions: bool = False


class VerifyEmailRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=16, max_length=512)


class ResendVerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr


class ForgotPasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr


class ResetPasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=16, max_length=512)
    password: str = Field(min_length=8, max_length=256)


class AccountSummary(BaseModel):
    """Public account view. Never includes a hash, a token, or an internal counter."""

    id: uuid.UUID
    email: str
    display_name: str
    role: str
    email_verified: bool
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - an OAuth token *type*, not a credential
    expires_in: int
    refresh_token: str
    refresh_expires_in: int
    session_id: uuid.UUID | None = None
    user: AccountSummary


class SessionSummary(BaseModel):
    id: uuid.UUID
    label: str
    user_agent: str
    created_at: datetime
    last_seen_at: datetime | None
    expires_at: datetime
    revoked_at: datetime | None = None
    device_id: uuid.UUID | None = None
    current: bool = False


class PatchUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str = Field(min_length=1, max_length=120)


class GenericMessage(BaseModel):
    """
    Response for endpoints whose real answer must not depend on whether an account exists.

    ``detail`` is operational guidance only; it never reveals account state.
    """

    message: str
    detail: str | None = None
