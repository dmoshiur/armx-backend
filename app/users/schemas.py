# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""Request and response models for user administration."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.auth.schemas import SessionSummary

__all__ = [
    "AdminUserSummary",
    "CreateUserRequest",
    "PatchAdminUserRequest",
    "UserListResponse",
    "UserSessionsResponse",
]


class AdminUserSummary(BaseModel):
    """
    Administrative view of an account.

    Deliberately excludes the password hash's existence, the Google subject and any token state:
    an administrator manages roles and access, and has no way to read credentials.
    """

    id: uuid.UUID
    email: str
    display_name: str
    role: str
    email_verified: bool
    is_active: bool
    locked_until: datetime | None = None
    failed_login_count: int = 0
    created_at: datetime
    last_login_at: datetime | None = None
    active_sessions: int = 0


class UserListResponse(BaseModel):
    items: list[AdminUserSummary]
    total: int
    limit: int
    offset: int


class CreateUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    password: str = Field(min_length=8, max_length=256)
    display_name: str = Field(default="", max_length=120)
    role: str = Field(default="user", pattern="^(user|vip|admin)$")
    verified: bool = True


class PatchAdminUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: str | None = Field(default=None, pattern="^(user|vip|admin)$")
    is_active: bool | None = None
    display_name: str | None = Field(default=None, min_length=1, max_length=120)


class UserSessionsResponse(BaseModel):
    user_id: uuid.UUID
    items: list[SessionSummary]
