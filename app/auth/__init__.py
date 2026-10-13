# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""Authentication: tokens, scopes, account lifecycle and the Google callback."""

from app.auth.dependencies import Principal, current_principal, require_admin, require_scope
from app.auth.scopes import ROLE_SCOPES, has_scope, scopes_for_role

__all__ = [
    "ROLE_SCOPES",
    "Principal",
    "current_principal",
    "has_scope",
    "require_admin",
    "require_scope",
    "scopes_for_role",
]
