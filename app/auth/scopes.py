# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Scopes.

A scope is a capability string of the form ``family:action`` (``smart_home:write``). Tool
manifests declare what they require; a principal carries what their role grants. Both sides are
server-defined - a client can never ask for a scope.

Matching is exact, or prefix-based when the granted scope ends in ``:*``. The wildcard has to be
written explicitly in a role bundle; nothing implies it. In particular ``tools:all`` does not
silently match ``admin:*`` and vice versa.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

from app.core.enums import Role

__all__ = ["ROLE_SCOPES", "has_all_scopes", "has_scope", "missing_scopes", "scopes_for_role"]

#: Capability bundles per role. Adding a capability here is a deliberate, reviewable act.
ROLE_SCOPES: Final[dict[Role, frozenset[str]]] = {
    Role.USER: frozenset(
        {
            "self:read",
            "self:write",
            "tools:basic",
            "tools:mock",
            "memory:write",
            "memory:read",
            "automation:write",
        }
    ),
    Role.VIP: frozenset(
        {
            "self:read",
            "self:write",
            "tools:basic",
            "tools:mock",
            "tools:advanced",
            "memory:read",
            "memory:write",
            "automation:write",
            "smart_home:read",
            "smart_home:write",
            "messaging:draft",
            "web_builder:generate",
            "device:link",
            "audit:self",
        }
    ),
    Role.ADMIN: frozenset(
        {
            "self:read",
            "self:write",
            "tools:basic",
            "tools:mock",
            "tools:advanced",
            "tools:all",
            "memory:read",
            "memory:write",
            "automation:write",
            "smart_home:read",
            "smart_home:write",
            "messaging:draft",
            "messaging:send",
            "web_builder:generate",
            "web_builder:deploy",
            "device:link",
            "device:unlink",
            "pc:unlock",
            "mail:read",
            "mail:send",
            "audit:self",
            "audit:all",
            "admin:*",
        }
    ),
}


def scopes_for_role(role: Role) -> frozenset[str]:
    """Capabilities granted by a role."""
    return ROLE_SCOPES.get(role, ROLE_SCOPES[Role.USER])


def has_scope(granted: Iterable[str], required: str) -> bool:
    """
    Whether ``required`` is satisfied by any granted scope.

    ``"*"`` grants everything (never assigned by a role bundle, but supported for a future
    service principal). ``"family:*"`` grants the whole family.
    """
    if not required:
        return True
    for grant in granted:
        if grant == required or grant == "*":
            return True
        if grant.endswith(":*") and required.startswith(grant[:-1]):
            return True
    return False


def missing_scopes(granted: Iterable[str], required: Iterable[str]) -> tuple[str, ...]:
    """Required scopes that are not satisfied (used for audit detail and error messages)."""
    granted_set = frozenset(granted)
    return tuple(scope for scope in sorted(required) if not has_scope(granted_set, scope))


def has_all_scopes(granted: Iterable[str], required: Iterable[str]) -> bool:
    return not missing_scopes(granted, required)
