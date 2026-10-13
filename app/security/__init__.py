# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
The security package.

Layered so that each layer can be reasoned about alone:

* :mod:`app.security.ratelimit` - fixed-window counters in PostgreSQL (no Redis in this system).
* :mod:`app.security.approvals` - the record of the user's decision on one exact action.
* :mod:`app.security.kill_switch` - a flag the model cannot reach.
* :mod:`app.security.gateway` - the single choke point every tool call passes through.

Importing the package pulls in all four, which is intentional: a deployment that cannot import
the gateway must not start.
"""

from app.security.approvals import (
    ApprovalPolicy,
    action_hash,
    consume,
    create_approval,
    decide,
    expire_stale,
    get_approval,
    list_for_actor,
    summarise_arguments,
)
from app.security.gateway import ActorRef, InvocationOutcome, SecurityGateway, ToolDecision
from app.security.kill_switch import KillSwitch
from app.security.ratelimit import RateLimiter, RateLimitResult, limit_key

__all__ = [
    "ActorRef",
    "ApprovalPolicy",
    "InvocationOutcome",
    "KillSwitch",
    "RateLimitResult",
    "RateLimiter",
    "SecurityGateway",
    "ToolDecision",
    "action_hash",
    "consume",
    "create_approval",
    "decide",
    "expire_stale",
    "get_approval",
    "limit_key",
    "list_for_actor",
    "summarise_arguments",
]
