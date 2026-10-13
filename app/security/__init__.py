# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Security Gateway.

This package is the only component allowed to decide whether an action happens. The LLM may
propose a tool call; everything that follows - kill-switch, tool enablement, scopes, role,
rate limit, risk tier, approval - is decided here, from server-side state.

Modules:

* ``kill_switch``  - the unconditional stop, read from the database on every check
* ``ratelimit``    - fixed-window counters in the primary database
* ``approvals``    - hash-bound, single-use, expiring approvals for HIGH-tier actions
* ``gateway``      - the decision function every tool call goes through

Submodules are imported directly (``from app.security.gateway import SecurityGateway``) rather
than re-exported here: the gateway imports the registry and the audit service, and a package-level
import of everything would create an import cycle for the tools that need the rate limiter.
"""
