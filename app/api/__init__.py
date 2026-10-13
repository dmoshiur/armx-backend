# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""Cross-cutting HTTP plumbing: middleware, error handling, health and metrics routes."""

from app.api.middleware import client_ip, register_middleware
from app.api.routes_health import router as health_router

__all__ = ["client_ip", "health_router", "register_middleware"]
