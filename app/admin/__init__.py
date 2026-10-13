# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
The operator console.

Small on purpose and separate from ``/admin/users``: what lives here is what the person running
the deployment needs, and the kill-switch is the first of those - it must keep working when
everything else is misbehaving, so it depends on nothing but the settings and one database table.
"""

from app.admin.routes import router

__all__ = ["router"]
