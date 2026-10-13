# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Authentication: tokens, scopes, the account lifecycle and the Google callback.

Modules: ``scopes`` (capability bundles), ``tokens`` (JWT access tokens, hashed refresh tokens),
``schemas``, ``service`` (the account lifecycle), ``dependencies`` (principal resolution and the
role/scope guards), ``routes`` (``/auth/*``) and ``google`` (OpenID Connect).

Nothing is re-exported here on purpose: ``dependencies`` imports the API layer, and a package-level
import would create a cycle for the modules that only need ``scopes``.
"""
