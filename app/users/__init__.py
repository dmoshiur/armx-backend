# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
User administration.

The ``/admin/users`` surface: listing, role changes, activation, unlock, session revocation. All
of the state transitions live in :mod:`app.auth.service` and are shared with sign-in, so an
administrator cannot take a shortcut a normal request would not take.
"""
