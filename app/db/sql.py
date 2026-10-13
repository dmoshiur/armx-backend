# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Small typed helpers over SQLAlchemy results.

``session.execute(update(...)).rowcount`` exists at runtime (the result is a
``CursorResult``) but not on the ``Result`` protocol, so every caller would otherwise need the
same cast. Keeping it here means one place to review, and one place to change if the typing
story improves upstream.
"""

from __future__ import annotations

from typing import Any, cast

from sqlalchemy import CursorResult, Result

__all__ = ["affected_rows"]


def affected_rows(result: Result[Any]) -> int:
    """Number of rows an INSERT/UPDATE/DELETE statement touched."""
    return int(cast("CursorResult[Any]", result).rowcount or 0)
