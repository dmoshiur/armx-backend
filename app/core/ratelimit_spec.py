# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Rate-limit specification parsing.

Manifests declare limits as strings (``"30/hour"``); the gateway and the auth
routes both need the same parser so a manifest can never be interpreted two
different ways.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ["RateLimitSpec", "parse_rate_limit"]

_UNIT_SECONDS: dict[str, int] = {
    "second": 1,
    "sec": 1,
    "s": 1,
    "minute": 60,
    "min": 60,
    "m": 60,
    "hour": 3600,
    "h": 3600,
    "day": 86400,
    "d": 86400,
}

_SPEC_RE = re.compile(r"^\s*(?P<count>\d{1,7})\s*/\s*(?P<unit>[a-z]+)\s*$", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class RateLimitSpec:
    """A parsed ``count / window`` pair."""

    count: int
    window_seconds: int

    def bucket(self, now_epoch: int) -> int:
        """Fixed-window bucket index; identical windows share a counter row."""
        return now_epoch // self.window_seconds

    @property
    def text(self) -> str:
        for unit, seconds in _UNIT_SECONDS.items():
            if seconds == self.window_seconds and len(unit) > 1:
                return f"{self.count}/{unit}"
        return f"{self.count}/{self.window_seconds}s"


def parse_rate_limit(
    spec: str | RateLimitSpec, *, default: RateLimitSpec | None = None
) -> RateLimitSpec:
    """
    Parse ``"30/hour"`` into a :class:`RateLimitSpec`.

    An empty or malformed spec falls back to ``default`` when one is supplied, so a
    typo in an environment variable cannot silently disable rate limiting.
    """
    if isinstance(spec, RateLimitSpec):
        return spec
    match = _SPEC_RE.match(spec or "")
    if match is None:
        if default is not None:
            return default
        raise ValueError(f"invalid rate limit spec: {spec!r}")
    unit = match.group("unit").lower()
    seconds = _UNIT_SECONDS.get(unit) or _UNIT_SECONDS.get(unit.rstrip("s"))
    if seconds is None:
        if default is not None:
            return default
        raise ValueError(f"invalid rate limit window: {spec!r}")
    count = int(match.group("count"))
    if count <= 0:
        raise ValueError(f"rate limit count must be positive: {spec!r}")
    return RateLimitSpec(count=count, window_seconds=seconds)
