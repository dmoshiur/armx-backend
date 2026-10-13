# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Risk tiers.

The tier is *always* decided server-side from the registered tool manifest. It is never taken
from the client, never taken from the model, and never mutated by tool output.

Policy (enforced by :mod:`app.security.gateway`):

============================  ==========================================================
LOW                           executes, rate limited, audited
MEDIUM                        executes unless the manifest declares ``confirm=True``, in
                              which case one fresh approval is required per action
HIGH                          always requires a fresh, hash-bound, single-use approval
============================  ==========================================================
"""

from __future__ import annotations

from enum import IntEnum

__all__ = ["RISK_ORDER", "Risk", "requires_approval", "risk_from_name"]


class Risk(IntEnum):
    """Ordered risk tier; comparison operators are meaningful."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        """Lowercase name: the API, the audit trail and approval prompts all use this form."""
        return self.name.lower()

    @classmethod
    def parse(cls, value: Risk | int | str) -> Risk:
        """Parse a tier from a manifest value, config value, or API payload."""
        if isinstance(value, cls):
            return value
        if isinstance(value, int):
            return cls(value)
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:  # pragma: no cover - defensive
            raise ValueError(f"unknown risk tier: {value!r}") from exc


RISK_ORDER: tuple[Risk, ...] = (Risk.LOW, Risk.MEDIUM, Risk.HIGH)


def requires_approval(risk: Risk, *, confirm: bool = False) -> bool:
    """
    Whether this tier needs a fresh approval.

    HIGH always does - no configuration, no override. MEDIUM does only when the manifest says
    so, which is how drafts and previews stay frictionless while a real send or publish does not.
    """
    if risk is Risk.HIGH:
        return True
    return risk is Risk.MEDIUM and confirm


def risk_from_name(name: str) -> Risk:
    """Convenience wrapper used by the integration spec parsers."""
    return Risk.parse(name)
