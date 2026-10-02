# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum


class RiskTier(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @classmethod
    def from_wire(cls, value: object) -> "RiskTier":
        try:
            return cls(str(value).upper())
        except ValueError:
            # Unknown or missing client tiers fail closed; callers must still derive
            # the actual required tier from the server-side action policy.
            return cls.HIGH


@dataclass(frozen=True, slots=True)
class RiskDecision:
    allowed: bool
    required: RiskTier
    present_factors: frozenset[str]
    missing_factors: frozenset[str]
    reason: str


def _canonical_factors(factors: Iterable[str]) -> frozenset[str]:
    aliases = {
        "face": "face",
        "voice": "voice",
        "pin": "pin",
        "system": "system_biometric",
        "biometric": "system_biometric",
        "system_biometric": "system_biometric",
    }
    return frozenset(
        aliases[item.strip().lower()] for item in factors if item.strip().lower() in aliases
    )


def required_factors(tier: RiskTier) -> frozenset[str]:
    if tier is RiskTier.LOW:
        # docs/api.md says face OR voice, but the same contract and AGENTS.md
        # explicitly disallow voice-only evidence; therefore LOW needs face.
        return frozenset({"face"})
    if tier is RiskTier.MEDIUM:
        return frozenset({"face", "voice"})
    return frozenset({"face", "voice", "system_biometric"})


def evaluate(
    tier: RiskTier,
    factors: Iterable[str],
    *,
    signature_valid: bool,
    unexpired: bool,
) -> RiskDecision:
    """Evaluate signed evidence; the client-supplied tier is never authoritative."""

    present = _canonical_factors(factors)
    if not signature_valid:
        return RiskDecision(False, tier, present, required_factors(tier), "invalid_signature")
    if not unexpired:
        return RiskDecision(False, tier, present, required_factors(tier), "evidence_expired")

    required = required_factors(tier)
    effective = set(required)
    if tier is RiskTier.HIGH:
        # A platform PIN is an accepted system-authenticator equivalent.
        effective.discard("system_biometric")
        has_system = "system_biometric" in present or "pin" in present
        missing = (required - present) - {"system_biometric"}
        if not has_system:
            missing = missing | {"system_biometric"}
    else:
        missing = required - present

    # Voice alone is explicitly not a LOW-tier identity proof.
    if tier is RiskTier.LOW and present == frozenset({"voice"}):
        missing = frozenset({"face"})

    missing_set = frozenset(missing)
    allowed = not missing_set
    return RiskDecision(
        allowed=allowed,
        required=tier,
        present_factors=present,
        missing_factors=missing_set,
        reason="verified" if allowed else "insufficient_evidence",
    )
