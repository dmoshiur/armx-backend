# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

from app.core.risk_policy import RiskTier, evaluate, required_factors


def test_low_requires_face_and_voice_alone_never_qualifies() -> None:
    assert required_factors(RiskTier.LOW) == frozenset({"face"})
    assert not evaluate(
        RiskTier.LOW,
        {"voice"},
        signature_valid=True,
        unexpired=True,
    ).allowed
    assert evaluate(
        RiskTier.LOW,
        {"face"},
        signature_valid=True,
        unexpired=True,
    ).allowed


def test_medium_requires_face_and_voice() -> None:
    assert not evaluate(
        RiskTier.MEDIUM,
        {"face"},
        signature_valid=True,
        unexpired=True,
    ).allowed
    assert evaluate(
        RiskTier.MEDIUM,
        {"face", "voice"},
        signature_valid=True,
        unexpired=True,
    ).allowed


def test_high_requires_face_voice_and_biometric_or_pin() -> None:
    assert not evaluate(
        RiskTier.HIGH,
        {"face", "voice"},
        signature_valid=True,
        unexpired=True,
    ).allowed
    assert evaluate(
        RiskTier.HIGH,
        {"face", "voice", "pin"},
        signature_valid=True,
        unexpired=True,
    ).allowed


def test_invalid_signature_or_stale_evidence_fails_closed() -> None:
    assert not evaluate(
        RiskTier.LOW,
        {"face"},
        signature_valid=False,
        unexpired=True,
    ).allowed
    assert not evaluate(
        RiskTier.LOW,
        {"face"},
        signature_valid=True,
        unexpired=False,
    ).allowed
    assert RiskTier.from_wire("unknown") is RiskTier.HIGH
