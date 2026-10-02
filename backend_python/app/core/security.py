# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken as InvalidFernetToken
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key

from app.config import Settings

_password_hasher = PasswordHasher()


@dataclass(frozen=True, slots=True)
class VerifiedAssertion:
    device_id: str
    scope: str
    nonce: str
    issued_at: datetime
    expires_at: datetime
    factors: frozenset[str]
    claims: dict[str, Any]


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, password)
    except (InvalidHashError, VerificationError, VerifyMismatchError):
        return False


def hash_device_key(device_key: str) -> str:
    return hashlib.sha256(device_key.encode("utf-8")).hexdigest()


def verify_device_key(device_key: str, expected_hash: str) -> bool:
    if not device_key or not expected_hash:
        return False
    return hmac.compare_digest(hash_device_key(device_key), expected_hash)


def create_access_token(
    settings: Settings,
    *,
    user_id: str,
    device_id: str,
    session_id: str,
    roles: list[str],
    lifetime: timedelta | None = None,
) -> tuple[str, datetime]:
    now = datetime.now(UTC)
    expires_at = now + (lifetime or timedelta(seconds=settings.access_token_ttl_seconds))
    claims = {
        "sub": user_id,
        "device_id": device_id,
        "sid": session_id,
        "roles": roles,
        "jti": secrets.token_urlsafe(18),
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "iss": "armx-backend",
        "aud": "armx-client",
        "token_use": "access",
    }
    token = jwt.encode(claims, settings.jwt_secret_key.get_secret_value(), algorithm="HS256")
    return token, expires_at


def decode_access_token(settings: Settings, token: str) -> dict[str, Any]:
    claims = jwt.decode(
        token,
        settings.jwt_secret_key.get_secret_value(),
        algorithms=["HS256"],
        issuer="armx-backend",
        audience="armx-client",
        options={"require": ["sub", "device_id", "sid", "exp", "iat", "jti", "token_use"]},
    )
    if claims.get("token_use") != "access":
        raise jwt.InvalidTokenError("wrong token use")
    return claims


def issue_refresh_token() -> tuple[str, str]:
    token = f"arx.refresh.{secrets.token_urlsafe(48)}"
    return token, hashlib.sha256(token.encode("ascii")).hexdigest()


def hash_nonce(nonce: str) -> str:
    return hashlib.sha256(nonce.encode("utf-8")).hexdigest()


def _pairing_fernet(settings: Settings) -> Fernet:
    root_key = settings.jwt_secret_key.get_secret_value().encode("utf-8")
    derived_key = base64.urlsafe_b64encode(
        hmac.new(root_key, b"armx/pairing-credential/v1", hashlib.sha256).digest()
    )
    return Fernet(derived_key)


def encrypt_pairing_secret(settings: Settings, value: str) -> str:
    return _pairing_fernet(settings).encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_pairing_secret(settings: Settings, value: str) -> str:
    try:
        return _pairing_fernet(settings).decrypt(value.encode("ascii")).decode("utf-8")
    except (InvalidFernetToken, UnicodeError, ValueError):
        raise ValueError("Pairing credential could not be recovered") from None


def decode_ed25519_spki(public_key_b64: str) -> Ed25519PublicKey:
    try:
        der = base64.b64decode(public_key_b64, validate=True)
        public_key = load_der_public_key(der)
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid Ed25519 SPKI public key") from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("Public key must be Ed25519 SPKI DER")
    return public_key


def canonical_json_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def verify_ed25519_signature(public_key_b64: str, signature_b64: str, message: bytes) -> bool:
    try:
        public_key = decode_ed25519_spki(public_key_b64)
        signature = base64.b64decode(signature_b64, validate=True)
        public_key.verify(signature, message)
        return True
    except (ValueError, TypeError, Exception) as exc:
        # Signature/encoding failures are deliberately collapsed to avoid details leaking.
        del exc
        return False


def verify_owner_assertion(
    token: str,
    *,
    device_public_key_b64: str,
    expected_device_id: str,
    expected_scope: str,
    now: datetime,
    max_ttl_seconds: int,
    clock_skew_seconds: int = 5,
) -> VerifiedAssertion:
    """Verify a device-signed compact JWS assertion and its bound claims.

    Token claims are authenticated using the paired device Ed25519 public key. The
    optional outer JSON fields are never trusted in place of these signed claims.
    """

    public_key = decode_ed25519_spki(device_public_key_b64)
    claims = jwt.decode(
        token,
        public_key,
        algorithms=["EdDSA"],
        options={"require": ["iat", "exp", "jti", "nonce", "device_id", "scope", "single_use"]},
    )
    issued_at = datetime.fromtimestamp(int(claims["iat"]), UTC)
    expires_at = datetime.fromtimestamp(int(claims["exp"]), UTC)
    if claims.get("scope") != expected_scope and claims.get("scope") != "owner_verified":
        raise jwt.InvalidTokenError("assertion scope mismatch")
    if claims.get("device_id") != expected_device_id:
        raise jwt.InvalidTokenError("assertion device mismatch")
    if claims.get("single_use") is not True:
        raise jwt.InvalidTokenError("assertion is not single-use")
    if issued_at > now + timedelta(seconds=clock_skew_seconds):
        raise jwt.InvalidTokenError("assertion issued in the future")
    if expires_at <= now or expires_at <= issued_at:
        raise jwt.ExpiredSignatureError("assertion expired")
    if expires_at - issued_at > timedelta(seconds=max_ttl_seconds):
        raise jwt.InvalidTokenError("assertion TTL exceeds policy")

    factors_value = claims.get("factors", claims.get("satisfied_factors", []))
    if not isinstance(factors_value, list) or not all(
        isinstance(item, str) for item in factors_value
    ):
        raise jwt.InvalidTokenError("invalid assertion factors")
    nonce = claims.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise jwt.InvalidTokenError("invalid assertion nonce")
    return VerifiedAssertion(
        device_id=expected_device_id,
        scope=str(claims["scope"]),
        nonce=nonce,
        issued_at=issued_at,
        expires_at=expires_at,
        factors=frozenset(factors_value),
        claims=claims,
    )
