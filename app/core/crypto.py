# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Cryptographic helpers.

The approval protocol depends on one property above all others: two logically identical
tool calls must produce byte-identical canonical JSON, and any single changed argument
must produce a different hash. Everything here exists to guarantee that.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import date, datetime, time
from decimal import Decimal
from enum import Enum
from typing import Any, Final
from uuid import UUID

__all__ = [
    "constant_time_compare",
    "decrypt_bytes",
    "encrypt_bytes",
    "hash_token",
    "new_nonce",
    "random_token",
    "sha256_hex",
    "stable_hash",
    "to_canonical_json",
    "to_canonical_text",
]

_MAX_CANONICAL_DEPTH: Final = 12


def _canonicalize(value: Any, depth: int = 0) -> Any:
    if depth > _MAX_CANONICAL_DEPTH:
        raise ValueError("structure too deeply nested to canonicalise")
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        # Reject NaN/inf: they are not valid JSON and would break cross-language hashing.
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("non-finite numbers cannot be canonicalised")
        return value
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, (datetime,)):
        return value.astimezone().isoformat() if value.tzinfo else value.isoformat()
    if isinstance(value, (date, time)):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Enum):
        return _canonicalize(value.value, depth + 1)
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, (list, tuple)):
        return [_canonicalize(item, depth + 1) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(_canonicalize(item, depth + 1) for item in value)
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"canonical JSON requires string keys, got {type(key).__name__}")
            out[key] = _canonicalize(item, depth + 1)
        return out
    if hasattr(value, "model_dump"):
        return _canonicalize(value.model_dump(mode="json"), depth + 1)
    raise ValueError(f"unsupported type for canonicalisation: {type(value).__name__}")


def to_canonical_text(value: Any) -> str:
    """Deterministic JSON text: sorted keys, no insignificant whitespace, UTF-8 safe."""
    return json.dumps(
        _canonicalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def to_canonical_json(value: Any) -> bytes:
    """UTF-8 bytes of :func:`to_canonical_text`."""
    return to_canonical_text(value).encode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    payload = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(payload).hexdigest()


def stable_hash(value: Any) -> str:
    """Canonical hash of a JSON-like structure (used for argument digests)."""
    return sha256_hex(to_canonical_json(value))


def hash_token(token: str, secret: str = "") -> str:
    """
    Hash a bearer token for storage.

    A server-side secret is prepended so a database dump alone is not enough to mount an
    offline search against tokens. Rotation of the secret invalidates all stored tokens,
    which is the intended behaviour for the "rotate secrets" runbook step.
    """
    material = f"{secret}:{token}".encode()
    return hashlib.sha256(material).hexdigest()


def random_token(nbytes: int = 32) -> str:
    """URL-safe high-entropy token, safe to email or place in a QR code."""
    return secrets.token_urlsafe(nbytes)


def new_nonce() -> str:
    """Short single-use nonce for replay protection."""
    return secrets.token_urlsafe(16)


def constant_time_compare(left: str, right: str) -> bool:
    """Timing-safe string comparison (HMAC signatures, webhook digests, pairing codes)."""
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def hmac_hex(secret: str, message: str | bytes) -> str:
    """HMAC-SHA256 in hex, used to sign outbound webhook calls and verify inbound ones."""
    payload = message.encode("utf-8") if isinstance(message, str) else message
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def encrypt_bytes(fernet_key: str, payload: bytes) -> bytes:
    """Authenticated encryption at rest (Fernet = AES-128-CBC + HMAC-SHA256)."""
    from cryptography.fernet import Fernet

    return Fernet(fernet_key.encode()).encrypt(payload)


def decrypt_bytes(fernet_key: str, token: bytes) -> bytes:
    from cryptography.fernet import Fernet

    return Fernet(fernet_key.encode()).decrypt(token)
