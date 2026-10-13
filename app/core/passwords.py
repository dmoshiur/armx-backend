# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Password hashing and strength policy.

argon2id is the default. If argon2 is unavailable on the target infrastructure the module
falls back to bcrypt at cost 12 (never to a fast hash), so a deployment can never silently
end up storing unsalted SHA-256 digests.
"""

from __future__ import annotations

import re
from typing import Final, Protocol

__all__ = [
    "PasswordPolicyError",
    "active_backend",
    "dummy_verify",
    "hash_password",
    "needs_rehash",
    "password_policy_error",
    "verify_password",
]

# OWASP-aligned argon2id parameters (64 MiB, 3 passes, 2 lanes).
_ARGON2_TIME_COST: Final = 3
_ARGON2_MEMORY_COST: Final = 65536
_ARGON2_PARALLELISM: Final = 2
_ARGON2_HASH_LEN: Final = 32

_BCRYPT_ROUNDS: Final = 12

_COMMON_PASSWORDS: Final = frozenset(
    {
        "password",
        "password1",
        "password123",
        "passw0rd",
        "123456",
        "12345678",
        "123456789",
        "1234567890",
        "qwerty",
        "qwerty123",
        "letmein",
        "welcome",
        "admin",
        "admin123",
        "administrator",
        "iloveyou",
        "monkey",
        "dragon",
        "football",
        "baseball",
        "sunshine",
        "princess",
        "trustno1",
        "armx",
        "armxai",
        "armx123",
        "changeme",
        "secret",
        "testpassword",
        "correcthorsebatterystaple",
    }
)
#: Common words that make a password weak *wherever* they appear, not only on their own:
#: "passwordpasswordpassword" and "MySecret123!" are both still breach-corpus passwords.
_COMMON_SUBSTRINGS: Final = (
    "password",
    "passw0rd",
    "123456",
    "12345678",
    "qwerty",
    "letmein",
    "welcome",
    "iloveyou",
    "monkey",
    "dragon",
    "changeme",
    "administrator",
    "armxai",
    "trustno1",
)

_REPEATED_CHAR: Final = re.compile(r"(.)\1{3,}")
_SEQUENTIAL: Final = ("0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop")


class PasswordPolicyError(ValueError):
    """Raised when a candidate password fails the strength policy."""

    def __init__(self, reason: str, guidance: str = "Choose a longer, unique passphrase.") -> None:
        super().__init__(reason)
        self.reason = reason
        self.guidance = guidance


class _Backend(Protocol):
    """Minimal interface both hashing backends implement."""

    name: str

    def hash(self, password: str) -> str: ...

    def verify(self, password: str, stored_hash: str) -> bool: ...

    def needs_rehash(self, stored_hash: str) -> bool: ...


class _Argon2Backend:
    name = "argon2id"

    def __init__(self, hasher: object) -> None:
        from argon2 import PasswordHasher

        if not isinstance(hasher, PasswordHasher):  # pragma: no cover - defensive
            raise TypeError("expected an argon2 PasswordHasher")
        self._hasher = hasher

    def hash(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify(self, password: str, stored_hash: str) -> bool:
        from argon2.exceptions import (
            InvalidHashError,
            VerificationError,
            VerifyMismatchError,
        )

        try:
            return bool(self._hasher.verify(stored_hash, password))
        except (InvalidHashError, VerificationError, VerifyMismatchError):
            return False

    def needs_rehash(self, stored_hash: str) -> bool:
        try:
            return bool(self._hasher.check_needs_rehash(stored_hash))
        except Exception:
            return True


class _BcryptBackend:
    name = "bcrypt"

    def __init__(self, module: object) -> None:
        self._bcrypt = module

    def hash(self, password: str) -> str:
        bcrypt = self._bcrypt
        salt = bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)  # type: ignore[attr-defined]
        return str(bcrypt.hashpw(password.encode(), salt).decode())  # type: ignore[attr-defined]

    def verify(self, password: str, stored_hash: str) -> bool:
        bcrypt = self._bcrypt
        try:
            return bool(bcrypt.checkpw(password.encode(), stored_hash.encode()))  # type: ignore[attr-defined]
        except ValueError:
            return False

    def needs_rehash(self, stored_hash: str) -> bool:
        if stored_hash.startswith(("$2a$", "$2b$", "$2y$")):
            try:
                return int(stored_hash.split("$")[2]) < _BCRYPT_ROUNDS
            except (IndexError, ValueError):  # pragma: no cover - defensive
                return True
        return True


def _select_backend() -> _Backend:
    try:
        from argon2 import PasswordHasher, Type

        hasher = PasswordHasher(
            time_cost=_ARGON2_TIME_COST,
            memory_cost=_ARGON2_MEMORY_COST,
            parallelism=_ARGON2_PARALLELISM,
            hash_len=_ARGON2_HASH_LEN,
            type=Type.ID,
        )
        return _Argon2Backend(hasher)
    except ImportError:  # pragma: no cover - exercised only without argon2 installed
        try:
            import bcrypt
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "no password hashing backend available: install argon2-cffi (preferred) or bcrypt"
            ) from exc
        return _BcryptBackend(bcrypt)


_BACKEND: Final[_Backend] = _select_backend()

#: Verified against on every failed lookup so "unknown email" and "wrong password" take
#: the same amount of time.
_DUMMY_HASH: str | None = None


def active_backend() -> str:
    """Name of the active hashing backend (``argon2id`` or ``bcrypt``)."""
    return _BACKEND.name


def hash_password(password: str) -> str:
    """Hash a password for storage. Never returns the input."""
    return _BACKEND.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verify a password against a stored hash.

    Returns ``False`` for a malformed hash rather than raising, so a corrupted row can
    never turn into a 500 that leaks whether the account exists.
    """
    if not stored_hash:
        return False
    return _BACKEND.verify(password, stored_hash)


def needs_rehash(stored_hash: str) -> bool:
    """True when a stored hash uses weaker parameters than the current policy."""
    if not stored_hash:
        return True
    return _BACKEND.needs_rehash(stored_hash)


def dummy_verify() -> None:
    """
    Spend the same CPU time as a real verification.

    Called on the "user not found" path of login so response timing does not reveal
    whether an email address exists.
    """
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password("armx-timing-equalisation-placeholder")
    verify_password("wrong-password", _DUMMY_HASH)


def password_policy_error(
    password: str, *, min_length: int, email: str | None = None
) -> str | None:
    """
    Return a human-readable reason when a password is unacceptable, else ``None``.

    Deliberately lenient about composition classes (length beats complexity theatre) but
    strict about the failure modes that actually show up in breach corpora.
    """
    if len(password) < min_length:
        return f"Password must be at least {min_length} characters"
    if len(password) > 256:
        return "Password must be at most 256 characters"
    lowered = password.lower()
    if lowered in _COMMON_PASSWORDS or any(word in lowered for word in _COMMON_SUBSTRINGS):
        return "Password is too common"
    if email:
        local, _, domain = email.lower().partition("@")
        if local and len(local) >= 3 and local in lowered:
            return "Password must not contain your email address"
        if domain and domain in lowered:
            return "Password must not contain your email domain"
    if _REPEATED_CHAR.search(password):
        return "Password repeats the same character too many times"
    if any(seq in lowered for seq in _SEQUENTIAL) and len(password) < 20:
        return "Password contains a long keyboard or alphabet sequence"
    return None
