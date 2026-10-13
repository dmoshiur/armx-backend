# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Google sign-in (OpenID Connect authorization-code flow).

Deliberately small and explicit:

* The ``state`` value carries a timestamp, a random nonce and an HMAC over both, so it cannot be
  forged and cannot be replayed after ten minutes. A CSRF attempt fails before any network call.
* The ID token is verified properly - RS256 signature against Google's JWKS (cached, keyed by
  ``kid``), plus ``iss``, ``aud`` and expiry. A token is never trusted because it decodes.
* The code exchange and the JWKS fetch go through one pooled, timeout-bounded HTTP client, so a
  hung Google endpoint cannot tie up a worker.

Sign-in is disabled until ``GOOGLE_OAUTH_ENABLED=true`` and the client credentials are set, and
the production validator refuses to start with the flag on but no credentials configured.
"""

from __future__ import annotations

import json
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any

import httpx
import jwt
from jwt import InvalidTokenError

from app.config import Settings
from app.core.crypto import constant_time_compare, hmac_hex, new_nonce
from app.core.logging import get_logger

__all__ = [
    "GoogleAuthError",
    "GoogleIdentity",
    "google_authorize_url",
    "verify_google_code",
]

logger = get_logger("auth.google")

_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"  # noqa: S105 - a URL, not a secret
_JWKS_ENDPOINT = "https://www.googleapis.com/oauth2/v3/certs"
_VALID_ISSUERS = ("accounts.google.com", "https://accounts.google.com")
_STATE_TTL_SECONDS = 600
_JWKS_TTL_SECONDS = 3600
_TIMEOUT = httpx.Timeout(10.0, connect=5.0)

_jwks_cache: dict[str, Any] = {"fetched_at": 0.0, "keys": {}}


class GoogleAuthError(Exception):
    """Sign-in failed. ``retryable`` marks upstream/network problems rather than bad input."""

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


@dataclass(frozen=True, slots=True)
class GoogleIdentity:
    subject: str
    email: str
    email_verified: bool
    name: str
    picture: str = ""


def _sign_state(settings: Settings, payload: str) -> str:
    return hmac_hex(settings.jwt_key(), payload)


def build_state(settings: Settings) -> str:
    """``<timestamp>.<nonce>.<hmac>`` - self-contained, unforgeable, short-lived."""
    payload = f"{int(time.time())}.{new_nonce()}"
    return f"{payload}.{_sign_state(settings, payload)}"


def verify_state(settings: Settings, state: str) -> None:
    """Raise unless the state was issued by this server within the last ten minutes."""
    parts = state.split(".")
    if len(parts) != 3:
        raise GoogleAuthError("Sign-in request is malformed; start again")
    timestamp, nonce, signature = parts
    if not constant_time_compare(_sign_state(settings, f"{timestamp}.{nonce}"), signature):
        raise GoogleAuthError("Sign-in request could not be verified; start again")
    try:
        issued_at = int(timestamp)
    except ValueError as exc:
        raise GoogleAuthError("Sign-in request is malformed; start again") from exc
    if abs(int(time.time()) - issued_at) > _STATE_TTL_SECONDS:
        raise GoogleAuthError("Sign-in request expired; start again")


def google_authorize_url(settings: Settings) -> tuple[str, str]:
    """URL to send the browser to, plus the state value the caller must keep."""
    state = build_state(settings)
    params = {
        "client_id": settings.google_oauth_client_id,
        "redirect_uri": settings.google_oauth_redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "prompt": "select_account",
        "include_granted_scopes": "true",
    }
    return f"{_AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}", state


async def verify_google_code(
    settings: Settings,
    *,
    code: str,
    state: str,
    client: httpx.AsyncClient | None = None,
) -> GoogleIdentity:
    """Exchange the authorization code and verify the resulting ID token."""
    verify_state(settings, state)
    if not code or len(code) > 4096:
        raise GoogleAuthError("Authorization code is missing or malformed")

    owns_client = client is None
    http = client or httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False)
    try:
        try:
            response = await http.post(
                _TOKEN_ENDPOINT,
                data={
                    "code": code,
                    "client_id": settings.google_oauth_client_id,
                    "client_secret": (
                        settings.google_oauth_client_secret.get_secret_value()
                        if settings.google_oauth_client_secret
                        else ""
                    ),
                    "redirect_uri": settings.google_oauth_redirect_uri,
                    "grant_type": "authorization_code",
                },
                headers={"Accept": "application/json"},
            )
        except httpx.HTTPError as exc:
            logger.warning("google token exchange failed: %s", type(exc).__name__)
            raise GoogleAuthError("Could not reach Google; try again", retryable=True) from exc

        if response.status_code >= 400:
            # Do not echo the body: it can contain the code or client details.
            logger.warning("google token endpoint returned %s", response.status_code)
            raise GoogleAuthError("Google rejected the sign-in attempt; start again")

        try:
            payload = response.json()
        except (json.JSONDecodeError, ValueError) as exc:
            raise GoogleAuthError("Google returned an unexpected response", retryable=True) from exc

        id_token = payload.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            raise GoogleAuthError("Google did not return an identity token")

        claims = await _verify_id_token(settings, id_token=id_token, http=http)
    finally:
        if owns_client:
            await http.aclose()

    return GoogleIdentity(
        subject=str(claims["sub"]),
        email=str(claims.get("email", "")).lower(),
        email_verified=bool(claims.get("email_verified", False)),
        name=str(claims.get("name", "")),
        picture=str(claims.get("picture", "")),
    )


async def _verify_id_token(
    settings: Settings, *, id_token: str, http: httpx.AsyncClient
) -> dict[str, Any]:
    try:
        header = jwt.get_unverified_header(id_token)
    except InvalidTokenError as exc:
        raise GoogleAuthError("Google identity token is malformed") from exc

    if header.get("alg") != "RS256":
        raise GoogleAuthError("Google identity token uses an unexpected algorithm")

    key = await _signing_key(http, kid=str(header.get("kid", "")))
    try:
        claims = jwt.decode(
            id_token,
            key=key,
            algorithms=["RS256"],
            audience=settings.google_oauth_client_id,
            issuer=list(_VALID_ISSUERS),
            options={"require": ["exp", "iat", "sub", "aud", "iss"]},
        )
    except InvalidTokenError as exc:
        raise GoogleAuthError("Google identity token could not be verified") from exc

    if not claims.get("email"):
        raise GoogleAuthError("Google account has no email address")
    return claims


async def _signing_key(http: httpx.AsyncClient, *, kid: str) -> Any:
    """Return the RSA public key for ``kid``, refreshing the cache once if it is unknown."""
    keys = await _jwks(http)
    key = keys.get(kid)
    if key is None:
        keys = await _jwks(http, force=True)
        key = keys.get(kid)
    if key is None:
        raise GoogleAuthError("Google signing key was not recognised")
    return key


async def _jwks(http: httpx.AsyncClient, *, force: bool = False) -> dict[str, Any]:
    now = time.time()
    cached: dict[str, Any] = _jwks_cache["keys"]
    if cached and not force and now - float(_jwks_cache["fetched_at"]) < _JWKS_TTL_SECONDS:
        return cached

    try:
        response = await http.get(_JWKS_ENDPOINT, headers={"Accept": "application/json"})
        response.raise_for_status()
        payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("google jwks fetch failed: %s", type(exc).__name__)
        if cached:  # a stale key is better than refusing every sign-in during an outage
            return cached
        raise GoogleAuthError("Could not verify Google keys; try again", retryable=True) from exc

    keys: dict[str, Any] = {}
    for entry in payload.get("keys", []):
        try:
            keys[str(entry["kid"])] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(entry))
        except (KeyError, ValueError, TypeError):  # pragma: no cover - defensive
            continue
    _jwks_cache["keys"] = keys
    _jwks_cache["fetched_at"] = now
    return keys


def reset_jwks_cache() -> None:
    """Clear the cached signing keys (tests, and an operator-forced refresh)."""
    _jwks_cache["keys"] = {}
    _jwks_cache["fetched_at"] = 0.0
