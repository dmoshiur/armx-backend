# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Typed API errors.

Every error the API returns is ``{"code", "message", "retryable", "request_id"}`` with a
stable machine-readable ``code``. Messages never contain secrets, SQL, or user data.
"""

from __future__ import annotations

from typing import Any

__all__ = ["APIError", "ErrorCode"]


class ErrorCode:
    """Stable error codes. Clients may branch on these; they never change meaning."""

    # request / validation
    INVALID_REQUEST = "invalid_request"
    VALIDATION_FAILED = "validation_failed"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    UNSUPPORTED_MEDIA_TYPE = "unsupported_media_type"

    # auth
    UNAUTHENTICATED = "unauthenticated"
    INVALID_CREDENTIALS = "invalid_credentials"
    TOKEN_EXPIRED = "token_expired"  # noqa: S105 - an error code, not a credential
    TOKEN_INVALID = "token_invalid"  # noqa: S105 - an error code, not a credential
    TOKEN_REUSE_DETECTED = "token_reuse_detected"  # noqa: S105 - an error code, not a credential
    EMAIL_NOT_VERIFIED = "email_not_verified"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_DISABLED = "account_disabled"
    FORBIDDEN = "forbidden"
    ROLE_REQUIRED = "role_required"
    SCOPE_REQUIRED = "scope_required"
    DEVICE_NOT_ACTIVE = "device_not_active"

    # security gateway
    TOOL_UNKNOWN = "tool_unknown"
    TOOL_DISABLED = "tool_disabled"
    TOOL_ARGUMENT_INVALID = "tool_argument_invalid"
    RATE_LIMITED = "rate_limited"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_INVALID = "approval_invalid"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_ALREADY_USED = "approval_already_used"
    APPROVAL_DENIED = "approval_denied"
    APPROVAL_ARGUMENT_MISMATCH = "approval_argument_mismatch"
    KILL_SWITCH_ENGAGED = "kill_switch_engaged"
    INTEGRATION_DISABLED = "integration_disabled"
    DESTINATION_NOT_ALLOWED = "destination_not_allowed"
    TOOL_TIMEOUT = "tool_timeout"
    TOOL_FAILED = "tool_failed"
    DRY_RUN_ONLY = "dry_run_only"
    CONSENT_REQUIRED = "consent_required"
    OWNER_PASSWORD_INVALID = "owner_password_invalid"  # noqa: S105 - an error code, not a credential

    # harness
    HARNESS_LIMIT_EXCEEDED = "harness_limit_exceeded"
    HARNESS_DEADLINE_EXCEEDED = "harness_deadline_exceeded"
    HARNESS_CANCELLED = "harness_cancelled"
    LLM_UNAVAILABLE = "llm_unavailable"
    LLM_REFUSED = "llm_refused"

    # infrastructure
    SERVICE_UNAVAILABLE = "service_unavailable"
    TLS_REQUIRED = "tls_required"
    INTERNAL_ERROR = "internal_error"
    WEBHOOK_SIGNATURE_INVALID = "webhook_signature_invalid"
    IDEMPOTENCY_CONFLICT = "idempotency_conflict"


class APIError(Exception):
    """Raise to return a structured error response."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int = 400,
        retryable: bool = False,
        details: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.retryable = retryable
        self.details = details or {}
        self.headers = headers or {}

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"APIError(code={self.code!r}, status_code={self.status_code})"

    # ------------------------------------------------------------ constructors
    @classmethod
    def unauthenticated(cls, message: str = "Authentication required") -> APIError:
        return cls(ErrorCode.UNAUTHENTICATED, message, status_code=401)

    @classmethod
    def invalid_token(cls, message: str = "Token is invalid or expired") -> APIError:
        return cls(ErrorCode.TOKEN_INVALID, message, status_code=401)

    @classmethod
    def forbidden(cls, message: str = "Not permitted") -> APIError:
        return cls(ErrorCode.FORBIDDEN, message, status_code=403)

    @classmethod
    def not_found(cls, message: str = "Resource not found") -> APIError:
        return cls(ErrorCode.NOT_FOUND, message, status_code=404)

    @classmethod
    def conflict(cls, message: str = "Resource already exists") -> APIError:
        return cls(ErrorCode.CONFLICT, message, status_code=409)

    @classmethod
    def rate_limited(cls, retry_after_seconds: int, message: str = "Too many requests") -> APIError:
        return cls(
            ErrorCode.RATE_LIMITED,
            message,
            status_code=429,
            retryable=True,
            headers={"Retry-After": str(max(1, retry_after_seconds))},
        )

    @classmethod
    def validation(cls, message: str = "Request validation failed") -> APIError:
        return cls(ErrorCode.VALIDATION_FAILED, message, status_code=422)

    @classmethod
    def unavailable(cls, message: str = "Service unavailable") -> APIError:
        return cls(ErrorCode.SERVICE_UNAVAILABLE, message, status_code=503, retryable=True)
