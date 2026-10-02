# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.


class APIError(Exception):
    """Safe, typed error rendered using the public API error envelope."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int = 400,
        retryable: bool = False,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.retryable = retryable


class AuthenticationError(APIError):
    def __init__(
        self, code: str = "auth_invalid_credentials", message: str = "Authentication failed"
    ) -> None:
        super().__init__(code, message, status_code=401)


class AuthorizationError(APIError):
    def __init__(self, code: str = "permission_denied", message: str = "Permission denied") -> None:
        super().__init__(code, message, status_code=403)


class PolicyError(APIError):
    def __init__(self, message: str = "Verification is required") -> None:
        super().__init__("policy_verification_required", message, status_code=428)
