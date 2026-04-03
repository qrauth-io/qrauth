"""Custom exception classes for the QRAuth SDK."""


class QRAuthError(Exception):
    """Base error class for all QRAuth SDK errors."""

    def __init__(self, message: str, status_code: int, code: str) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.message!r}, status_code={self.status_code}, code={self.code!r})"


class AuthenticationError(QRAuthError):
    """Raised when the API key is invalid or missing (HTTP 401)."""

    def __init__(self, message: str = "Invalid or missing API key") -> None:
        super().__init__(message, 401, "AUTHENTICATION_ERROR")


class AuthorizationError(QRAuthError):
    """Raised when the API key lacks permission for the requested action (HTTP 403)."""

    def __init__(self, message: str = "Insufficient permissions") -> None:
        super().__init__(message, 403, "AUTHORIZATION_ERROR")


class NotFoundError(QRAuthError):
    """Raised when the requested resource does not exist (HTTP 404)."""

    def __init__(self, message: str = "Resource not found") -> None:
        super().__init__(message, 404, "NOT_FOUND")


class RateLimitError(QRAuthError):
    """Raised when the API rate limit has been exceeded (HTTP 429)."""

    def __init__(
        self, message: str = "Rate limit exceeded", retry_after: int | None = None
    ) -> None:
        super().__init__(message, 429, "RATE_LIMIT_EXCEEDED")
        self.retry_after = retry_after


class QuotaExceededError(QRAuthError):
    """Raised when the plan quota has been exceeded (HTTP 429)."""

    def __init__(self, message: str = "Plan quota exceeded") -> None:
        super().__init__(message, 429, "QUOTA_EXCEEDED")


class ValidationError(QRAuthError):
    """Raised when request validation fails (HTTP 400)."""

    def __init__(self, message: str = "Validation failed") -> None:
        super().__init__(message, 400, "VALIDATION_ERROR")
