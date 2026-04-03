"""QRAuth Python SDK -- cryptographic QR code verification and authentication."""

from .client import QRAuth
from .errors import (
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    QRAuthError,
    QuotaExceededError,
    RateLimitError,
    ValidationError,
)

__all__ = [
    "QRAuth",
    "QRAuthError",
    "AuthenticationError",
    "AuthorizationError",
    "NotFoundError",
    "RateLimitError",
    "QuotaExceededError",
    "ValidationError",
]

__version__ = "0.1.0"
