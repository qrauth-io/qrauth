"""QRAuth Python SDK -- cryptographic QR code verification and authentication."""

from .canonical import (
    CANONICAL_FIELD_SEPARATOR,
    QRVA_PROTOCOL_VERSION,
    CanonicalQRPayload,
    assert_canonical_safe,
    canonical_geo_hash,
    canonicalize_payload,
    sha3_256_hex,
)
from .client import QRAuth
from .types import (
    ALG_VERSIONS,
    AlgVersion,
    AlgVersionStatus,
    VerificationResult,
    VerificationWarning,
    is_alg_deprecated,
)
from .errors import (
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    QRAuthError,
    QuotaExceededError,
    RateLimitError,
    ValidationError,
)
from .types import (
    AuthSessionResponse,
    AuthSessionStatus,
    AuthSessionUser,
    AuthSessionVerifyResult,
    CreateAuthSessionOptions,
    CreateEphemeralSessionOptions,
    EphemeralSessionResponse,
    ClaimEphemeralSessionOptions,
    EphemeralSessionClaimResult,
    ListEphemeralSessionsOptions,
    EphemeralSessionDetail,
    ProximityAttestationResult,
    ProximityVerifyResult,
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
    # Auth session types
    "CreateAuthSessionOptions",
    "AuthSessionResponse",
    "AuthSessionUser",
    "AuthSessionStatus",
    "AuthSessionVerifyResult",
    # Ephemeral session types
    "CreateEphemeralSessionOptions",
    "EphemeralSessionResponse",
    "ClaimEphemeralSessionOptions",
    "EphemeralSessionClaimResult",
    "ListEphemeralSessionsOptions",
    "EphemeralSessionDetail",
    # Proximity attestation types
    "ProximityAttestationResult",
    "ProximityVerifyResult",
    # QRVA canonical serialization (cross-language protocol)
    "QRVA_PROTOCOL_VERSION",
    "CANONICAL_FIELD_SEPARATOR",
    "CanonicalQRPayload",
    "sha3_256_hex",
    "canonical_geo_hash",
    "canonicalize_payload",
    "assert_canonical_safe",
    # QRVA algorithm versioning
    "ALG_VERSIONS",
    "AlgVersion",
    "AlgVersionStatus",
    "VerificationResult",
    "VerificationWarning",
    "is_alg_deprecated",
]

__version__ = "0.2.0"
