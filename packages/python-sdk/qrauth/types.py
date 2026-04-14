"""Type definitions for the QRAuth SDK.

Uses TypedDict for structured response/request shapes, providing editor
autocompletion and static-analysis support without runtime overhead.
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, TypedDict


# ---------------------------------------------------------------------------
# Algorithm versions (QRVA protocol)
#
# Duplicated from ``packages/shared/src/alg-versions.ts`` so the published
# Python SDK stays self-contained. The strings below are protocol-pinned by
# the cross-language test vectors in
# ``packages/protocol-tests/fixtures/canonical-vectors.json`` -- any drift
# between this file and the shared source fails CI.
# ---------------------------------------------------------------------------

AlgVersion = str
AlgVersionStatus = Literal["accepted", "deprecated", "rejected", "unknown"]


class _AlgVersionsConst:
    """Namespace for QRVA-compliant algorithm version strings.

    Prefer ``ALG_VERSIONS.HYBRID_ECDSA_SLHDSA_V1`` over raw strings in
    application code so an IDE can auto-complete the set and typos fail
    at import time rather than at signature-verification time.
    """

    ECDSA_P256_SHA256_V1: str = "ecdsa-p256-sha256-v1"
    HYBRID_ECDSA_SLHDSA_V1: str = "hybrid-ecdsa-slhdsa-v1"
    SLHDSA_SHA2_128S_V1: str = "slhdsa-sha2-128s-v1"
    SLHDSA_SHA2_256S_V1: str = "slhdsa-sha2-256s-v1"


ALG_VERSIONS = _AlgVersionsConst()

_DEPRECATED_ALG_VERSIONS = frozenset({ALG_VERSIONS.ECDSA_P256_SHA256_V1})


def is_alg_deprecated(alg_version: str) -> bool:
    """Return True if the token was signed with a deprecated algorithm.

    Use this in operator dashboards to surface "tokens using deprecated
    cryptography" warnings. Do not surface to end users.
    """
    return alg_version in _DEPRECATED_ALG_VERSIONS


# ---------------------------------------------------------------------------
# QR Code -- create
# ---------------------------------------------------------------------------


class LocationInput(TypedDict, total=False):
    lat: float
    lng: float
    radiusM: int  # noqa: N815 (matches API field name)


class CreateQRCodeOptions(TypedDict, total=False):
    """Options for ``QRAuth.create()``."""

    destination: str
    label: str
    location: LocationInput
    expires_in: str
    content_type: str
    content: Dict[str, Any]


class DomainWarning(TypedDict, total=False):
    similar_to: str
    verified_org: str
    similarity: float
    reason: str


class QRCodeResponse(TypedDict, total=False):
    token: str
    verification_url: str
    qr_image_url: str
    # Per-token ECDSA-P256 signature. Retained on the row for classical-
    # verifier compatibility. The tenant's SLH-DSA signature covers the
    # Merkle batch root (referenced via ``merkle_batch_id``) and is
    # fetched via the transparency-log batch endpoint, not returned here.
    signature: str
    organization_id: str
    label: Optional[str]
    created_at: str
    expires_at: Optional[str]
    transparency_log_index: Optional[int]
    domain_warnings: List[DomainWarning]
    # PQC fields (present on tokens issued after the hybrid cutover).
    alg_version: AlgVersion
    merkle_batch_id: str


# ---------------------------------------------------------------------------
# QR Code -- list
# ---------------------------------------------------------------------------


class ListQRCodesOptions(TypedDict, total=False):
    page: int
    page_size: int
    status: str  # "ACTIVE" | "EXPIRED" | "REVOKED"


class ScanCount(TypedDict):
    scans: int


class QRCodeDetail(TypedDict, total=False):
    token: str
    destinationUrl: str  # noqa: N815
    label: Optional[str]
    status: str
    signature: str
    contentType: str  # noqa: N815
    content: Optional[Dict[str, Any]]
    latitude: Optional[float]
    longitude: Optional[float]
    radiusM: int  # noqa: N815
    expiresAt: Optional[str]  # noqa: N815
    createdAt: str  # noqa: N815
    updatedAt: str  # noqa: N815
    _count: ScanCount


class PaginatedResponse(TypedDict):
    data: List[QRCodeDetail]
    total: int
    page: int
    pageSize: int  # noqa: N815
    totalPages: int  # noqa: N815


# ---------------------------------------------------------------------------
# QR Code -- verify
# ---------------------------------------------------------------------------


class VerifyOptions(TypedDict, total=False):
    client_lat: float
    client_lng: float


class OrganizationInfo(TypedDict, total=False):
    id: str
    name: str
    slug: str
    trustLevel: str  # noqa: N815
    kycStatus: str  # noqa: N815
    domainVerified: bool  # noqa: N815


class LocationMatch(TypedDict, total=False):
    matched: bool
    distanceM: Optional[float]  # noqa: N815
    registeredAddress: Optional[str]  # noqa: N815


class SecurityInfo(TypedDict, total=False):
    signatureValid: bool  # noqa: N815
    proxyDetected: bool  # noqa: N815
    trustScore: int  # noqa: N815
    transparencyLogVerified: bool  # noqa: N815
    # PQC-era fields. Present on tokens issued after the hybrid cutover.
    algVersion: AlgVersion  # noqa: N815
    algVersionStatus: AlgVersionStatus  # noqa: N815
    pqcProtected: bool  # noqa: N815
    merkleProofValid: bool  # noqa: N815
    merkleBatchId: str  # noqa: N815


class VerificationWarning(TypedDict, total=False):
    """Non-fatal advisory surfaced by the verifier.

    A ``warnings`` entry on a successful verification does not make
    the token invalid -- it signals that operators should plan a
    response (re-issue, monitor, etc). Surface to operator dashboards
    only, not to end users.
    """

    code: Literal["ALG_DEPRECATED", "TOKEN_EXPIRING_SOON", "GEO_MISMATCH_SOFT"]
    message: str
    # Present only when ``code == "ALG_DEPRECATED"``. ISO 8601.
    sunset_date: str


class DomainWarningInfo(TypedDict, total=False):
    message: str
    similarDomain: str  # noqa: N815
    verifiedOrg: str  # noqa: N815


class VerificationResult(TypedDict, total=False):
    verified: bool
    organization: OrganizationInfo
    destination_url: str
    location_match: LocationMatch
    security: SecurityInfo
    domain_warning: DomainWarningInfo
    # Non-fatal advisory conditions surfaced by the verifier. Check
    # this in operator dashboards even when ``verified`` is True.
    warnings: List[VerificationWarning]
    scannedAt: str  # noqa: N815


# ---------------------------------------------------------------------------
# Auth Sessions
# ---------------------------------------------------------------------------


class CreateAuthSessionOptions(TypedDict, total=False):
    """Options for ``QRAuth.create_auth_session()``."""

    scopes: List[str]
    redirect_url: str
    metadata: Dict[str, Any]
    code_challenge: str
    code_challenge_method: str  # Only "S256" is supported


class AuthSessionResponse(TypedDict, total=False):
    session_id: str
    token: str
    qr_url: str
    qr_data_url: str
    status: str
    scopes: List[str]
    expires_at: str


class AuthSessionUser(TypedDict, total=False):
    id: str
    name: Optional[str]
    email: Optional[str]


class AuthSessionStatus(TypedDict, total=False):
    session_id: str
    status: str  # "PENDING" | "SCANNED" | "APPROVED" | "DENIED" | "EXPIRED"
    scopes: List[str]
    user: Optional[AuthSessionUser]
    signature: Optional[str]
    expires_at: str
    scanned_at: Optional[str]
    resolved_at: Optional[str]


class _AuthSessionVerifySession(TypedDict, total=False):
    id: str
    status: str
    app_name: str
    scopes: List[str]
    user: Optional[AuthSessionUser]
    signature: Optional[str]
    resolved_at: Optional[str]


class AuthSessionVerifyResult(TypedDict, total=False):
    valid: bool
    session: _AuthSessionVerifySession


# ---------------------------------------------------------------------------
# Ephemeral Sessions
# ---------------------------------------------------------------------------


class CreateEphemeralSessionOptions(TypedDict, total=False):
    """Options for ``QRAuth.create_ephemeral_session()``."""

    scopes: List[str]
    ttl: str
    max_uses: int
    device_binding: bool
    metadata: Dict[str, Any]


class EphemeralSessionResponse(TypedDict, total=False):
    session_id: str
    token: str
    claim_url: str
    expires_at: str
    scopes: List[str]
    ttl_seconds: int
    max_uses: int


class ClaimEphemeralSessionOptions(TypedDict, total=False):
    """Options for ``QRAuth.claim_ephemeral_session()``."""

    device_fingerprint: str


class EphemeralSessionClaimResult(TypedDict, total=False):
    session_id: str
    status: str
    scopes: List[str]
    metadata: Optional[Dict[str, Any]]
    expires_at: str


class ListEphemeralSessionsOptions(TypedDict, total=False):
    """Options for ``QRAuth.list_ephemeral_sessions()``."""

    status: str  # "PENDING" | "CLAIMED" | "EXPIRED" | "REVOKED"
    page: int
    page_size: int


class EphemeralSessionDetail(TypedDict, total=False):
    id: str
    token: str
    status: str
    scopes: List[str]
    ttl_seconds: int
    max_uses: int
    use_count: int
    device_binding: bool
    metadata: Optional[Dict[str, Any]]
    claim_url: str
    claimed_at: Optional[str]
    expires_at: str
    revoked_at: Optional[str]
    created_at: str


# ---------------------------------------------------------------------------
# Bulk create
# ---------------------------------------------------------------------------


class BulkCreateItem(TypedDict, total=False):
    destination: str
    label: str
    location: LocationInput
    expires_in: str


class BulkResultEntry(TypedDict, total=False):
    index: int
    success: bool
    data: QRCodeResponse
    error: str


class BulkCreateResponse(TypedDict):
    total: int
    succeeded: int
    failed: int
    results: List[BulkResultEntry]


# ---------------------------------------------------------------------------
# Proximity Attestation
# ---------------------------------------------------------------------------


class ProximityAttestationResult(TypedDict, total=False):
    jwt: str
    claims: Dict[str, Any]
    publicKey: str  # noqa: N815
    keyId: str  # noqa: N815


class ProximityVerifyResult(TypedDict, total=False):
    valid: bool
    claims: Optional[Dict[str, Any]]
    error: Optional[str]
