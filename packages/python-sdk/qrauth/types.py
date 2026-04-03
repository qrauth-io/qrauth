"""Type definitions for the QRAuth SDK.

Uses TypedDict for structured response/request shapes, providing editor
autocompletion and static-analysis support without runtime overhead.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, TypedDict


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
    signature: str
    organization_id: str
    label: Optional[str]
    created_at: str
    expires_at: Optional[str]
    transparency_log_index: Optional[int]
    domain_warnings: List[DomainWarning]


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
    scannedAt: str  # noqa: N815


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
