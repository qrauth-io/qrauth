// ---------------------------------------------------------------------------
// Constructor options
// ---------------------------------------------------------------------------

export interface QRAuthOptions {
  /** API key (starts with `qrauth_`). */
  apiKey: string;
  /** Base URL of the QRAuth API. Defaults to `https://qrauth.io`. */
  baseUrl?: string;
}

// ---------------------------------------------------------------------------
// QR Code — create
// ---------------------------------------------------------------------------

export interface CreateQRCodeOptions {
  /** The URL this QR code points to. Required for URL-type QR codes. */
  destination: string;
  /** Human-readable label. */
  label?: string;
  /** Physical location where the QR code will be deployed. */
  location?: {
    lat: number;
    lng: number;
    /** Geo-fence radius in metres. Default: 50. */
    radiusM?: number;
  };
  /**
   * Expiration as a duration string (e.g. `'1y'`, `'30d'`, `'6h'`) or
   * an ISO 8601 datetime string. If omitted, the QR code never expires.
   */
  expiresIn?: string;
  /** Content type (e.g. `'url'`, `'event'`, `'coupon'`). Defaults to `'url'`. */
  contentType?: string;
  /** Structured content payload (for non-URL content types). */
  content?: Record<string, unknown>;
}

export interface QRCodeResponse {
  token: string;
  verification_url: string;
  qr_image_url: string;
  signature: string;
  organization_id: string;
  label: string | null;
  created_at: string;
  expires_at: string | null;
  transparency_log_index: number | null;
  domain_warnings?: DomainWarning[];
}

export interface DomainWarning {
  similar_to: string;
  verified_org: string;
  similarity: number;
  reason: string;
}

// ---------------------------------------------------------------------------
// QR Code — list
// ---------------------------------------------------------------------------

export interface ListQRCodesOptions {
  page?: number;
  pageSize?: number;
  status?: 'ACTIVE' | 'EXPIRED' | 'REVOKED';
}

export interface QRCodeDetail {
  token: string;
  destinationUrl: string;
  label: string | null;
  status: string;
  signature: string;
  contentType: string;
  content: Record<string, unknown> | null;
  latitude: number | null;
  longitude: number | null;
  radiusM: number;
  expiresAt: string | null;
  createdAt: string;
  updatedAt: string;
  _count: { scans: number };
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
}

// ---------------------------------------------------------------------------
// QR Code — verify
// ---------------------------------------------------------------------------

export interface VerifyOptions {
  /** Client latitude for geo-fence matching. */
  clientLat?: number;
  /** Client longitude for geo-fence matching. */
  clientLng?: number;
}

export interface VerificationResult {
  verified: boolean;
  organization: {
    id: string;
    name: string;
    slug: string;
    trustLevel: string;
    kycStatus: string;
    domainVerified?: boolean;
  };
  destination_url: string;
  location_match: {
    matched: boolean;
    distanceM: number | null;
    registeredAddress: string | null;
  };
  security: {
    signatureValid: boolean;
    proxyDetected: boolean;
    trustScore: number;
    transparencyLogVerified: boolean;
  };
  domain_warning?: {
    message: string;
    similarDomain: string;
    verifiedOrg: string;
  };
  scannedAt: string;
}

// ---------------------------------------------------------------------------
// Bulk create
// ---------------------------------------------------------------------------

export interface BulkCreateItem {
  destination: string;
  label?: string;
  location?: {
    lat: number;
    lng: number;
    radiusM?: number;
  };
  expiresIn?: string;
}

export interface BulkCreateResponse {
  total: number;
  succeeded: number;
  failed: number;
  results: Array<{
    index: number;
    success: boolean;
    data?: QRCodeResponse;
    error?: string;
  }>;
}
