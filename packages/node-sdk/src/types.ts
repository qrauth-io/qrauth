// ---------------------------------------------------------------------------
// Constructor options
// ---------------------------------------------------------------------------

export interface QRAuthOptions {
  /** API key (starts with `qrauth_`). Used for QR code management endpoints. */
  apiKey?: string;
  /** App client ID (starts with `qrauth_app_`). Used for auth-session endpoints. */
  clientId?: string;
  /** App client secret. Used with clientId for server-side auth-session flows. */
  clientSecret?: string;
  /** Base URL of the QRAuth API. Defaults to `https://qrauth.io`. */
  baseUrl?: string;
}

// ---------------------------------------------------------------------------
// Algorithm versions (QRVA protocol)
//
// Duplicated from `packages/shared/src/alg-versions.ts` so `@qrauth/node`
// stays dependency-free when published. The strings below are protocol-
// pinned by the cross-language test vectors in
// `packages/protocol-tests/fixtures/canonical-vectors.json` — any drift
// between this file and the shared source fails CI.
// ---------------------------------------------------------------------------

export const ALG_VERSIONS = {
  HYBRID_ECDSA_SLHDSA_V1: 'hybrid-ecdsa-slhdsa-v1',
  SLHDSA_SHA2_128S_V1: 'slhdsa-sha2-128s-v1',
  SLHDSA_SHA2_256S_V1: 'slhdsa-sha2-256s-v1',
} as const;

export type AlgVersion = string;

export type AlgVersionStatus = 'accepted' | 'deprecated' | 'rejected' | 'unknown';

const DEPRECATED_ALG_VERSIONS: ReadonlySet<string> = new Set<string>([]);

/**
 * Returns true if the given alg_version is on the deprecation list.
 * Use this to surface operator warnings in application dashboards.
 * Do not surface to end users.
 */
export function isAlgDeprecated(algVersion: string): boolean {
  return DEPRECATED_ALG_VERSIONS.has(algVersion);
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
  /**
   * Per-token ECDSA-P256 signature over the canonical payload. Retained
   * on the row for classical-verifier compatibility. The tenant's
   * SLH-DSA signature covers the Merkle batch root (not per token) and
   * is referenced via `merkle_batch_id` below.
   */
  signature: string;
  organization_id: string;
  label: string | null;
  created_at: string;
  expires_at: string | null;
  transparency_log_index: number | null;
  domain_warnings?: DomainWarning[];
  /**
   * Algorithm version the token was signed under. One of
   * `ALG_VERSIONS.*`. Tokens issued after the PQC migration default to
   * `HYBRID_ECDSA_SLHDSA_V1`. Legacy tokens retain
   * `ECDSA_P256_SHA256_V1` until re-issued.
   */
  alg_version?: AlgVersion;
  /**
   * Identifier of the signed Merkle batch this token belongs to. Every
   * hybrid-signed token lives in exactly one batch; the batch's Merkle
   * root is signed with SLH-DSA. Use this to look up batch metadata
   * via `GET /api/v1/transparency/batch/:batchId` for audit purposes.
   */
  merkle_batch_id?: string;
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
  algVersion?: AlgVersion;
  merkleBatchId?: string;
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

/**
 * Verification warning surfaced by the verifier when a non-fatal
 * condition is detected. A `warnings` array on a successful
 * `VerificationResult` does not make the token invalid — it signals
 * that operators should plan a response (re-issue, monitor, etc).
 *
 * Surface this to operator dashboards. Do not surface to end users.
 */
export interface VerificationWarning {
  code: 'ALG_DEPRECATED' | 'TOKEN_EXPIRING_SOON' | 'GEO_MISMATCH_SOFT';
  message: string;
  /** Present only when `code === 'ALG_DEPRECATED'`. ISO 8601. */
  sunsetDate?: string;
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
    /**
     * Algorithm version the token was signed under. One of
     * `ALG_VERSIONS.*` values.
     */
    algVersion?: AlgVersion;
    /**
     * Classification of `algVersion` at verification time. Values:
     *   - `accepted`   — current, recommended
     *   - `deprecated` — still verifies, but sunsetting; see `warnings`
     *   - `rejected`   — verification fails closed
     *   - `unknown`    — schema violation, verification fails closed
     */
    algVersionStatus?: AlgVersionStatus;
    /**
     * True when `algVersion` is anything other than the legacy ECDSA
     * string. Equivalent to the guarantee "this token is protected by
     * a post-quantum signing leg in addition to the classical one".
     */
    pqcProtected?: boolean;
    /**
     * True when the token's Merkle inclusion proof verified against
     * the signed batch root. `false` here means the PQC leg is
     * rejected even if the classical ECDSA leg passed.
     */
    merkleProofValid?: boolean;
    /**
     * Batch identifier the token was issued under. Use with
     * `GET /api/v1/transparency/batch/:batchId` for auditor lookups.
     */
    merkleBatchId?: string;
  };
  domain_warning?: {
    message: string;
    similarDomain: string;
    verifiedOrg: string;
  };
  /**
   * Non-fatal advisory conditions surfaced by the verifier. Empty
   * array (or undefined) means no warnings fired. Always check this
   * in your operator dashboard even when `verified === true`.
   */
  warnings?: VerificationWarning[];
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
  results: Array<
    | { index: number; success: true; data: QRCodeResponse; label?: string }
    | { index: number; success: false; error: string; errorCode: string; label?: string }
  >;
}

// ---------------------------------------------------------------------------
// Auth Sessions
// ---------------------------------------------------------------------------

export interface CreateAuthSessionOptions {
  /** Requested scopes (e.g. `['identity', 'email']`). */
  scopes?: string[];
  /** URL to redirect after approval (for deep-link flows). */
  redirectUrl?: string;
  /** Arbitrary metadata attached to the session. */
  metadata?: Record<string, unknown>;
  /** PKCE code challenge (S256). Required for public-client flows. */
  codeChallenge?: string;
  /** Code challenge method. Only `'S256'` is supported. */
  codeChallengeMethod?: 'S256';
}

export interface AuthSessionResponse {
  sessionId: string;
  token: string;
  qrUrl: string;
  qrDataUrl: string;
  status: string;
  scopes: string[];
  expiresAt: string;
}

export interface AuthSessionUser {
  id: string;
  name?: string;
  email?: string;
}

export interface AuthSessionStatus {
  sessionId: string;
  status: 'PENDING' | 'SCANNED' | 'APPROVED' | 'DENIED' | 'EXPIRED';
  scopes: string[];
  user: AuthSessionUser | null;
  signature: string | null;
  expiresAt: string;
  scannedAt: string | null;
  resolvedAt: string | null;
}

export interface GetAuthSessionOptions {
  /** PKCE code verifier. Required to access user data on PKCE sessions. */
  codeVerifier?: string;
}

export interface AuthSessionVerifyResult {
  valid: boolean;
  session: {
    id: string;
    status: string;
    appName: string;
    scopes: string[];
    user: AuthSessionUser | null;
    signature: string | null;
    resolvedAt: string | null;
  };
}

// ---------------------------------------------------------------------------
// Ephemeral Sessions
// ---------------------------------------------------------------------------

export interface CreateEphemeralSessionOptions {
  /** Permission scopes granted to the ephemeral session. */
  scopes: string[];
  /** Time-to-live as a duration string (e.g. '30m', '4h', '72h'). Default: '30m'. */
  ttl?: string;
  /** Maximum number of times the session can be claimed. Default: 1. */
  maxUses?: number;
  /** Lock session to the first device that claims it. Default: false. */
  deviceBinding?: boolean;
  /** Developer-defined context attached to the session. */
  metadata?: Record<string, unknown>;
}

export interface EphemeralSessionResponse {
  sessionId: string;
  token: string;
  claimUrl: string;
  expiresAt: string;
  scopes: string[];
  ttlSeconds: number;
  maxUses: number;
}

export interface ClaimEphemeralSessionOptions {
  /** Device fingerprint for device-bound sessions. */
  deviceFingerprint?: string;
}

export interface EphemeralSessionClaimResult {
  sessionId: string;
  status: string;
  scopes: string[];
  metadata: Record<string, unknown> | null;
  expiresAt: string;
}

export interface ListEphemeralSessionsOptions {
  /** Filter by status. */
  status?: 'PENDING' | 'CLAIMED' | 'EXPIRED' | 'REVOKED';
  page?: number;
  pageSize?: number;
}

export interface EphemeralSessionDetail {
  id: string;
  token: string;
  status: string;
  scopes: string[];
  ttlSeconds: number;
  maxUses: number;
  useCount: number;
  deviceBinding: boolean;
  metadata: Record<string, unknown> | null;
  claimUrl: string;
  claimedAt: string | null;
  expiresAt: string;
  revokedAt: string | null;
  createdAt: string;
}

// ---------------------------------------------------------------------------
// Proximity Attestation
// ---------------------------------------------------------------------------

export interface ProximityAttestationOptions {
  clientLat: number;
  clientLng: number;
}

export interface ProximityAttestationResult {
  jwt: string;
  claims: Record<string, unknown>;
  publicKey: string;
  keyId: string;
}

export interface ProximityVerifyOptions {
  jwt: string;
  publicKey?: string;
}

export interface ProximityVerifyResult {
  valid: boolean;
  claims?: Record<string, unknown>;
  error?: string;
}
