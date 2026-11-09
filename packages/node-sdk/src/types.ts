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
  /**
   * The URL this QR code points to. Required for URL-type QR codes; leave it
   * out for other content types, whose code points to its verification page.
   */
  destination?: string;
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
  /**
   * Content type (e.g. `'url'`, `'event'`, `'coupon'`, `'app-link'`,
   * `'link-list'`). Defaults to `'url'`. See `ContentType`.
   */
  contentType?: ContentType | (string & {});
  /**
   * Structured content payload (for non-URL content types). `AppLinkContent`
   * and `LinkListContent` describe the two link types.
   */
  content?: Record<string, unknown> | AppLinkContent | LinkListContent;
  /**
   * Browser scan behaviour for URL codes. `'FLASH'` (the API default): a
   * VERIFIED scan of an https destination without a location binding shows
   * a short trust reveal, then continues to the destination. `'PAGE'`:
   * always the full verification page. For `'app-link'` codes, FLASH
   * continues to the link for the scanner's platform; `'link-list'` codes
   * always show the page.
   */
  scanMode?: ScanMode;
}

/** Content types the API accepts. */
export type ContentType = 'url' | 'vcard' | 'coupon' | 'event' | 'pdf' | 'feedback' | 'app-link' | 'link-list';

/**
 * `content` of an `'app-link'` code: absolute https URLs (no user name or
 * password). The verify page sends iPhone, iPad and iPod to `iosUrl`,
 * Android to `androidUrl` and every other device to `fallbackUrl`.
 */
export interface AppLinkContent {
  iosUrl: string;
  androidUrl: string;
  fallbackUrl: string;
}

/** One entry of a `'link-list'` code: `label` 1–40 characters, `url` absolute https. */
export interface LinkListItem {
  label: string;
  url: string;
}

/** `content` of a `'link-list'` code: `title` 1–60 characters, `description` up to 200, 1–20 `links`. */
export interface LinkListContent {
  title: string;
  description?: string;
  links: LinkListItem[];
}

/**
 * Options for `image()` (GET /api/v1/qrcodes/:token/image). The image is the
 * code drawn with its stored style.
 *
 * - Screen size: `px` (64-1024) for PNG or SVG. Default PNG 300 px.
 * - Print PNG: `sizeMm` (10-1000) or `sizeIn` (0.4-39.37), and `dpi`
 *   (72-1200, default 300). Paid plans only.
 * - PDF (vector): `format: 'pdf'`, `sizeMm` or `sizeIn` (default 50 mm) and
 *   an optional `marginMm` (0-50). Paid plans only.
 * - SVG at a physical size: `format: 'svg'` with `sizeMm` or `sizeIn`.
 *
 * `px` and the print options are mutually exclusive, as are `sizeMm` and
 * `sizeIn`. The API answers 400 (`ValidationError`) for other combinations
 * or a print raster above 12,000 px per side or 100 megapixels, 403
 * (`AuthorizationError`) for a print export on the Free plan, and 422 for a
 * size whose modules would be under 0.4 mm.
 */
export interface QRCodeImageOptions {
  /** `png` (default), `svg` or `pdf`. */
  format?: 'png' | 'svg' | 'pdf';
  /** Screen width in pixels, 64-1024. */
  px?: number;
  /** Print width of the whole artwork (code, quiet zone and frame) in mm, 10-1000. */
  sizeMm?: number;
  /** Print width in inches, 0.4-39.37. */
  sizeIn?: number;
  /** PNG resolution for a print size, 72-1200. */
  dpi?: number;
  /** PDF margin on every side, in mm, 0-50. */
  marginMm?: number;
}

export interface QRCodeImage {
  /** The image bytes. */
  data: Buffer;
  /** `image/png`, `image/svg+xml; charset=utf-8` or `application/pdf`. */
  contentType: string;
  /** Strong ETag of the image; unchanged while the code's image is unchanged. */
  etag: string | null;
  /** The file name the API suggests, e.g. `qrauth-abc123-50mm.pdf`. */
  filename: string | null;
  /** PNG width actually rendered, in pixels (`X-QRAuth-Image-Px`); undefined for SVG without `px` and PDF. */
  px?: number;
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
  alg_version: AlgVersion;
  /**
   * Identifier of the signed Merkle batch this token belongs to. Every
   * hybrid-signed token lives in exactly one batch; the batch's Merkle
   * root is signed with SLH-DSA. Use this to look up batch metadata
   * via `GET /api/v1/transparency/batch/:batchId` for audit purposes.
   */
  merkle_batch_id: string | null;
  /** The code's scan mode setting. Absent from API versions before scan modes. */
  scan_mode?: ScanMode;
}

export interface DomainWarning {
  /** The link this warning is about (`'app-link'` and `'link-list'` codes only). */
  url?: string;
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
  /** Results per page, 1-100. Default 20. */
  pageSize?: number;
  status?: 'ACTIVE' | 'EXPIRED' | 'REVOKED';
  /**
   * Search, up to 100 characters. Matches a label substring, a destination
   * host substring of a URL code (host only, not path or query) or a content
   * type key, case-insensitively, or a token prefix (case-sensitive).
   */
  q?: string;
  /** Content type key, e.g. `'vcard'`; exact match, ignoring case. */
  contentType?: string;
  /** Codes carrying at least one of these tags (up to 20). */
  tagIds?: string[];
  /** A folder id, or `'unfiled'` for codes without a folder. */
  folderId?: string;
  /** `true`: only codes marked outside the organization's allowlist; `false`: only codes not marked. */
  outsidePolicy?: boolean;
}

export interface QRCodeDetail {
  token: string;
  destinationUrl: string;
  label: string | null;
  status: string;
  signature: string;
  contentType: string;
  /** Content of non-URL codes; `AppLinkContent` and `LinkListContent` for `'app-link'` and `'link-list'`. */
  content: Record<string, unknown> | AppLinkContent | LinkListContent | null;
  latitude: number | null;
  longitude: number | null;
  radiusM: number;
  expiresAt: string | null;
  createdAt: string;
  updatedAt: string;
  _count: { scans: number };
  algVersion?: AlgVersion;
  merkleBatchId?: string;
  /** Scan mode setting. Absent from API versions before scan modes. */
  scanMode?: ScanMode;
  /**
   * The URL the code encodes, as in the create response. Returned by
   * `get()`; absent from older API versions and from `list()` items.
   */
  verification_url?: string;
  /** Lowercased host of `destinationUrl`. Absent from older API versions. */
  destinationHost?: string | null;
  /** The code's folder id, `null` when unfiled. Absent from older API versions. */
  folderId?: string | null;
  /** The code's tags, sorted by name. Absent from older API versions. */
  tags?: QRCodeTag[];
  /** The code's folder, `null` when unfiled. Absent from older API versions. */
  folder?: { id: string; name: string } | null;
  /**
   * The destination (or a link) is outside the organization's enforced
   * allowlist. The code keeps working; its destination can only be changed
   * to an allowed domain. Absent from older API versions.
   */
  outsidePolicy?: boolean;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
}

// ---------------------------------------------------------------------------
// QR Code — tags and folders
// ---------------------------------------------------------------------------

/** The fixed tag palette. Map each key to a colour of your own theme. */
export const TAG_COLORS = [
  'grey',
  'blue',
  'teal',
  'green',
  'yellow',
  'orange',
  'red',
  'pink',
  'purple',
] as const;

export type TagColor = (typeof TAG_COLORS)[number];

/** A tag as embedded in a code returned by `list()` or `get()`. */
export interface QRCodeTag {
  id: string;
  name: string;
  color: TagColor;
}

export interface Tag extends QRCodeTag {
  /** Codes carrying this tag, in any status. */
  codeCount: number;
  createdAt: string;
}

export interface CreateTagOptions {
  /** 1-32 characters after trimming; unique per organization, ignoring case. */
  name: string;
  /** Default `'grey'`. */
  color?: TagColor;
}

/** At least one of `name` and `color`. */
export interface UpdateTagOptions {
  name?: string;
  color?: TagColor;
}

export interface Folder {
  id: string;
  name: string;
  /** Codes in this folder, in any status. */
  codeCount: number;
  createdAt: string;
}

export interface ListFoldersResponse {
  data: Folder[];
  /** Codes without a folder. */
  unfiledCount: number;
}

export interface BulkTagOptions {
  /** Tag ids to add (up to 20). */
  add?: string[];
  /** Tag ids to remove (up to 20). */
  remove?: string[];
}

export interface BulkOrganizeResult {
  /** Tokens of your organization that were updated (duplicates removed). */
  updated: string[];
  /** Tokens that do not exist or belong to another organization. */
  notFound: string[];
}

// ---------------------------------------------------------------------------
// QR Code — edit history
// ---------------------------------------------------------------------------

/**
 * What a revision records:
 *   - `BASELINE`: where history begins for a code issued before edit history existed
 *   - `CREATED`: the code was created
 *   - `UPDATED`: a tracked field was changed
 *   - `RESTORED`: an earlier destination was restored (see `restoredFrom`)
 *   - `REVOKED`: the code was revoked
 */
export type RevisionKind = 'BASELINE' | 'CREATED' | 'UPDATED' | 'RESTORED' | 'REVOKED';

/** The fields edit history tracks. Label, location and scan limits are not tracked. */
export type TrackedField = 'destinationUrl' | 'content' | 'style' | 'expiresAt' | 'scanMode' | 'status';

/** A tracked field's value before and after a revision. `before` is `null` on `CREATED` and `BASELINE`. */
export interface FieldChange<T> {
  before: T | null;
  after: T | null;
}

/** The tracked fields a revision changed. `CREATED` and `BASELINE` carry every field. */
export interface RevisionChanges {
  destinationUrl?: FieldChange<string>;
  content?: FieldChange<Record<string, unknown>>;
  style?: FieldChange<Record<string, unknown>>;
  /** ISO 8601, or `null` for no expiry. */
  expiresAt?: FieldChange<string>;
  scanMode?: FieldChange<ScanMode>;
  status?: FieldChange<'ACTIVE' | 'EXPIRED' | 'REVOKED'>;
}

/**
 * Who made a revision. A user or API key that no longer exists keeps its
 * `id`, with `name`/`email` or `label`/`prefix` set to `null`. `SYSTEM`
 * revisions were made by QRAuth itself; `id` names the process.
 */
export type RevisionActor =
  | { type: 'USER'; id: string; name: string | null; email: string | null }
  | { type: 'API_KEY'; id: string; label: string | null; prefix: string | null }
  | { type: 'SYSTEM'; id: string };

/** One entry in a code's edit history. */
export interface QRCodeRevision {
  /** 1, 2, 3 … per code. */
  revision: number;
  kind: RevisionKind;
  /** ISO 8601. */
  createdAt: string;
  changes: RevisionChanges;
  actor: RevisionActor;
  /** The `X-Request-Id` of the request that made the change; `null` when no API request made it (e.g. `BASELINE`). */
  requestId: string | null;
  /** For `RESTORED`: the revision whose destination was restored. */
  restoredFrom: number | null;
}

export interface GetHistoryOptions {
  /** Default 1. */
  page?: number;
  /** Default 20, max 100. */
  pageSize?: number;
}

/** A page of edit history, newest first. */
export type QRCodeHistory = PaginatedResponse<QRCodeRevision>;

/** A QR code after a change, as `restoreDestination()` returns it. */
export interface UpdatedQRCode extends Omit<QRCodeDetail, '_count' | 'verification_url'> {
  /** Present when the new destination resembles a domain verified by another organization. */
  domain_warnings?: DomainWarning[];
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

/**
 * Verify-page trust state.
 *   - `VERIFIED`: every check passed and QRAuth has verified the issuer
 *     (verified domain or approved identity review).
 *   - `SIGNED_UNVERIFIED_ISSUER`: every check passed, but the issuer is not
 *     verified by QRAuth. The code is authentic; who issued it is not
 *     confirmed.
 *   - `UNTRUSTED`: anything else (invalid signature, revoked, expired,
 *     geo-blocked, low trust score, lookalike or flagged destination, issuer
 *     suspended).
 */
export type TrustState = 'VERIFIED' | 'SIGNED_UNVERIFIED_ISSUER' | 'UNTRUSTED';

/**
 * Browser scan behaviour. `FLASH`: a short trust reveal, then the browser
 * continues to the destination. `PAGE`: the full verification page.
 */
export type ScanMode = 'FLASH' | 'PAGE';

/** Issuer identity, named only when `trust_state` is `VERIFIED`. */
export type VerificationOrganization =
  | {
      verified: true;
      name: string;
      /** Host of the issuer's verified domain, when it has one. */
      verified_domain?: string;
    }
  | { verified: false };

export interface VerificationResult {
  /**
   * `true` only when `trust_state === 'VERIFIED'`. A valid signature from an
   * issuer QRAuth has not verified gives `false` with `trust_state`
   * `SIGNED_UNVERIFIED_ISSUER`. Read `trust_state` to tell the cases apart.
   */
  verified: boolean;
  trust_state: TrustState;
  /** Why the code is not trusted, when there is a single reason. */
  reason?: string;
  organization: VerificationOrganization;
  /** Absent on failure responses (revoked, expired, scan limit, suspended, …). */
  destination_url?: string;
  /**
   * What a browser does on this scan. `FLASH` only when the result is
   * `VERIFIED`, the code is a URL code with an https destination and no
   * location binding, and its issuer left quick redirect on; otherwise
   * `PAGE`. Failure responses are always `PAGE`. Absent from API versions
   * before scan modes.
   */
  scan_mode?: ScanMode;
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
    algVersion?: AlgVersion | null;
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
    merkleBatchId?: string | null;
  };
  /** Present when the destination looks like a verified organization's domain. */
  domain_warning?: {
    message: string;
    /**
     * The protected domain the destination resembles (a verified
     * organization's domain or one of QRAuth's protected brands); for
     * `reason: 'mixed_script'`, the destination host itself (punycode).
     */
    similar_to: string;
    /** Name of the verified organization or protected brand; empty for `mixed_script`. */
    verified_org: string;
    /** Similarity score, 0–100. */
    similarity: number;
    /**
     * Why: `'confusable'` (Unicode confusable, UTS #39), `'mixed_script'`
     * (letters of different scripts in one name), or an edit-distance
     * reason such as `'typosquatting'`. Absent from older API versions.
     */
    reason?: string;
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

/**
 * One item of `bulk()`. Bulk create makes URL codes only: an item has a
 * destination URL and no content type. To create a vCard, coupon, event, PDF
 * or feedback code, call `create()` once per code. The API answers 400 for a
 * bulk request whose items carry `contentType` or `content`.
 */
export interface BulkCreateItem {
  destination: string;
  label?: string;
  /** See `CreateQRCodeOptions.scanMode`. */
  scanMode?: ScanMode;
  location?: {
    lat: number;
    lng: number;
    radiusM?: number;
  };
  expiresIn?: string;
}

export interface BulkCreateResponse {
  results: Array<
    | { index: number; success: true; data: QRCodeResponse; label?: string }
    | {
        index: number;
        success: false;
        error: string;
        /** e.g. QUOTA_EXCEEDED, RATE_LIMIT, VALIDATION_ERROR, DESTINATION_FLAGGED, DESTINATION_NOT_ALLOWED, INTERNAL_ERROR */
        errorCode: string;
        /** Web Risk threat types, when `errorCode` is DESTINATION_FLAGGED. */
        threatTypes?: string[];
        label?: string;
      }
  >;
  summary: {
    total: number;
    succeeded: number;
    failed: number;
  };
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
  qrImageDataUrl: string;
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

/**
 * A session as returned by list and get. The claim `token` and `claimUrl` are
 * bearer secrets and are returned only once, by `createEphemeralSession`.
 */
export interface EphemeralSessionDetail {
  id: string;
  status: string;
  scopes: string[];
  ttlSeconds: number;
  maxUses: number;
  useCount: number;
  deviceBinding: boolean;
  metadata: Record<string, unknown> | null;
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

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

/** Who performed an audited action. */
export type AuditActorType = 'USER' | 'API_KEY' | 'SYSTEM' | 'SUPERADMIN';

/**
 * Who performed an audited action. A user or API key that no longer exists
 * keeps its `id`, with `name`/`email` or `label`/`prefix` set to `null`.
 * `SYSTEM` is QRAuth itself; `id` names the process. `SUPERADMIN` is QRAuth
 * staff, shown as `QRAuth` without naming the person.
 */
export type AuditActorView =
  | { type: 'USER'; id: string; name: string | null; email: string | null }
  | { type: 'API_KEY'; id: string; label: string | null; prefix: string | null }
  | { type: 'SYSTEM'; id: string }
  | { type: 'SUPERADMIN'; id: null; name: 'QRAuth' };

/** One entry of the organization audit log. */
export interface AuditEntry {
  /** `log:<id>` for audit-table entries, `qr:<id>` for QR code edit history. */
  id: string;
  source: 'audit' | 'qr_revision';
  /** e.g. `apiKey.create`, `member.role.update`, `qr.updated`. */
  action: string;
  /** Readable description of `action`, e.g. `API key created`. */
  label: string;
  resourceType: string;
  resourceId: string;
  /** QR code events: the code's token, when the code still exists. */
  resourceName: string | null;
  actor: AuditActorView;
  /** ISO 8601. */
  createdAt: string;
  /** The `X-Request-Id` of the request that made the change, when there was one. */
  requestId: string | null;
  /** The client's IP address and user agent; `null` for QR code events, QRAuth staff actions and where none was recorded. */
  ipAddress: string | null;
  userAgent: string | null;
  /** Details of the action. QR code events: `{ revision, restoredFrom? }`. */
  metadata: Record<string, unknown> | null;
  /** QR code events: the changed fields as `{ field: { before, after } }`. `null` otherwise. */
  changes: Record<string, { before: unknown; after: unknown }> | null;
}

/** A page of the audit log, newest first. */
export interface AuditPage {
  data: AuditEntry[];
  /** Opaque; pass as `cursor` for the next (older) page. `null` on the last page. */
  nextCursor: string | null;
}

/** Filters for `exportAuditCsv()`; `listAuditEntries()` adds `cursor` and `limit`. */
export interface AuditFilterParams {
  /** A user id, API key id or system process id. */
  actor?: string;
  actorType?: AuditActorType;
  /** An exact action, e.g. `apiKey.revoke`. */
  action?: string;
  resourceType?: string;
  resourceId?: string;
  /** Oldest entry to include: a `Date` or an ISO 8601 string with offset. */
  from?: Date | string;
  /** Newest entry to include: a `Date` or an ISO 8601 string with offset. */
  to?: Date | string;
}

// ---------------------------------------------------------------------------
// Organization policies
// ---------------------------------------------------------------------------

export type AllowlistMode = 'OFF' | 'ENFORCE';

/** The lowest role that may change a code's destination or content. */
export type DestinationEditRole = 'MEMBER' | 'MANAGER' | 'ADMIN';

/** An allowlist entry: a registrable domain in ASCII (punycode) form. */
export interface AllowlistEntry {
  domain: string;
  /** Subdomains of `domain` are allowed too. */
  includeSubdomains: boolean;
  /** `domain` in Unicode, for display. */
  unicode: string;
}

/** The organization's policy, from `getPolicy()` and `updatePolicy()`. */
export interface OrgPolicy {
  allowlistMode: AllowlistMode;
  allowlist: AllowlistEntry[];
  destinationEditMinRole: DestinationEditRole;
  /** ISO 8601; `null` while the organization has never changed its policy. */
  updatedAt: string | null;
  /** `false` below the Business plan: the policy can only be switched off. */
  editable: boolean;
  /** Codes (not revoked) currently marked outside the allowlist. */
  outsidePolicyCount: number;
  /** Active legacy API keys: created before keys recorded an owner. */
  apiKeysWithoutCreator: number;
}

/** A domain to allow: a host, URL or internationalised name, reduced by the API to its registrable domain. */
export interface AllowlistEntryInput {
  domain: string;
  /** Default `true`. */
  includeSubdomains?: boolean;
}

/** `updatePolicy()`: the whole policy (it replaces the current one). */
export interface UpdatePolicyOptions {
  allowlistMode: AllowlistMode;
  /** At most 200 entries. Omit to keep the stored list as it is (e.g. to switch the policy off). */
  allowlist?: AllowlistEntryInput[];
  destinationEditMinRole: DestinationEditRole;
}

/** How one submitted entry was normalised, in the order submitted. */
export type AllowlistNormalisation =
  | { input: string; ok: true; entry: AllowlistEntry; note: string | null }
  | { input: string; ok: false; message: string };

/** An active code whose destination or links fall outside a proposed allowlist. */
export interface PolicyAffectedCode {
  token: string;
  label: string | null;
  contentType: string;
  /** The destination or links that are not allowed. */
  outside: string[];
}

/** `previewPolicy()`: what a proposed allowlist would store and which active codes it would leave outside. */
export interface PolicyPreview {
  entries: AllowlistNormalisation[];
  allowlist: AllowlistEntry[];
  /** The first 100 affected codes. */
  affected: PolicyAffectedCode[];
  affectedTotal: number;
}

/** CSV export filters: the date range is required; one export holds at most 100,000 entries. */
export interface AuditExportParams extends AuditFilterParams {
  from: Date | string;
  to: Date | string;
}

export interface AuditListParams extends AuditFilterParams {
  /** `nextCursor` from the previous page. */
  cursor?: string;
  /** 1–100, default 50. */
  limit?: number;
}

// ---------------------------------------------------------------------------
// Bulk import and export (Business plan and above)
// ---------------------------------------------------------------------------

export type BulkRowStatus = 'ok' | 'warning' | 'error';

/** One data row of a dry run. */
export interface BulkDryRunRow {
  /** Row number in the file: the header is row 1. */
  row: number;
  status: BulkRowStatus;
  /** Machine-readable reason of the first error or warning, e.g. `'url-invalid'`, `'destination-flagged'`, `'lookalike'`. */
  code: string | null;
  /** Reasons, errors first. */
  messages: string[];
  /** The destination, normalised as single create stores it. */
  url: string;
  label: string | null;
  folder: string | null;
  tags: string[];
  /** ISO 8601 UTC datetime. */
  expiresAt: string | null;
  /** The date as written when the cell was a date only (`YYYY-MM-DD`); `expiresAt` is 23:59:59 of it in the dry run's `timezone`. */
  expiresDate: string | null;
  scanMode: ScanMode | null;
}

export interface BulkDryRunTotals {
  rows: number;
  ok: number;
  warning: number;
  error: number;
  /** Folder and tag names the import would create. */
  newFolders: string[];
  newTags: string[];
}

/** `bulkImportDryRun()`: every row checked, nothing created. Commit it within an hour. */
export interface BulkDryRun {
  id: string;
  expiresAt: string;
  delimiter: ',' | ';';
  columns: Array<'url' | 'label' | 'folder' | 'tags' | 'expiresAt' | 'scanMode'>;
  /** IANA time zone of date-only expiry dates. */
  timezone: string;
  totals: BulkDryRunTotals;
  rows: BulkDryRunRow[];
}

export type BulkJobKind = 'IMPORT' | 'EXPORT';
export type BulkJobStatus = 'QUEUED' | 'RUNNING' | 'SUCCEEDED' | 'FAILED';

/** An import or export job. Deleted, with its results or ZIP, 24 hours after it ends. */
export interface BulkJob {
  id: string;
  kind: BulkJobKind;
  status: BulkJobStatus;
  /** Rows (import) or codes (export). */
  total: number;
  processed: number;
  succeeded: number;
  failed: number;
  skipped: number;
  /** Why a FAILED job stopped. */
  error: string | null;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  expiresAt: string | null;
  /** Export: the ZIP's size in bytes once it is ready. */
  fileBytes: number | null;
}

/** Which codes a ZIP export contains (at most 1,000). */
export type BulkExportSelection =
  | { tokens: string[] }
  | { importJobId: string }
  | {
      filter: {
        q?: string;
        contentType?: string;
        tagIds?: string[];
        /** A folder id, or `'unfiled'`. */
        folderId?: string;
        outsidePolicy?: boolean;
        status?: 'ACTIVE' | 'EXPIRED' | 'REVOKED';
      };
    };

export interface BulkExportOptions {
  selection: BulkExportSelection;
  formats: Array<'svg' | 'png'>;
  /** Required with `'png'`: a screen width (64–1024 px) or a print size (at most 4,000 px wide). */
  png?: { px: number } | { sizeMm: number; dpi?: number };
}

/** A download link for the export's starter, valid 5 minutes; no API key is needed to fetch it. */
export interface BulkExportLink {
  url: string;
  expiresAt: string;
}
