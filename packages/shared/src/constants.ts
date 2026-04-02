// ---------------------------------------------------------------------------
// Cryptography
// ---------------------------------------------------------------------------

export const ECDSA_ALGORITHM = "ES256" as const;
export const ECDSA_CURVE = "P-256" as const;

// ---------------------------------------------------------------------------
// Token generation
// ---------------------------------------------------------------------------

/** Number of characters in a generated QR token. */
export const TOKEN_LENGTH = 8 as const;

/**
 * Character set deliberately excludes visually ambiguous glyphs:
 *   0 / O  (zero vs letter-O)
 *   1 / l  (one vs lowercase-L)
 *   I       (uppercase-I)
 */
export const TOKEN_CHARSET =
  "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789" as const;

// ---------------------------------------------------------------------------
// Geolocation
// ---------------------------------------------------------------------------

/** Maximum allowed geo-fence radius in metres. */
export const MAX_GEO_RADIUS_M = 1000 as const;

/** Default geo-fence radius in metres when the issuer omits the value. */
export const DEFAULT_GEO_RADIUS_M = 50 as const;

// ---------------------------------------------------------------------------
// Trust & fraud
// ---------------------------------------------------------------------------

/**
 * Minimum trust score (0–100) required to treat a scan as legitimate.
 * Scans below this threshold are flagged for review.
 */
export const TRUST_SCORE_THRESHOLD = 50 as const;

// ---------------------------------------------------------------------------
// API routing
// ---------------------------------------------------------------------------

export const API_VERSION = "v1" as const;
export const API_PREFIX = "/api/v1" as const;

// ---------------------------------------------------------------------------
// Cache TTLs (seconds)
// ---------------------------------------------------------------------------

export const CACHE_TTL = {
  /** Public key of an issuer – long-lived, rotates rarely. */
  ISSUER_PUBLIC_KEY: 3600,
  /** QR code metadata – medium-lived, may be revoked. */
  QR_CODE: 60,
  /** Result of a verification call – short-lived, geo changes frequently. */
  VERIFY_RESULT: 30,
} as const;

// ---------------------------------------------------------------------------
// Domain enumerations
// ---------------------------------------------------------------------------

/**
 * Organization trust levels, ordered from lowest to highest trust.
 * The value is stored in the database and returned in API responses.
 */
export const OrganizationTrustLevel = {
  INDIVIDUAL: 'INDIVIDUAL',
  BUSINESS: 'BUSINESS',
  GOVERNMENT: 'GOVERNMENT',
} as const;
export type OrganizationTrustLevel = (typeof OrganizationTrustLevel)[keyof typeof OrganizationTrustLevel];

// Keep IssuerTrustLevel as alias for backward compat
export const IssuerTrustLevel = OrganizationTrustLevel;
export type IssuerTrustLevel = OrganizationTrustLevel;

export const MembershipRole = {
  OWNER: 'OWNER',
  ADMIN: 'ADMIN',
  MANAGER: 'MANAGER',
  MEMBER: 'MEMBER',
  VIEWER: 'VIEWER',
} as const;
export type MembershipRole = (typeof MembershipRole)[keyof typeof MembershipRole];

export const ROLE_HIERARCHY: MembershipRole[] = ['OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER'];

export const Plan = {
  FREE: 'FREE',
  PRO: 'PRO',
  ENTERPRISE: 'ENTERPRISE',
} as const;
export type Plan = (typeof Plan)[keyof typeof Plan];

export const PASSWORD_MIN_LENGTH = 8;
export const INVITATION_EXPIRY_HOURS = 72;
export const JWT_EXPIRY = '7d';

/** KYC verification lifecycle for an issuer account. */
export const KycStatus = {
  PENDING: "pending",
  SUBMITTED: "submitted",
  APPROVED: "approved",
  REJECTED: "rejected",
} as const;

export type KycStatus = (typeof KycStatus)[keyof typeof KycStatus];

/** Lifecycle state of a QR code. */
export const QRCodeStatus = {
  ACTIVE: "active",
  REVOKED: "revoked",
  EXPIRED: "expired",
} as const;

export type QRCodeStatus = (typeof QRCodeStatus)[keyof typeof QRCodeStatus];

/** Lifecycle state of a signing key pair. */
export const KeyStatus = {
  ACTIVE: "active",
  ROTATED: "rotated",
  REVOKED: "revoked",
} as const;

export type KeyStatus = (typeof KeyStatus)[keyof typeof KeyStatus];

/** Categories of detected fraud or anomalous behaviour. */
export const FraudType = {
  /** Replay of a token that has already been scanned. */
  REPLAY_ATTACK: "replay_attack",
  /** Scan origin is a known VPN, TOR exit node, or datacenter proxy. */
  PROXY_DETECTED: "proxy_detected",
  /** Client claims a location that does not match the registered geo-fence. */
  LOCATION_MISMATCH: "location_mismatch",
  /** Abnormally high scan velocity for a single token. */
  VELOCITY_ABUSE: "velocity_abuse",
  /** Cryptographic signature on the QR payload is invalid. */
  INVALID_SIGNATURE: "invalid_signature",
  /** Catch-all for anomalies that do not fit another category. */
  ANOMALOUS_PATTERN: "anomalous_pattern",
} as const;

export type FraudType = (typeof FraudType)[keyof typeof FraudType];

/** Operational severity of a fraud incident. */
export const FraudSeverity = {
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
} as const;

export type FraudSeverity = (typeof FraudSeverity)[keyof typeof FraudSeverity];

// ---------------------------------------------------------------------------
// Auth platform enumerations
// ---------------------------------------------------------------------------

export const AppStatus = {
  ACTIVE: 'ACTIVE',
  SUSPENDED: 'SUSPENDED',
  DELETED: 'DELETED',
} as const;
export type AppStatus = (typeof AppStatus)[keyof typeof AppStatus];

export const AuthSessionStatus = {
  PENDING: 'PENDING',
  SCANNED: 'SCANNED',
  APPROVED: 'APPROVED',
  DENIED: 'DENIED',
  EXPIRED: 'EXPIRED',
} as const;
export type AuthSessionStatus = (typeof AuthSessionStatus)[keyof typeof AuthSessionStatus];

export const AUTH_SESSION_EXPIRY_SECONDS = 300; // 5 minutes
export const ALLOWED_SCOPES = ['identity', 'email', 'organization'] as const;
export type AuthScope = (typeof ALLOWED_SCOPES)[number];

export const AuthProvider = {
  EMAIL: 'EMAIL',
  GOOGLE: 'GOOGLE',
  GITHUB: 'GITHUB',
  MICROSOFT: 'MICROSOFT',
  APPLE: 'APPLE',
} as const;
export type AuthProvider = (typeof AuthProvider)[keyof typeof AuthProvider];

export const MAX_FAILED_LOGIN_ATTEMPTS = 5;
export const ACCOUNT_LOCKOUT_MINUTES = 15;
