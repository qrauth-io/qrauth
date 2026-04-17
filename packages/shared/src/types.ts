import type {
  DeviceTrustLevel,
  EphemeralSessionStatus,
  FraudSeverity,
  FraudType,
  KeyStatus,
  KycStatus,
  MembershipRole,
  OrganizationTrustLevel,
  QRCodeStatus,
} from "./constants.js";

// ---------------------------------------------------------------------------
// Core domain entities
// ---------------------------------------------------------------------------

export interface Organization {
  id: string;
  name: string;
  /** URL-safe unique identifier derived from the organization name. */
  slug: string;
  email: string;
  /** Optional canonical domain used for DID / well-known verification. */
  domain?: string;
  trustLevel: OrganizationTrustLevel;
  kycStatus: KycStatus;
  plan: string;
  billingEmail?: string;
  createdAt: Date;
  updatedAt: Date;
}

/** @deprecated Use Organization instead. */
export type Issuer = Organization;

export interface User {
  id: string;
  name: string;
  email: string;
  emailVerified: boolean;
  provider: string;
  providerId?: string;
  avatarUrl?: string;
  lastLoginAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface LoginEvent {
  id: string;
  userId: string;
  success: boolean;
  provider: string;
  ipAddress?: string;
  ipCountry?: string;
  ipCity?: string;
  userAgent?: string;
  deviceType?: string;
  browser?: string;
  os?: string;
  fingerprint?: string;
  metadata?: Record<string, unknown>;
  createdAt: string;
}

export interface Membership {
  id: string;
  userId: string;
  organizationId: string;
  role: MembershipRole;
  invitedBy?: string;
  joinedAt: Date;
  createdAt: Date;
}

export interface Invitation {
  id: string;
  organizationId: string;
  email: string;
  role: MembershipRole;
  token: string;
  invitedBy: string;
  expiresAt: Date;
  acceptedAt?: Date;
  createdAt: Date;
}

export interface AuditLogEntry {
  id: string;
  organizationId: string;
  userId: string;
  action: string;
  resource: string;
  resourceId: string;
  metadata?: Record<string, unknown>;
  ipAddress?: string;
  createdAt: Date;
}

export interface AuthPayload {
  userId: string;
  orgId: string;
  role: MembershipRole;
  email: string;
}

export interface SigningKey {
  id: string;
  organizationId: string;
  /** PEM-encoded or JWK-serialised public key. */
  publicKey: string;
  /** Short identifier embedded in QR signatures so verifiers can look up the right key. */
  keyId: string;
  algorithm: string;
  status: KeyStatus;
  createdAt: Date;
  /** Set when a new key supersedes this one. */
  rotatedAt?: Date;
  /** Set when the key is permanently invalidated before natural rotation. */
  revokedAt?: Date;
}

export interface QRCode {
  id: string;
  /** Short, human-readable token encoded into the physical QR image. */
  token: string;
  organizationId: string;
  signingKeyId: string;
  destinationUrl: string;
  label?: string;
  /** ECDSA signature over the canonical payload (token:url:geoHash:expiry). */
  signature: string;
  /** Geohash string encoding the registered latitude/longitude. */
  geoHash?: string;
  latitude?: number;
  longitude?: number;
  /** Geo-fence radius in metres. */
  radiusM: number;
  status: QRCodeStatus;
  expiresAt?: Date;
  revokedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface Scan {
  id: string;
  qrCodeId: string;
  /** SHA-256 hash of the client IP address – never store the raw IP. */
  clientIpHash: string;
  clientLat?: number;
  clientLng?: number;
  userAgent?: string;
  /** Composite trust score from 0 (completely untrusted) to 100 (fully trusted). */
  trustScore: number;
  proxyDetected: boolean;
  passkeyVerified: boolean;
  createdAt: Date;
}

export interface FraudIncident {
  id: string;
  qrCodeId: string;
  /** The specific scan that triggered this incident, if applicable. */
  scanId?: string;
  type: FraudType;
  severity: FraudSeverity;
  /** Arbitrary structured evidence collected at detection time. */
  details: Record<string, unknown>;
  resolved: boolean;
  resolvedAt?: Date;
  createdAt: Date;
}

export interface TransparencyLogEntry {
  id: string;
  /** Monotonically increasing position in the append-only log. */
  logIndex: number;
  qrCodeId: string;
  organizationId: string;
  /** SHA-256 hash of the raw token string. */
  tokenHash: string;
  /** SHA-256 hash of the destination URL. */
  destinationHash: string;
  geoHash?: string;
  /** Hash of the immediately preceding log entry, forming a chain. */
  previousHash?: string;
  /** Hash of this entry's own content (including previousHash). */
  entryHash: string;
  createdAt: Date;
}

export interface ApiKeyRecord {
  id: string;
  organizationId: string;
  /** Bcrypt / Argon2 hash of the raw API key – never stored in plaintext. */
  keyHash: string;
  /** First 8 characters of the raw key shown in the dashboard for identification. */
  prefix: string;
  label?: string;
  lastUsedAt?: Date;
  revokedAt?: Date;
  createdAt: Date;
}

// ---------------------------------------------------------------------------
// API response shapes
// ---------------------------------------------------------------------------

export interface VerificationResult {
  verified: boolean;
  organization: {
    id: string;
    name: string;
    slug: string;
    trustLevel: OrganizationTrustLevel;
    kycStatus: KycStatus;
  };
  destination_url: string;
  location_match: {
    /** Whether the client's reported position falls within the registered geo-fence. */
    matched: boolean;
    /** Straight-line distance in metres between the client position and registered centre. */
    distanceM: number | null;
    /** Human-readable description of the registered location, derived from the geohash. */
    registeredAddress: string | null;
  };
  security: {
    signatureValid: boolean;
    proxyDetected: boolean;
    /** Composite trust score 0–100 computed at scan time. */
    trustScore: number;
    transparencyLogVerified: boolean;
  };
  scannedAt: string;
}

// ---------------------------------------------------------------------------
// Shared input shapes
// ---------------------------------------------------------------------------

export interface LocationInput {
  lat: number;
  lng: number;
  /** Geo-fence radius in metres. */
  radiusM: number;
}

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
}

// ---------------------------------------------------------------------------
// Auth platform entities
// ---------------------------------------------------------------------------

export interface App {
  id: string;
  organizationId: string;
  name: string;
  slug: string;
  clientId: string;
  redirectUrls: string[];
  webhookUrl?: string;
  allowedScopes: string[];
  logoUrl?: string;
  description?: string;
  status: string;
  createdAt: string;
  updatedAt: string;
}

export interface AuthSession {
  id: string;
  appId: string;
  token: string;
  status: string;
  scopes: string[];
  userId?: string;
  geoLat?: number;
  geoLng?: number;
  signature?: string;
  redirectUrl?: string;
  metadata?: Record<string, unknown>;
  expiresAt: string;
  scannedAt?: string;
  resolvedAt?: string;
  createdAt: string;
}

export interface AuthSessionResult {
  sessionId: string;
  status: string;
  user?: {
    id: string;
    name: string;
    email: string;
  };
  signature?: string;
  resolvedAt?: string;
}

// ---------------------------------------------------------------------------
// Ephemeral sessions
// ---------------------------------------------------------------------------

export interface EphemeralSession {
  id: string;
  appId: string;
  token: string;
  status: EphemeralSessionStatus;
  scopes: string[];
  ttlSeconds: number;
  maxUses: number;
  useCount: number;
  deviceBinding: boolean;
  boundDeviceHash: string | null;
  metadata: Record<string, unknown> | null;
  claimUrl: string | null;
  claimedAt: string | null;
  expiresAt: string;
  revokedAt: string | null;
  createdAt: string;
}

export interface EphemeralSessionCreateResult {
  sessionId: string;
  token: string;
  claimUrl: string;
  expiresAt: string;
  scopes: string[];
  ttlSeconds: number;
  maxUses: number;
}

export interface EphemeralSessionClaimResult {
  sessionId: string;
  status: string;
  scopes: string[];
  metadata: Record<string, unknown> | null;
  expiresAt: string;
}

// ---------------------------------------------------------------------------
// Device policy
// ---------------------------------------------------------------------------

export interface DevicePolicy {
  id: string;
  organizationId: string;
  maxDevices: number;
  requireBiometric: boolean;
  geoFenceLat: number | null;
  geoFenceLng: number | null;
  geoFenceRadiusKm: number | null;
  autoRevokeAfterDays: number | null;
  createdAt: string;
  updatedAt: string;
}

// ---------------------------------------------------------------------------
// Device registry
// ---------------------------------------------------------------------------

export interface TrustedDevice {
  id: string;
  userId: string;
  fingerprint: string;
  name: string | null;
  trustLevel: DeviceTrustLevel;
  deviceType: string | null;
  browser: string | null;
  os: string | null;
  ipCountry: string | null;
  ipCity: string | null;
  lastSeenAt: string;
  trustedAt: string | null;
  revokedAt: string | null;
  createdAt: string;
  passkeyCount?: number;
}

// ---------------------------------------------------------------------------
// Proximity Attestation
// ---------------------------------------------------------------------------

export interface ProximityAttestationClaims {
  /** Subject: SHA-256 hash of the QR token */
  sub: string;
  /** Issuer: organization ID */
  iss: string;
  /** Location: geohash of QR code's registered position */
  loc: string;
  /** Proximity result */
  proximity: {
    matched: boolean;
    distanceM: number;
    radiusM: number;
  };
  /** Issued-at (Unix epoch seconds) */
  iat: number;
  /** Expiry (Unix epoch seconds) */
  exp: number;
}

export interface ProximityAttestation {
  /** Compact JWT (header.payload.signature) */
  jwt: string;
  /** Decoded claims */
  claims: ProximityAttestationClaims;
  /** PEM-encoded public key for offline verification */
  publicKey: string;
  /** Signing key identifier */
  keyId: string;
}

export interface ProximityVerifyResult {
  valid: boolean;
  claims?: ProximityAttestationClaims;
  error?: string;
}

// ---------------------------------------------------------------------------
// WebAuthn / Passkeys
// ---------------------------------------------------------------------------

export interface Passkey {
  id: string;
  userId: string;
  deviceId: string | null;
  credentialId: string;
  transports: string[];
  aaguid: string | null;
  name: string | null;
  lastUsedAt: string | null;
  revokedAt: string | null;
  createdAt: string;
}
