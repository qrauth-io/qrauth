import { z } from "zod";
import {
  DEFAULT_GEO_RADIUS_M,
  EPHEMERAL_SESSION_MAX_TTL,
  EPHEMERAL_SESSION_MAX_USES,
  IssuerTrustLevel,
  MAX_GEO_RADIUS_M,
  PASSWORD_MIN_LENGTH,
} from "./constants.js";

// ---------------------------------------------------------------------------
// Organization schemas
// ---------------------------------------------------------------------------

export const createOrganizationSchema = z.object({
  name: z
    .string()
    .min(2, "Name must be at least 2 characters")
    .max(100, "Name must not exceed 100 characters"),
  email: z.string().email("Must be a valid email address"),
  domain: z.string().url("Must be a valid URL").optional(),
  trustLevel: z
    .enum(
      Object.values(IssuerTrustLevel) as [
        (typeof IssuerTrustLevel)[keyof typeof IssuerTrustLevel],
        ...(typeof IssuerTrustLevel)[keyof typeof IssuerTrustLevel][],
      ]
    )
    .optional(),
  plan: z.string().optional(),
  billingEmail: z.string().email("Must be a valid email address").optional(),
});

export type CreateOrganizationInput = z.infer<typeof createOrganizationSchema>;

/** @deprecated Use createOrganizationSchema instead. */
export const createIssuerSchema = createOrganizationSchema;
export type CreateIssuerInput = CreateOrganizationInput;

export const updateOrganizationSchema = createOrganizationSchema.partial();

export type UpdateOrganizationInput = z.infer<typeof updateOrganizationSchema>;

/** @deprecated Use updateOrganizationSchema instead. */
export const updateIssuerSchema = updateOrganizationSchema;
export type UpdateIssuerInput = UpdateOrganizationInput;

// ---------------------------------------------------------------------------
// Auth schemas
// ---------------------------------------------------------------------------

export const signupSchema = z.object({
  name: z.string().min(2).max(100),
  email: z.string().email(),
  password: z.string().min(PASSWORD_MIN_LENGTH).max(128),
  organizationName: z.string().min(2).max(100),
});
export type SignupInput = z.infer<typeof signupSchema>;

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});
export type LoginInput = z.infer<typeof loginSchema>;

export const switchOrgSchema = z.object({
  organizationId: z.string().min(1),
});
export type SwitchOrgInput = z.infer<typeof switchOrgSchema>;

export const forgotPasswordSchema = z.object({
  email: z.string().email(),
});
export type ForgotPasswordInput = z.infer<typeof forgotPasswordSchema>;

export const resendVerificationSchema = z.object({
  email: z.string().email(),
});
export type ResendVerificationInput = z.infer<typeof resendVerificationSchema>;

export const resetPasswordSchema = z.object({
  token: z.string().min(1),
  password: z.string().min(PASSWORD_MIN_LENGTH).max(128),
});
export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>;

export const inviteUserSchema = z.object({
  email: z.string().email(),
  role: z.enum(['ADMIN', 'MANAGER', 'MEMBER', 'VIEWER']),
});
export type InviteUserInput = z.infer<typeof inviteUserSchema>;

export const updateMemberRoleSchema = z.object({
  role: z.enum(['ADMIN', 'MANAGER', 'MEMBER', 'VIEWER']),
});
export type UpdateMemberRoleInput = z.infer<typeof updateMemberRoleSchema>;

// ---------------------------------------------------------------------------
// Location / geo-fence schema
// ---------------------------------------------------------------------------

export const locationSchema = z.object({
  lat: z
    .number()
    .min(-90, "Latitude must be >= -90")
    .max(90, "Latitude must be <= 90"),
  lng: z
    .number()
    .min(-180, "Longitude must be >= -180")
    .max(180, "Longitude must be <= 180"),
  radiusM: z
    .number()
    .int("Radius must be a whole number of metres")
    .min(1, "Radius must be at least 1 metre")
    .max(
      MAX_GEO_RADIUS_M,
      `Radius must not exceed ${MAX_GEO_RADIUS_M} metres`
    )
    .default(DEFAULT_GEO_RADIUS_M),
});

/** Validated location input parsed from a request body or query string. */
export type LocationInputParsed = z.infer<typeof locationSchema>;

// ---------------------------------------------------------------------------
// QR code schemas
// ---------------------------------------------------------------------------

export const createQRCodeSchema = z.object({
  destinationUrl: z
    .string()
    .url("Must be a valid URL")
    .max(2048, "URL must not exceed 2048 characters"),
  label: z.string().max(200, "Label must not exceed 200 characters").optional(),
  location: locationSchema.optional(),
  expiresAt: z
    .string()
    .datetime({ message: "Must be a valid ISO 8601 datetime string" })
    .optional(),
  maxScans: z.number().int().positive().optional(),
  maxScansPerDevice: z.number().int().positive().optional(),
});

export type CreateQRCodeInput = z.infer<typeof createQRCodeSchema>;

export const bulkCreateQRCodeSchema = z.object({
  items: z
    .array(createQRCodeSchema)
    .min(1, "At least one QR code is required")
    .max(64, "Cannot create more than 64 QR codes in a single request"),
});

export type BulkCreateQRCodeInput = z.infer<typeof bulkCreateQRCodeSchema>;

export const updateQRCodeSchema = z.object({
  destinationUrl: z.string().url("Must be a valid URL").optional(),
  label: z.string().max(200, "Label must not exceed 200 characters").optional(),
  content: z.any().optional(),
  expiresAt: z.string().datetime({ message: "Must be a valid ISO 8601 datetime string" }).optional(),
  maxScans: z.number().int().positive().optional(),
  maxScansPerDevice: z.number().int().positive().optional(),
});

export type UpdateQRCodeInput = z.infer<typeof updateQRCodeSchema>;

// ---------------------------------------------------------------------------
// Verification query schema
// ---------------------------------------------------------------------------

export const verifyQuerySchema = z.object({
  clientLat: z.coerce.number().optional(),
  clientLng: z.coerce.number().optional(),
});

export type VerifyQuery = z.infer<typeof verifyQuerySchema>;

// ---------------------------------------------------------------------------
// Pagination schema
// ---------------------------------------------------------------------------

export const paginationSchema = z.object({
  page: z.coerce
    .number()
    .int("Page must be an integer")
    .min(1, "Page must be at least 1")
    .default(1),
  pageSize: z.coerce
    .number()
    .int("Page size must be an integer")
    .min(1, "Page size must be at least 1")
    .max(100, "Page size must not exceed 100")
    .default(20),
});

export type PaginationQuery = z.infer<typeof paginationSchema>;

// ---------------------------------------------------------------------------
// Analytics query schema
// ---------------------------------------------------------------------------

export const analyticsQuerySchema = paginationSchema.extend({
  startDate: z
    .string()
    .datetime({ message: "startDate must be a valid ISO 8601 datetime string" })
    .optional(),
  endDate: z
    .string()
    .datetime({ message: "endDate must be a valid ISO 8601 datetime string" })
    .optional(),
});

export type AnalyticsQuery = z.infer<typeof analyticsQuerySchema>;

// ---------------------------------------------------------------------------
// Transparency log query schema
// ---------------------------------------------------------------------------

export const transparencyLogQuerySchema = paginationSchema.extend({
  startIndex: z.coerce
    .number()
    .int("startIndex must be an integer")
    .optional(),
  endIndex: z.coerce.number().int("endIndex must be an integer").optional(),
  organizationId: z.string().optional(),
});

export type TransparencyLogQuery = z.infer<typeof transparencyLogQuerySchema>;

// ---------------------------------------------------------------------------
// Auth platform schemas
// ---------------------------------------------------------------------------

export const createAppSchema = z.object({
  name: z.string().min(2).max(100),
  description: z.string().max(500).optional(),
  redirectUrls: z.array(z.string().url()).min(1).max(10),
  webhookUrl: z.string().url().optional(),
  allowedScopes: z.array(z.enum(['identity', 'email', 'organization'])).min(1).default(['identity']),
  logoUrl: z.string().url().optional(),
});
export type CreateAppInput = z.infer<typeof createAppSchema>;

export const updateAppSchema = createAppSchema.partial();
export type UpdateAppInput = z.infer<typeof updateAppSchema>;

export const oauthCallbackSchema = z.object({
  code: z.string().min(1),
  state: z.string().min(1),
});
export type OAuthCallbackInput = z.infer<typeof oauthCallbackSchema>;

export const createAuthSessionSchema = z.object({
  scopes: z.array(z.enum(['identity', 'email', 'organization'])).min(1).default(['identity']),
  redirectUrl: z.string().url().optional(),
  metadata: z.record(z.unknown()).optional(),
  codeChallenge: z.string().min(43).max(128).optional(), // PKCE S256 base64url-encoded hash
  codeChallengeMethod: z.enum(['S256']).optional(),
});
export type CreateAuthSessionInput = z.infer<typeof createAuthSessionSchema>;

export const onboardingCompleteSchema = z.object({
  organizationName: z.string().min(2).max(100),
  useCase: z.enum(['MUNICIPALITY', 'PARKING', 'FINANCE', 'RESTAURANT', 'DEVELOPER', 'OTHER']),
});
export type OnboardingCompleteInput = z.infer<typeof onboardingCompleteSchema>;

// ---------------------------------------------------------------------------
// Ephemeral session schemas
// ---------------------------------------------------------------------------

export const createEphemeralSessionSchema = z.object({
  scopes: z.array(z.string().min(1).max(100)).min(1).max(50),
  ttl: z.string().min(1).max(20).default('30m'),
  maxUses: z.number().int().min(1).max(EPHEMERAL_SESSION_MAX_USES).default(1),
  deviceBinding: z.boolean().default(false),
  metadata: z.record(z.unknown()).optional(),
});
export type CreateEphemeralSessionInput = z.infer<typeof createEphemeralSessionSchema>;

export const claimEphemeralSessionSchema = z.object({
  deviceFingerprint: z.string().min(1).max(256).optional(),
});
export type ClaimEphemeralSessionInput = z.infer<typeof claimEphemeralSessionSchema>;

export const listEphemeralSessionsSchema = z.object({
  status: z.enum(['PENDING', 'CLAIMED', 'EXPIRED', 'REVOKED']).optional(),
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
});
export type ListEphemeralSessionsInput = z.infer<typeof listEphemeralSessionsSchema>;

// ---------------------------------------------------------------------------
// Device policy schemas
// ---------------------------------------------------------------------------

export const updateDevicePolicySchema = z.object({
  maxDevices: z.number().int().min(1).max(100).optional(),
  requireBiometric: z.boolean().optional(),
  geoFenceLat: z.number().min(-90).max(90).optional().nullable(),
  geoFenceLng: z.number().min(-180).max(180).optional().nullable(),
  geoFenceRadiusKm: z.number().min(1).max(10000).optional().nullable(),
  autoRevokeAfterDays: z.number().int().min(1).max(365).optional().nullable(),
  // Post-quantum WebAuthn bridge enforcement (ALGORITHM.md §9). See
  // packages/api/src/services/device-policy.ts for the per-mode contract.
  bridgePolicy: z.enum(['required', 'optional', 'disabled']).optional(),
});
export type UpdateDevicePolicyInput = z.infer<typeof updateDevicePolicySchema>;

// ---------------------------------------------------------------------------
// Device registry schemas
// ---------------------------------------------------------------------------

export const updateDeviceSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  trustLevel: z.enum(['TRUSTED', 'SUSPICIOUS']).optional(),
});
export type UpdateDeviceInput = z.infer<typeof updateDeviceSchema>;

// ---------------------------------------------------------------------------
// Proximity attestation schemas
// ---------------------------------------------------------------------------

export const proximityAttestationRequestSchema = z.object({
  clientLat: z.number().min(-90).max(90),
  clientLng: z.number().min(-180).max(180),
});
export type ProximityAttestationRequest = z.infer<typeof proximityAttestationRequestSchema>;

export const proximityVerifyRequestSchema = z.object({
  jwt: z.string().min(1),
  publicKey: z.string().min(1).optional(),
});
export type ProximityVerifyRequest = z.infer<typeof proximityVerifyRequestSchema>;

// ---------------------------------------------------------------------------
// Passkey schemas
// ---------------------------------------------------------------------------

export const registerPasskeySchema = z.object({
  name: z.string().min(1).max(100).optional(),
});
export type RegisterPasskeyInput = z.infer<typeof registerPasskeySchema>;

export const updatePasskeySchema = z.object({
  name: z.string().min(1).max(100),
});
export type UpdatePasskeyInput = z.infer<typeof updatePasskeySchema>;
