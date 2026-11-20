import { z } from 'zod';

/**
 * Organization API keys created in the dashboard or with the API-key
 * endpoints (ADR-0008 D8). A key records the member who created it and acts
 * with the lower of its role and that member's current role; it is refused
 * once that member leaves the organization. Keys created before owners were
 * recorded have none ("legacy keys") and keep role MEMBER.
 */

/** Roles a member may give a key, never above their own. */
export const API_KEY_ROLES = ['MEMBER', 'MANAGER', 'ADMIN'] as const;
export type ApiKeyRole = (typeof API_KEY_ROLES)[number];

/**
 * POST /api/v1/api-keys and POST /api/v1/organizations/:id/api-keys. Unknown
 * fields are ignored and an empty label is no label, as before `role` existed.
 */
export const createApiKeySchema = z.object({
  label: z
    .string()
    .trim()
    .max(100)
    .optional()
    .transform((v) => v || undefined),
  role: z.enum(API_KEY_ROLES).default('MEMBER'),
});

/** POST /api/v1/api-keys/:id/rotate. Without `role` the new key keeps the old key's role (capped at the caller's). */
export const rotateApiKeySchema = z.object({ role: z.enum(API_KEY_ROLES).optional() }).strict();

export type CreateApiKeyInput = z.input<typeof createApiKeySchema>;
export type RotateApiKeyInput = z.input<typeof rotateApiKeySchema>;

/** The member a key belongs to, in key listings. `isMember` false: they left and the key is refused. */
export interface ApiKeyOwner {
  id: string;
  name: string | null;
  email: string | null;
  isMember: boolean;
}

export const API_KEY_ROLE_TOO_HIGH_CODE = 'api-key-role-too-high';
export const API_KEY_ISSUER_REQUIRED_CODE = 'api-key-owner-required';
