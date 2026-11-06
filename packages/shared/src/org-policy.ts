import { z } from 'zod';

import { ROLE_HIERARCHY, type MembershipRole } from './constants.js';

/**
 * Organization policies (ADR-0008 D8): a destination allowlist and the
 * lowest role that may change a code's destination. Shared by the API, the
 * dashboard and the Node SDK; domain normalisation (Public Suffix List)
 * runs in the API only.
 */

export const ALLOWLIST_MODES = ['OFF', 'ENFORCE'] as const;
export type AllowlistMode = (typeof ALLOWLIST_MODES)[number];

/** Minimum roles a policy may require for destination changes. */
export const DESTINATION_EDIT_ROLES = ['MEMBER', 'MANAGER', 'ADMIN'] as const;
export type DestinationEditRole = (typeof DESTINATION_EDIT_ROLES)[number];

export const ALLOWLIST_MAX_ENTRIES = 200;

/** Roles that may read and change organization policies. */
export const POLICY_MANAGER_ROLES = ['OWNER', 'ADMIN'] as const;

export const DESTINATION_NOT_ALLOWED_CODE = 'destination-not-allowed';
export const DESTINATION_EDIT_ROLE_CODE = 'destination-edit-role-required';
export const POLICY_INVALID_CODE = 'policy-invalid';
export const POLICY_ROLE_REQUIRED_CODE = 'policy-role-required';

/** True when `role` is `min` or higher (ROLE_HIERARCHY is ordered highest first). */
export function roleAtLeast(role: string, min: MembershipRole): boolean {
  const index = ROLE_HIERARCHY.indexOf(role as MembershipRole);
  return index !== -1 && index <= ROLE_HIERARCHY.indexOf(min);
}

/** The higher of two roles. */
export function higherRole(a: MembershipRole, b: MembershipRole): MembershipRole {
  return ROLE_HIERARCHY.indexOf(a) <= ROLE_HIERARCHY.indexOf(b) ? a : b;
}

/**
 * One allowlist entry as submitted. `domain` may be a host, a URL or an
 * internationalised name; the API reduces it to its registrable domain.
 */
export const allowlistEntryInputSchema = z
  .object({
    domain: z.string().trim().min(1, 'Enter a domain').max(512),
    includeSubdomains: z.boolean().default(true),
  })
  .strict();

const allowlistInputSchema = z
  .array(allowlistEntryInputSchema)
  .max(ALLOWLIST_MAX_ENTRIES, `An allowlist holds at most ${ALLOWLIST_MAX_ENTRIES} domains`);

/**
 * PUT /api/v1/policies: the whole policy. Without `allowlist` the stored list
 * is kept as it is (not re-normalised), e.g. to switch the policy off.
 */
export const orgPolicyUpdateSchema = z
  .object({
    allowlistMode: z.enum(ALLOWLIST_MODES),
    allowlist: allowlistInputSchema.optional(),
    destinationEditMinRole: z.enum(DESTINATION_EDIT_ROLES),
  })
  .strict();

/** POST /api/v1/policies/preview: an allowlist to check before saving. */
export const orgPolicyPreviewSchema = z.object({ allowlist: allowlistInputSchema }).strict();

export type AllowlistEntryInput = z.input<typeof allowlistEntryInputSchema>;
export type OrgPolicyUpdateInput = z.input<typeof orgPolicyUpdateSchema>;
export type OrgPolicyPreviewInput = z.input<typeof orgPolicyPreviewSchema>;

/** A stored allowlist entry: a registrable domain in ASCII (punycode) form. */
export interface AllowlistEntry {
  domain: string;
  includeSubdomains: boolean;
}

/** An entry as the API returns it, with the Unicode form for display. */
export interface AllowlistEntryView extends AllowlistEntry {
  unicode: string;
}

/** GET and PUT /api/v1/policies. */
export interface OrgPolicyView {
  allowlistMode: AllowlistMode;
  allowlist: AllowlistEntryView[];
  destinationEditMinRole: DestinationEditRole;
  updatedAt: string | null;
  /** False below the Business plan: the policy can only be switched off. */
  editable: boolean;
  /** Codes (not revoked) currently marked outside the policy. */
  outsidePolicyCount: number;
  /** Active API keys with no recorded creator (see destinationEditMinRole). */
  apiKeysWithoutCreator: number;
}

/** How one submitted entry was normalised. */
export type AllowlistNormalisation =
  | { input: string; ok: true; entry: AllowlistEntryView; note: string | null }
  | { input: string; ok: false; message: string };

/** A code whose destination or links fall outside a proposed allowlist. */
export interface PolicyAffectedCode {
  token: string;
  label: string | null;
  contentType: string;
  /** The destination or links that are not allowed. */
  outside: string[];
}

/** POST /api/v1/policies/preview. */
export interface OrgPolicyPreview {
  entries: AllowlistNormalisation[];
  /** The entries as they would be stored (normalised, duplicates merged). */
  allowlist: AllowlistEntryView[];
  /** Active codes outside the proposed list (first 100), and their total. */
  affected: PolicyAffectedCode[];
  affectedTotal: number;
}
