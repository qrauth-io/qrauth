import { Prisma, type PrismaClient } from '@prisma/client';
import {
  ALLOWLIST_MAX_ENTRIES,
  DESTINATION_EDIT_ROLE_CODE,
  DESTINATION_NOT_ALLOWED_CODE,
  POLICY_INVALID_CODE,
  POLICY_ROLE_REQUIRED_CODE,
  higherRole,
  planAllowsGovernance,
  roleAtLeast,
  type AllowlistEntry,
  type AllowlistMode,
  type DestinationEditRole,
  type MembershipRole,
  type OrgPolicyPreview,
  type OrgPolicyView,
  type PolicyAffectedCode,
} from '@qrauth/shared';
import { z } from 'zod';

import {
  GOVERNANCE_PLAN_REQUIRED_CODE,
  POLICY_DOWNGRADE_MESSAGE,
  POLICY_PLAN_MESSAGE,
} from '../config/plan-limits.js';
import { allowlistView, normaliseAllowlist, policyDestinations, urlsOutside } from '../lib/allowlist-domains.js';
import { lowerRole } from '../middleware/auth.js';
import type { UserContext } from '../types/fastify.js';
import { recordAudit, type AuditContext } from './audit.js';

/**
 * Organization policies (ADR-0008 D8).
 *
 * Consistency: a policy change locks the organization row FOR UPDATE; every
 * destination write takes FOR KEY SHARE on the same row first thing in its
 * transaction (before the QR row lock, so the two never wait on each other
 * in opposite orders) and re-reads the policy. A write therefore sees either
 * the old policy and commits before the change recomputes `outsidePolicy`,
 * or the new policy.
 */

type Db = PrismaClient | Prisma.TransactionClient;

export interface PolicySettings {
  allowlistMode: AllowlistMode;
  allowlist: AllowlistEntry[];
  destinationEditMinRole: DestinationEditRole;
}

export const DEFAULT_POLICY: Readonly<PolicySettings> = Object.freeze({
  allowlistMode: 'OFF',
  allowlist: [],
  destinationEditMinRole: 'MEMBER',
});

const storedAllowlistSchema = z
  .array(z.object({ domain: z.string().min(1), includeSubdomains: z.boolean() }).strict())
  .max(ALLOWLIST_MAX_ENTRIES);

/** Interactive transactions that recompute every code of an organization. */
const POLICY_TX_TIMEOUT_MS = 30_000;
const SCAN_BATCH = 1000;
const PREVIEW_LIMIT = 100;
const ALLOWLIST_MESSAGE_LIMIT = 10;

const ROLE_LABELS: Record<DestinationEditRole, string> = { MEMBER: 'Member', MANAGER: 'Manager', ADMIN: 'Admin' };
const roleLabel = (role: MembershipRole): string => ROLE_LABELS[role as DestinationEditRole] ?? role;

// ---------------------------------------------------------------------------
// Reading and locking
// ---------------------------------------------------------------------------

/** The organization's policy; no row reads as the defaults. A stored allowlist that does not parse throws. */
export async function readPolicy(db: Db, orgId: string): Promise<PolicySettings & { id: string | null; updatedAt: Date | null }> {
  const row = await db.orgPolicy.findUnique({ where: { organizationId: orgId } });
  if (!row) return { ...DEFAULT_POLICY, allowlist: [], id: null, updatedAt: null };
  return {
    id: row.id,
    allowlistMode: row.allowlistMode,
    allowlist: storedAllowlistSchema.parse(row.allowlist),
    destinationEditMinRole: row.destinationEditMinRole as DestinationEditRole,
    updatedAt: row.updatedAt,
  };
}

/** Locks the organization row against a concurrent policy change, then reads the policy. */
export async function lockPolicyForWrite(tx: Prisma.TransactionClient, orgId: string): Promise<PolicySettings> {
  await tx.$queryRaw`SELECT 1 FROM "organizations" WHERE "id" = ${orgId} FOR KEY SHARE`;
  return readPolicy(tx, orgId);
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

export interface PolicyRefusal {
  status: 403 | 422;
  body: { statusCode: number; error: string; code: string; message: string } & Record<string, unknown>;
}

/** Thrown inside a write's transaction when the locked policy refuses it. */
export class PolicyRefusalError extends Error {
  constructor(readonly refusal: PolicyRefusal) {
    super(refusal.body.message);
    this.name = 'PolicyRefusalError';
  }
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function describeAllowlist(allowlist: readonly AllowlistEntry[]): string {
  const shown = allowlistView(allowlist.slice(0, ALLOWLIST_MESSAGE_LIMIT)).map(
    (e) => (e.includeSubdomains ? `${e.unicode} (and subdomains)` : e.unicode),
  );
  const more = allowlist.length - shown.length;
  return more > 0 ? `${shown.join(', ')} and ${more} more` : shown.join(', ');
}

/** 422 when the policy is enforced and a URL's host is not on the allowlist, else null. */
export function allowlistRefusal(policy: PolicySettings, urls: readonly string[]): PolicyRefusal | null {
  if (policy.allowlistMode !== 'ENFORCE') return null;
  const outside = urlsOutside(urls, policy.allowlist);
  if (outside.length === 0) return null;
  const hosts = [...new Set(outside.map(hostOf))];
  const subject = hosts.length === 1 ? `${hosts[0]} is` : `${hosts.join(', ')} are`;
  return {
    status: 422,
    body: {
      statusCode: 422,
      error: 'Unprocessable Entity',
      code: DESTINATION_NOT_ALLOWED_CODE,
      message: `${subject} not on this organization's destination allowlist. Allowed: ${describeAllowlist(policy.allowlist)}.`,
      outside,
      allowedDomains: allowlistView(policy.allowlist),
    },
  };
}

type ActorRole =
  | { kind: 'role'; role: MembershipRole }
  | { kind: 'no-creator'; role: MembershipRole }
  | { kind: 'not-a-member' };

/**
 * The requester's role in the organization now, read from the database:
 * a user's membership; for an API key, the lower of the key's role and its
 * creator's current role. A legacy key (no owner) carries its stored role,
 * which the auth middleware applies; the destination-edit gate refuses it.
 */
async function currentActorRole(db: Db, user: UserContext): Promise<ActorRole> {
  if (user.apiKeyId) {
    const key = await db.apiKey.findUnique({
      where: { id: user.apiKeyId },
      select: { organizationId: true, role: true, createdByUserId: true, revokedAt: true },
    });
    if (!key || key.revokedAt !== null || key.organizationId !== user.orgId) return { kind: 'not-a-member' };
    if (!key.createdByUserId) return { kind: 'no-creator', role: key.role };
    const creator = await db.membership.findUnique({
      where: { userId_organizationId: { userId: key.createdByUserId, organizationId: user.orgId } },
      select: { role: true },
    });
    return creator ? { kind: 'role', role: lowerRole(key.role, creator.role) } : { kind: 'not-a-member' };
  }
  const membership = await db.membership.findUnique({
    where: { userId_organizationId: { userId: user.id, organizationId: user.orgId } },
    select: { role: true },
  });
  return membership ? { kind: 'role', role: membership.role } : { kind: 'not-a-member' };
}

function roleRefusalMessage(actor: ActorRole, min: MembershipRole, viaApiKey: boolean): string {
  const required = `the ${roleLabel(min)} role or higher`;
  if (actor.kind === 'no-creator') {
    return `Changing a code's destination requires ${required} in this organization. This is a legacy API key with no owner, so it cannot change destinations under this policy. Rotate it on the API Keys page to give it an owner and a role.`;
  }
  if (viaApiKey) {
    return `Changing a code's destination requires ${required} in this organization. This API key acts with the lower of its own role and its owner's current role, which is below that.`;
  }
  return `Changing a code's destination requires ${required} in this organization. You can still edit the code's label, tags and other settings.`;
}

/**
 * 403 when the policy's minimum role (or `floor`, the route's own minimum,
 * whichever is higher) is above the requester's current role, else null.
 * With the default minimum (MEMBER) nothing is looked up: the route's role
 * check is today's rule.
 */
export async function destinationRoleRefusal(
  db: Db,
  user: UserContext,
  policy: PolicySettings,
  floor: MembershipRole,
): Promise<PolicyRefusal | null> {
  if (policy.destinationEditMinRole === 'MEMBER') return null;
  const min = higherRole(policy.destinationEditMinRole, floor);
  const actor = await currentActorRole(db, user);
  if (actor.kind === 'role' && roleAtLeast(actor.role, min)) return null;
  return {
    status: 403,
    body: {
      statusCode: 403,
      error: 'Forbidden',
      code: DESTINATION_EDIT_ROLE_CODE,
      message: roleRefusalMessage(actor, min, Boolean(user.apiKeyId)),
      requiredRole: min,
    },
  };
}

/**
 * The checks a destination write must pass, run first in its transaction
 * against the locked policy: the allowlist for `urls` and, for a change
 * (not a create), the requester's role. Throws PolicyRefusalError; returns
 * the locked policy, against which the caller sets the code's mark.
 */
export async function enforcePolicyInTransaction(
  tx: Prisma.TransactionClient,
  orgId: string,
  args: { urls: readonly string[]; change?: { user: UserContext; floor: MembershipRole } },
): Promise<PolicySettings> {
  const policy = await lockPolicyForWrite(tx, orgId);
  if (args.change) {
    const roleRefusal = await destinationRoleRefusal(tx, args.change.user, policy, args.change.floor);
    if (roleRefusal) throw new PolicyRefusalError(roleRefusal);
  }
  const refusal = allowlistRefusal(policy, args.urls);
  if (refusal) throw new PolicyRefusalError(refusal);
  return policy;
}

/** `outsidePolicy` for a code with these destinations under `policy`: true when enforced and any is outside. */
export function isOutsidePolicy(policy: PolicySettings, destinations: readonly string[]): boolean {
  return policy.allowlistMode === 'ENFORCE' && urlsOutside(destinations, policy.allowlist).length > 0;
}

// ---------------------------------------------------------------------------
// Codes outside a list
// ---------------------------------------------------------------------------

type CodeStatus = 'ACTIVE' | 'EXPIRED' | 'REVOKED';

/** Calls `visit` with each code of the organization (in `statuses`) whose destinations fall outside `allowlist`. */
async function forEachCodeOutside(
  db: Db,
  orgId: string,
  allowlist: readonly AllowlistEntry[],
  statuses: readonly CodeStatus[],
  visit: (code: PolicyAffectedCode & { id: string }) => void,
): Promise<void> {
  let cursor: string | undefined;
  for (;;) {
    const page = await db.qRCode.findMany({
      where: { organizationId: orgId, status: { in: [...statuses] } },
      select: { id: true, token: true, label: true, contentType: true, destinationUrl: true, content: true },
      orderBy: { id: 'asc' },
      take: SCAN_BATCH,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
    });
    for (const code of page) {
      const outside = urlsOutside(policyDestinations(code), allowlist);
      if (outside.length > 0) {
        visit({ id: code.id, token: code.token, label: code.label, contentType: code.contentType || 'url', outside });
      }
    }
    if (page.length < SCAN_BATCH) return;
    cursor = page[page.length - 1].id;
  }
}

/**
 * Sets `outsidePolicy` on every code of the organization to match `policy`
 * (all false when the allowlist is off; revoked codes are never marked).
 * Returns the number of codes marked.
 */
export async function recomputeOutsidePolicy(tx: Prisma.TransactionClient, orgId: string, policy: PolicySettings): Promise<number> {
  if (policy.allowlistMode !== 'ENFORCE') {
    await tx.$executeRaw`UPDATE "qr_codes" SET "outsidePolicy" = false WHERE "organizationId" = ${orgId} AND "outsidePolicy"`;
    return 0;
  }
  const ids: string[] = [];
  await forEachCodeOutside(tx, orgId, policy.allowlist, ['ACTIVE', 'EXPIRED'], (code) => ids.push(code.id));
  await tx.$executeRaw`
    UPDATE "qr_codes" SET "outsidePolicy" = ("id" = ANY(${ids}::text[]))
    WHERE "organizationId" = ${orgId} AND "outsidePolicy" IS DISTINCT FROM ("id" = ANY(${ids}::text[]))`;
  return ids.length;
}

// ---------------------------------------------------------------------------
// Views, preview, update
// ---------------------------------------------------------------------------

export async function policyView(prisma: PrismaClient, orgId: string): Promise<OrgPolicyView> {
  const [policy, org, outsidePolicyCount, apiKeysWithoutCreator] = await Promise.all([
    readPolicy(prisma, orgId),
    prisma.organization.findUniqueOrThrow({ where: { id: orgId }, select: { plan: true } }),
    prisma.qRCode.count({ where: { organizationId: orgId, outsidePolicy: true } }),
    prisma.apiKey.count({ where: { organizationId: orgId, revokedAt: null, createdByUserId: null } }),
  ]);
  return {
    allowlistMode: policy.allowlistMode,
    allowlist: allowlistView(policy.allowlist),
    destinationEditMinRole: policy.destinationEditMinRole,
    updatedAt: policy.updatedAt?.toISOString() ?? null,
    editable: planAllowsGovernance(org.plan),
    outsidePolicyCount,
    apiKeysWithoutCreator,
  };
}

/** How a proposed allowlist would be stored, and the active codes outside it. Stores nothing. */
export async function previewPolicy(
  prisma: PrismaClient,
  orgId: string,
  entries: ReadonlyArray<{ domain: string; includeSubdomains: boolean }>,
): Promise<OrgPolicyPreview> {
  const { results, allowlist } = normaliseAllowlist(entries);
  const affected: PolicyAffectedCode[] = [];
  let affectedTotal = 0;
  await forEachCodeOutside(prisma, orgId, allowlist, ['ACTIVE'], ({ id: _id, ...code }) => {
    affectedTotal += 1;
    if (affected.length < PREVIEW_LIMIT) affected.push(code);
  });
  return { entries: results, allowlist, affected, affectedTotal };
}

export class PolicyUpdateError extends Error {
  constructor(readonly status: 403 | 422, readonly body: Record<string, unknown> & { message: string }) {
    super(body.message);
    this.name = 'PolicyUpdateError';
  }
}

const sameAllowlist = (a: readonly AllowlistEntry[], b: readonly AllowlistEntry[]): boolean =>
  a.length === b.length && a.every((e, i) => e.domain === b[i].domain && e.includeSubdomains === b[i].includeSubdomains);

const samePolicy = (a: PolicySettings, b: PolicySettings): boolean =>
  a.allowlistMode === b.allowlistMode && a.destinationEditMinRole === b.destinationEditMinRole && sameAllowlist(a.allowlist, b.allowlist);

/** Below the Business plan the only change allowed is switching off: mode to OFF and/or role to MEMBER, list untouched. */
const isSwitchOff = (before: PolicySettings, after: PolicySettings): boolean =>
  sameAllowlist(before.allowlist, after.allowlist) &&
  (after.allowlistMode === before.allowlistMode || after.allowlistMode === 'OFF') &&
  (after.destinationEditMinRole === before.destinationEditMinRole || after.destinationEditMinRole === 'MEMBER');

const auditFields = (p: PolicySettings) => ({
  allowlistMode: p.allowlistMode,
  allowlist: p.allowlist,
  destinationEditMinRole: p.destinationEditMinRole,
});

function planRefusal(before: PolicySettings): PolicyUpdateError {
  const message = samePolicy(before, DEFAULT_POLICY) ? POLICY_PLAN_MESSAGE : POLICY_DOWNGRADE_MESSAGE;
  return new PolicyUpdateError(403, { statusCode: 403, error: 'Forbidden', code: GOVERNANCE_PLAN_REQUIRED_CODE, message });
}

function invalidRefusal(message: string, extra: Record<string, unknown> = {}): PolicyUpdateError {
  return new PolicyUpdateError(422, { statusCode: 422, error: 'Unprocessable Entity', code: POLICY_INVALID_CODE, message, ...extra });
}

/**
 * Replaces the organization's policy (PUT semantics), recomputes which codes
 * are outside it and records `policy.update` with before and after, in one
 * transaction under the organization row lock. A request that changes
 * nothing writes nothing. Returns whether anything changed.
 */
/**
 * Throws 403 unless the requester is OWNER or ADMIN now, read from the
 * membership (not the session token, which may predate a demotion).
 */
export async function assertPolicyManager(db: Db, user: UserContext): Promise<void> {
  const actor = await currentActorRole(db, user);
  if (actor.kind !== 'not-a-member' && roleAtLeast(actor.role, 'ADMIN')) return;
  throw new PolicyUpdateError(403, {
    statusCode: 403,
    error: 'Forbidden',
    code: POLICY_ROLE_REQUIRED_CODE,
    message: 'Organization policies are managed by owners and admins.',
  });
}

export async function updatePolicy(
  prisma: PrismaClient,
  orgId: string,
  input: {
    allowlistMode: AllowlistMode;
    /** Omitted: keep the stored list as it is, without re-normalising it. */
    allowlist?: ReadonlyArray<{ domain: string; includeSubdomains: boolean }>;
    destinationEditMinRole: DestinationEditRole;
  },
  ctx: AuditContext,
  user: UserContext,
): Promise<boolean> {
  let submitted: AllowlistEntry[] | undefined;
  if (input.allowlist) {
    const { results, allowlist } = normaliseAllowlist(input.allowlist);
    if (results.some((r) => !r.ok)) {
      throw invalidRefusal('Some allowlist entries are not valid domains.', { entries: results });
    }
    submitted = allowlist.map(({ domain, includeSubdomains }) => ({ domain, includeSubdomains }));
  }

  return prisma.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT 1 FROM "organizations" WHERE "id" = ${orgId} FOR UPDATE`;
    await assertPolicyManager(tx, user);
    const { plan } = await tx.organization.findUniqueOrThrow({ where: { id: orgId }, select: { plan: true } });
    const before = await readPolicy(tx, orgId);
    const after: PolicySettings = {
      allowlistMode: input.allowlistMode,
      allowlist: submitted ?? before.allowlist,
      destinationEditMinRole: input.destinationEditMinRole,
    };
    if (after.allowlistMode === 'ENFORCE' && after.allowlist.length === 0) {
      throw invalidRefusal('Add at least one domain before enforcing the allowlist.');
    }
    if (samePolicy(before, after)) return false;
    if (!planAllowsGovernance(plan) && !isSwitchOff(before, after)) throw planRefusal(before);

    const data = { ...after, allowlist: after.allowlist as unknown as Prisma.InputJsonValue };
    const row = await tx.orgPolicy.upsert({
      where: { organizationId: orgId },
      create: { organizationId: orgId, ...data },
      update: data,
    });
    const outsidePolicy = await recomputeOutsidePolicy(tx, orgId, after);
    await recordAudit(tx, ctx, {
      organizationId: orgId,
      action: 'policy.update',
      resource: 'OrgPolicy',
      resourceId: row.id,
      metadata: { before: before.id ? auditFields(before) : null, after: auditFields(after), codesOutsidePolicy: outsidePolicy },
    });
    return true;
  }, { timeout: POLICY_TX_TIMEOUT_MS });
}
