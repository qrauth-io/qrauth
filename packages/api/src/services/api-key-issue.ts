import type { ApiKey, Prisma, PrismaClient } from '@prisma/client';
import {
  API_KEY_ISSUER_REQUIRED_CODE,
  API_KEY_ROLE_TOO_HIGH_CODE,
  roleAtLeast,
  type ApiKeyOwner,
  type ApiKeyRole,
  type MembershipRole,
} from '@qrauth/shared';

import { generateApiKey } from '../lib/crypto.js';
import { lowerRole } from '../middleware/auth.js';
import type { UserContext } from '../types/fastify.js';
import { recordAudit, type AuditContext } from './audit.js';

/**
 * Organization API keys created in the dashboard or with the API-key
 * endpoints (ADR-0008 D8). Every new key records the member who created it
 * (`createdByUserId`); middleware/auth.ts then caps the key at that member's
 * current role on each request and refuses it once they leave. Keys created
 * before this have no owner and are unchanged ("legacy keys").
 */

type Db = PrismaClient | Prisma.TransactionClient;

/** Roles that may create and rotate keys (the routes' own check, re-read from the membership). */
const ISSUER_MIN_ROLE: MembershipRole = 'ADMIN';

const ROLE_LABELS: Record<MembershipRole, string> = { OWNER: 'Owner', ADMIN: 'Admin', MANAGER: 'Manager', MEMBER: 'Member', VIEWER: 'Viewer' };

export class ApiKeyIssueError extends Error {
  constructor(readonly status: 403 | 404, readonly body: { statusCode: number; error: string; code?: string; message: string }) {
    super(body.message);
    this.name = 'ApiKeyIssueError';
  }
}

const forbidden = (code: string, message: string) =>
  new ApiKeyIssueError(403, { statusCode: 403, error: 'Forbidden', code, message });

export interface KeyIssuer {
  userId: string;
  /** The issuer's role now: their membership role, or for an API key the lower of its role and its owner's. */
  role: MembershipRole;
}

/**
 * Who is creating a key, read from the database: the signed-in member, or
 * for a request made with an API key, that key's owner (a legacy key has
 * none and cannot create keys). The role must still be ADMIN or above.
 */
export async function keyIssuer(db: Db, user: UserContext): Promise<KeyIssuer> {
  let userId = user.id;
  let keyRole: MembershipRole | null = null;
  if (user.apiKeyId) {
    const key = await db.apiKey.findUnique({ where: { id: user.apiKeyId }, select: { createdByUserId: true, role: true } });
    if (!key?.createdByUserId) {
      throw forbidden(API_KEY_ISSUER_REQUIRED_CODE, 'This API key has no owner, so it cannot create or rotate keys. Create keys while signed in to the dashboard.');
    }
    userId = key.createdByUserId;
    keyRole = key.role;
  }
  const membership = await db.membership.findUnique({
    where: { userId_organizationId: { userId, organizationId: user.orgId } },
    select: { role: true },
  });
  const role = membership ? (keyRole ? lowerRole(keyRole, membership.role) : membership.role) : null;
  if (!role || !roleAtLeast(role, ISSUER_MIN_ROLE)) {
    throw forbidden(API_KEY_ROLE_TOO_HIGH_CODE, 'Creating and rotating API keys needs the Owner or Admin role in this organization.');
  }
  return { userId, role };
}

function assertRoleAllowed(issuer: KeyIssuer, role: MembershipRole): void {
  if (!roleAtLeast(issuer.role, role)) {
    throw forbidden(API_KEY_ROLE_TOO_HIGH_CODE, `A key's role cannot be above your own; ${ROLE_LABELS[role]} is not allowed.`);
  }
}

/** Non-secret details of a key for its audit entry (never the key or its hash). */
export function keyAuditDetails(key: Pick<ApiKey, 'prefix' | 'label' | 'source' | 'role' | 'createdByUserId'>) {
  return { prefix: key.prefix, label: key.label, source: key.source, role: key.role, createdByUserId: key.createdByUserId };
}

export interface IssuedKey {
  key: ApiKey;
  /** The full key: shown to the caller once, never stored. */
  fullKey: string;
}

/** Creates a key owned by `issuer` and records apiKey.create, in `tx`. */
export async function createOwnedKey(
  tx: Prisma.TransactionClient,
  ctx: AuditContext,
  args: { organizationId: string; issuer: KeyIssuer; label: string | null; role: ApiKeyRole },
): Promise<IssuedKey> {
  assertRoleAllowed(args.issuer, args.role);
  const { fullKey, prefix, hash } = generateApiKey();
  const key = await tx.apiKey.create({
    data: {
      organizationId: args.organizationId,
      keyHash: hash,
      prefix,
      label: args.label,
      role: args.role,
      createdByUserId: args.issuer.userId,
    },
  });
  await recordAudit(tx, ctx, {
    organizationId: args.organizationId,
    action: 'apiKey.create',
    resource: 'ApiKey',
    resourceId: key.id,
    metadata: keyAuditDetails(key),
  });
  return { key, fullKey };
}

/** The old key's role, capped at the issuer's and at ADMIN (a VIEWER key stays VIEWER). */
function cappedRole(role: MembershipRole, issuer: KeyIssuer): MembershipRole {
  return lowerRole(lowerRole(role, issuer.role), 'ADMIN');
}

/**
 * Replaces an active key of the organization with a new one owned by
 * `issuer`: the old key is revoked at once (no overlap) and the new one keeps
 * its label and, unless `role` is given, its role capped at the issuer's.
 * One apiKey.rotate entry names both keys. 404 when the key is not an active
 * key of the organization.
 */
export async function rotateKey(
  tx: Prisma.TransactionClient,
  ctx: AuditContext,
  args: { organizationId: string; keyId: string; issuer: KeyIssuer; role?: ApiKeyRole },
): Promise<IssuedKey & { previous: ApiKey }> {
  const previous = await tx.apiKey.findFirst({ where: { id: args.keyId, organizationId: args.organizationId, revokedAt: null } });
  const { count } = await tx.apiKey.updateMany({
    where: { id: args.keyId, organizationId: args.organizationId, revokedAt: null },
    data: { revokedAt: new Date() },
  });
  if (!previous || count === 0) {
    throw new ApiKeyIssueError(404, { statusCode: 404, error: 'Not Found', message: 'API key not found or already revoked.' });
  }
  const role = args.role ?? cappedRole(previous.role, args.issuer);
  assertRoleAllowed(args.issuer, role);
  const { fullKey, prefix, hash } = generateApiKey();
  const key = await tx.apiKey.create({
    data: {
      organizationId: args.organizationId,
      keyHash: hash,
      prefix,
      label: previous.label,
      role,
      createdByUserId: args.issuer.userId,
    },
  });
  await recordAudit(tx, ctx, {
    organizationId: args.organizationId,
    action: 'apiKey.rotate',
    resource: 'ApiKey',
    resourceId: key.id,
    metadata: {
      ...keyAuditDetails(key),
      previous: { id: previous.id, prefix: previous.prefix, role: previous.role, createdByUserId: previous.createdByUserId },
    },
  });
  return { key, fullKey, previous };
}

/** Each key's owner, for listings: name, email and whether they are still a member. */
export async function keyOwners(
  db: Db,
  organizationId: string,
  keys: ReadonlyArray<{ createdByUserId: string | null }>,
): Promise<Map<string, ApiKeyOwner>> {
  const ids = [...new Set(keys.map((k) => k.createdByUserId).filter((id): id is string => id !== null))];
  if (ids.length === 0) return new Map();
  const [users, memberships] = await Promise.all([
    db.user.findMany({ where: { id: { in: ids } }, select: { id: true, name: true, email: true } }),
    db.membership.findMany({ where: { organizationId, userId: { in: ids } }, select: { userId: true } }),
  ]);
  const members = new Set(memberships.map((m) => m.userId));
  const byId = new Map(users.map((u) => [u.id, u]));
  return new Map(
    ids.map((id) => [id, { id, name: byId.get(id)?.name ?? null, email: byId.get(id)?.email ?? null, isMember: members.has(id) }]),
  );
}
