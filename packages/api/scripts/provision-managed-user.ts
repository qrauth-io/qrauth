/**
 * Operator script: provision a pre-verified, operator-managed user into an
 * EXISTING organization and hand back a one-time set-password link.
 *
 * Why: pilot users (e.g. PerforMax: @allianz.com, @mondial-assistance.gr) sit
 * behind corporate mail gateways that may never deliver the verify-email
 * link, and email/password signup blocks login until that link is clicked
 * (routes/auth.ts POST /login → 403 EmailNotVerified). Operator provisioning +
 * out-of-band delivery of the set-password link replaces the email proof.
 *
 * Anti-takeover invariant: this script only ever CREATES an account. If any
 * user already holds the address (case-insensitive), it aborts without
 * touching that account. Because the operator creates the account, there is
 * no window in which a third party could SIGN UP with the address first.
 *
 * OAuth sign-in: since #215 (a8eb576) the OAuth callback links or signs in an
 * existing account only when the provider itself verified the email (Google
 * verified_email, GitHub verified primary, Microsoft xms_edov, Apple
 * email_verified). An unverified provider identity asserting a provisioned
 * address is refused, so the Microsoft-tenant takeover this script used to
 * warn about is closed.
 *
 * The created user:
 *   - emailVerified=true, emailVerifyToken=null
 *   - passwordHash='' — can never satisfy POST /login: the empty string is
 *     falsy, so /login verifies against its dummy hash (and verifyPassword('')
 *     itself returns false)
 *   - onboardedAt=now — otherwise the web AuthGuard forces /onboarding, whose
 *     POST /onboarding/complete renames the user's ACTIVE org (the shared
 *     pilot org) with no role check
 *   - one Membership in the target org (never OWNER)
 *   - a set-password token minted exactly like POST /forgot-password
 *     (32 random bytes hex, SHA-256 at rest) and consumed by the normal
 *     POST /reset-password + web /auth/jwt/reset-password page
 *
 * Usage (MANUAL ONLY, never wired into migrations/seed/CI):
 *   npm run user:provision -w packages/api -- \
 *     --email <e> --name "<n>" --org-slug <slug> [--role MEMBER] [--ttl-hours 48] [--dry-run]
 *
 * Output: user id, email, org slug, expiry, and the set-password URL. The raw
 * token appears ONLY inside that URL and is never logged anywhere else.
 */

import { randomBytes } from 'node:crypto';
import { hostname, userInfo } from 'node:os';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { PrismaClient, type MembershipRole } from '@prisma/client';
import { signupSchema, inviteUserSchema } from '@qrauth/shared';
import { hashString } from '../src/lib/crypto.js';
import { passwordResetUrl } from '../src/lib/dashboard-url.js';
import { AuditLogService } from '../src/services/audit.js';

export const DEFAULT_TTL_HOURS = 48;
export const MAX_TTL_HOURS = 72;
const DEFAULT_ROLE: MembershipRole = 'MEMBER';
const AUDIT_ACTION = 'user.provisioned_by_operator';

export class ProvisionError extends Error {}

export interface ProvisionOptions {
  email: string;
  name: string;
  orgSlug: string;
  role: MembershipRole;
  ttlHours: number;
  dryRun: boolean;
}

export interface ProvisionResult {
  dryRun: boolean;
  userId: string | null;
  email: string;
  orgSlug: string;
  role: MembershipRole;
  expiresAt: Date;
  setPasswordUrl: string | null;
  /** Null when the audit row was written (or on dry-run); the error message otherwise. */
  auditError: string | null;
}

// ---------------------------------------------------------------------------
// Argument parsing / validation
// ---------------------------------------------------------------------------

/** Trim + lowercase. Exported so tests and callers agree on one normalization. */
export function normalizeEmail(raw: string): string {
  return raw.trim().toLowerCase();
}

function parseRole(raw: string | undefined): MembershipRole {
  const role = (raw ?? DEFAULT_ROLE).trim().toUpperCase();
  if (role === 'OWNER') {
    throw new ProvisionError('--role OWNER is not allowed for managed users.');
  }
  // Same role set the invitation flow accepts (ADMIN/MANAGER/MEMBER/VIEWER).
  const parsed = inviteUserSchema.shape.role.safeParse(role);
  if (!parsed.success) {
    throw new ProvisionError(`--role must be one of ADMIN, MANAGER, MEMBER, VIEWER (got "${raw}").`);
  }
  return parsed.data;
}

function parseTtlHours(raw: string | undefined): number {
  if (raw === undefined) return DEFAULT_TTL_HOURS;
  const ttl = Number(raw);
  if (!Number.isInteger(ttl) || ttl < 1 || ttl > MAX_TTL_HOURS) {
    throw new ProvisionError(`--ttl-hours must be an integer between 1 and ${MAX_TTL_HOURS} (got "${raw}").`);
  }
  return ttl;
}

export function parseCliArgs(argv: string[]): ProvisionOptions {
  let values;
  try {
    ({ values } = parseArgs({
      args: argv,
      strict: true,
      allowPositionals: false,
      options: {
        email: { type: 'string' },
        name: { type: 'string' },
        'org-slug': { type: 'string' },
        role: { type: 'string' },
        'ttl-hours': { type: 'string' },
        'dry-run': { type: 'boolean', default: false },
      },
    }));
  } catch (err) {
    throw new ProvisionError(err instanceof Error ? err.message : String(err));
  }

  if (!values.email || !values.name || !values['org-slug']) {
    throw new ProvisionError('--email, --name and --org-slug are required.');
  }

  const email = normalizeEmail(values.email);
  // Same email/name rules as POST /signup.
  if (!signupSchema.shape.email.safeParse(email).success) {
    throw new ProvisionError(`--email is not a valid email address (got "${values.email}").`);
  }
  const name = values.name.trim();
  if (!signupSchema.shape.name.safeParse(name).success) {
    throw new ProvisionError('--name must be 2-100 characters.');
  }

  return {
    email,
    name,
    orgSlug: values['org-slug'].trim(),
    role: parseRole(values.role),
    ttlHours: parseTtlHours(values['ttl-hours']),
    dryRun: values['dry-run'] ?? false,
  };
}

// ---------------------------------------------------------------------------
// Provisioning
// ---------------------------------------------------------------------------

async function assertEmailUnused(db: Pick<PrismaClient, 'user'>, email: string): Promise<void> {
  // Case-insensitive: users.email is case-sensitive in Postgres and neither
  // /signup nor /login normalizes, so "Jane@x.com" may already exist.
  const existing = await db.user.findFirst({
    where: { email: { equals: email, mode: 'insensitive' } },
    select: { id: true },
  });
  if (existing) {
    throw new ProvisionError(
      `A user with email ${email} already exists (id=${existing.id}). ` +
        'Refusing to modify an existing account.',
    );
  }
}

export async function provisionManagedUser(
  prisma: PrismaClient,
  opts: ProvisionOptions,
  now: Date = new Date(),
): Promise<ProvisionResult> {
  // parseCliArgs already rejects OWNER; re-check for programmatic callers.
  if (opts.role === 'OWNER') {
    throw new ProvisionError('OWNER is not allowed for managed users.');
  }
  const expiresAt = new Date(now.getTime() + opts.ttlHours * 60 * 60 * 1000);

  const org = await prisma.organization.findUnique({
    where: { slug: opts.orgSlug },
    select: { id: true, slug: true },
  });
  if (!org) {
    throw new ProvisionError(`Organization with slug "${opts.orgSlug}" not found. Create it first.`);
  }

  await assertEmailUnused(prisma, opts.email);

  const base = { email: opts.email, orgSlug: org.slug, role: opts.role, expiresAt };
  if (opts.dryRun) {
    return { ...base, dryRun: true, userId: null, setPasswordUrl: null, auditError: null };
  }

  const rawToken = randomBytes(32).toString('hex');

  const user = await prisma.$transaction(async (tx) => {
    // Re-check inside the transaction to narrow the race with a concurrent
    // signup; the unique index on users.email backstops exact-case races.
    await assertEmailUnused(tx, opts.email);

    const created = await tx.user.create({
      data: {
        name: opts.name,
        email: opts.email,
        passwordHash: '',
        emailVerified: true,
        emailVerifyToken: null,
        onboardedAt: now,
        passwordResetToken: hashString(rawToken),
        passwordResetExpires: expiresAt,
      },
      select: { id: true },
    });

    await tx.membership.create({
      data: { userId: created.id, organizationId: org.id, role: opts.role },
    });

    return created;
  });

  // AuditLogService takes a PrismaClient, not a transaction client, so the
  // audit row is written right after the commit rather than inside it. A
  // failure here must not lose the set-password link (the account already
  // exists), so it is reported to the caller instead of thrown.
  let auditError: string | null = null;
  try {
    await new AuditLogService(prisma).log({
      organizationId: org.id,
      userId: user.id,
      action: AUDIT_ACTION,
      resource: 'User',
      resourceId: user.id,
      metadata: {
        role: opts.role,
        ttlHours: opts.ttlHours,
        setPasswordExpiresAt: expiresAt.toISOString(),
        operator: userInfo().username,
        host: hostname(),
        via: 'scripts/provision-managed-user.ts',
      },
    });
  } catch (err) {
    auditError = err instanceof Error ? err.message : String(err);
  }

  return { ...base, dryRun: false, userId: user.id, setPasswordUrl: passwordResetUrl(rawToken), auditError };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function printResult(result: ProvisionResult): void {
  if (result.dryRun) {
    console.log('DRY RUN: nothing written.');
    console.log(`Would provision ${result.email} into org ${result.orgSlug} as ${result.role}.`);
    console.log(`Set-password link would expire at ${result.expiresAt.toISOString()}.`);
    return;
  }
  console.log(`user id:          ${result.userId}`);
  console.log(`email:            ${result.email}`);
  console.log(`org slug:         ${result.orgSlug}`);
  console.log(`expires at:       ${result.expiresAt.toISOString()}`);
  console.log(`set-password URL: ${result.setPasswordUrl}`);
  if (result.auditError) {
    console.error(`[provision-managed-user] WARNING: user created but the ${AUDIT_ACTION} audit row was NOT written: ${result.auditError}`);
  }
}

async function main(): Promise<void> {
  const opts = parseCliArgs(process.argv.slice(2));
  // No Redis/BullMQ is imported on this path, so disconnecting Prisma is
  // enough for the process to exit on its own.
  const prisma = new PrismaClient({ log: [{ level: 'warn', emit: 'stdout' }] });
  try {
    const result = await provisionManagedUser(prisma, opts);
    printResult(result);
    if (result.auditError) process.exitCode = 1;
  } finally {
    await prisma.$disconnect();
  }
}

const isEntryPoint = process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isEntryPoint) {
  main().catch((err) => {
    console.error('[provision-managed-user] FAILED:', err instanceof Error ? err.message : err);
    process.exitCode = 1;
  });
}
