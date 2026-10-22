/**
 * Operator script: create an ADDITIONAL organization owned by an EXISTING user.
 *
 * Why: QRAuth only creates organizations at signup (POST /signup and a first
 * OAuth sign-in). There is no route for an existing user to add another org,
 * and invitations cannot grant OWNER. Pilots need their own org (e.g.
 * "PerforMax Pilot") so provisioned members never see the owner's main org.
 *
 * What it does, mirroring POST /signup:
 *   - one transaction: the organization (name, slug, contact email) plus the
 *     owner's OWNER membership. organizations.email is UNIQUE and is where
 *     security/key/API-key notices go, so an owner's second org needs its own
 *     address: pass --org-email (e.g. a plus-alias of the owner's mailbox).
 *   - then the org's first signing key via SigningService.createKeyPair, the
 *     same audited path signup uses (writes the key to the KMS dir and pushes
 *     it to the remote signer when one is configured)
 *   - an `organization.created_by_operator` audit row
 *
 * Refuses (nothing written) when:
 *   - the owner email does not match exactly one existing user
 *   - the slug is taken (no random suffix: the operator picks the slug)
 *   - the org email is already used by another organization
 *   - the owner already owns an org with the same name (case-insensitive)
 *
 * Usage (MANUAL ONLY, run on the QRAuth host from packages/api):
 *   npm run org:create -w packages/api -- \
 *     --name "<org name>" --owner-email <email> [--org-email <email>] [--slug <slug>] [--dry-run]
 */

import { hostname, userInfo } from 'node:os';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { PrismaClient } from '@prisma/client';
import { signupSchema } from '@qrauth/shared';
import { config } from '../src/lib/config.js';
import { closeQueues } from '../src/lib/queue.js';
import { AuditLogService } from '../src/services/audit.js';
import { SigningService } from '../src/services/signing.js';
import { HttpEcdsaSigner, LocalEcdsaSigner, type EcdsaSigner } from '../src/services/ecdsa-signer/index.js';
import { HttpRsaSigner, LocalRsaSigner, type RsaSigner } from '../src/services/rsa-signer/index.js';

const AUDIT_ACTION = 'organization.created_by_operator';
const SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

export class CreateOrgError extends Error {}

export interface CreateOrgOptions {
  name: string;
  ownerEmail: string;
  /** Contact address stored on the org (unique). Defaults to the owner's email. */
  orgEmail: string;
  slug: string;
  dryRun: boolean;
}

export interface CreateOrgResult {
  dryRun: boolean;
  organizationId: string | null;
  name: string;
  slug: string;
  orgEmail: string;
  ownerUserId: string;
  ownerEmail: string;
  signingKeyId: string | null;
  /** Set when the org was created but a follow-up step failed; the org is NOT rolled back. */
  warnings: string[];
}

/** Same derivation as POST /signup. */
export function slugFromName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

export function parseCliArgs(argv: string[]): CreateOrgOptions {
  let values;
  try {
    ({ values } = parseArgs({
      args: argv,
      strict: true,
      allowPositionals: false,
      options: {
        name: { type: 'string' },
        'owner-email': { type: 'string' },
        'org-email': { type: 'string' },
        slug: { type: 'string' },
        'dry-run': { type: 'boolean', default: false },
      },
    }));
  } catch (err) {
    throw new CreateOrgError(err instanceof Error ? err.message : String(err));
  }

  if (!values.name || !values['owner-email']) {
    throw new CreateOrgError('--name and --owner-email are required.');
  }

  const name = values.name.trim();
  if (!signupSchema.shape.organizationName.safeParse(name).success) {
    throw new CreateOrgError(`--name is not a valid organization name (got "${values.name}").`);
  }
  const ownerEmail = values['owner-email'].trim().toLowerCase();
  if (!signupSchema.shape.email.safeParse(ownerEmail).success) {
    throw new CreateOrgError(`--owner-email is not a valid email address (got "${values['owner-email']}").`);
  }
  const orgEmail = (values['org-email'] ?? ownerEmail).trim().toLowerCase();
  if (!signupSchema.shape.email.safeParse(orgEmail).success) {
    throw new CreateOrgError(`--org-email is not a valid email address (got "${values['org-email']}").`);
  }
  const slug = (values.slug ?? slugFromName(name)).trim();
  if (!SLUG_RE.test(slug)) {
    throw new CreateOrgError(`--slug must be lowercase letters, digits and single hyphens (got "${slug}").`);
  }

  return { name, ownerEmail, orgEmail, slug, dryRun: values['dry-run'] ?? false };
}

type Db = Pick<PrismaClient, 'user' | 'organization' | 'membership'>;

/**
 * Exactly one user whose email equals `email` ignoring case. Prisma's
 * insensitive `equals` is an unescaped ILIKE (`_` and `%` act as wildcards),
 * so candidates are re-checked for exact equality here.
 */
async function findOwner(db: Db, email: string): Promise<{ id: string; email: string }> {
  const candidates = await db.user.findMany({
    where: { email: { equals: email, mode: 'insensitive' } },
    select: { id: true, email: true },
  });
  const exact = candidates.filter((u) => u.email.toLowerCase() === email);
  if (exact.length !== 1) {
    throw new CreateOrgError(
      exact.length === 0
        ? `No user with email ${email}. The owner must already have a QRAuth account.`
        : `${exact.length} users match ${email} ignoring case. Refusing to guess the owner.`,
    );
  }
  return exact[0];
}

async function assertCreatable(db: Db, opts: CreateOrgOptions, ownerId: string): Promise<void> {
  if (await db.organization.findUnique({ where: { slug: opts.slug }, select: { id: true } })) {
    throw new CreateOrgError(`Slug "${opts.slug}" is already taken. Pass a different --slug.`);
  }
  const emailTaken = await db.organization.findMany({
    where: { email: { equals: opts.orgEmail, mode: 'insensitive' } },
    select: { email: true, slug: true },
  });
  const taken = emailTaken.find((o) => o.email.toLowerCase() === opts.orgEmail);
  if (taken) {
    throw new CreateOrgError(
      `Org email ${opts.orgEmail} is already used by organization "${taken.slug}". ` +
        'Organization emails are unique; pass a different --org-email (e.g. a plus-alias).',
    );
  }
  const owned = await db.membership.findMany({
    where: { userId: ownerId, role: 'OWNER' },
    select: { organization: { select: { name: true, slug: true } } },
  });
  const duplicate = owned.find((m) => m.organization.name.trim().toLowerCase() === opts.name.toLowerCase());
  if (duplicate) {
    throw new CreateOrgError(
      `${opts.ownerEmail} already owns an organization named "${duplicate.organization.name}" (slug ${duplicate.organization.slug}).`,
    );
  }
}

export interface CreateOrgDeps {
  createKeyPair: (organizationId: string) => Promise<{ keyId: string }>;
  audit: (entry: Parameters<AuditLogService['log']>[0]) => Promise<unknown>;
}

export async function createOrganization(
  prisma: PrismaClient,
  opts: CreateOrgOptions,
  deps: CreateOrgDeps,
): Promise<CreateOrgResult> {
  const owner = await findOwner(prisma, opts.ownerEmail);
  await assertCreatable(prisma, opts, owner.id);

  const base = { name: opts.name, slug: opts.slug, orgEmail: opts.orgEmail, ownerUserId: owner.id, ownerEmail: owner.email };
  if (opts.dryRun) {
    return { ...base, dryRun: true, organizationId: null, signingKeyId: null, warnings: [] };
  }

  const org = await prisma.$transaction(async (tx) => {
    // Re-check inside the transaction; the unique index on slug backstops races.
    await assertCreatable(tx, opts, owner.id);
    const created = await tx.organization.create({
      data: { name: opts.name, slug: opts.slug, email: opts.orgEmail },
      select: { id: true },
    });
    await tx.membership.create({ data: { userId: owner.id, organizationId: created.id, role: 'OWNER' } });
    return created;
  });

  // Like signup, the signing key is created right after the org commits. A
  // failure here leaves a usable org without a key; report it instead of
  // throwing so the operator sees the org id (a key can be added later with
  // POST /organizations/:id/keys/rotate).
  const warnings: string[] = [];
  let signingKeyId: string | null = null;
  try {
    signingKeyId = (await deps.createKeyPair(org.id)).keyId;
  } catch (err) {
    warnings.push(`signing key NOT created: ${err instanceof Error ? err.message : String(err)}`);
  }

  try {
    await deps.audit({
      organizationId: org.id,
      userId: owner.id,
      action: AUDIT_ACTION,
      resource: 'Organization',
      resourceId: org.id,
      metadata: {
        name: opts.name,
        slug: opts.slug,
        orgEmail: opts.orgEmail,
        signingKeyId,
        operator: userInfo().username,
        host: hostname(),
        via: 'scripts/create-org.ts',
      },
    });
  } catch (err) {
    warnings.push(`${AUDIT_ACTION} audit row NOT written: ${err instanceof Error ? err.message : String(err)}`);
  }

  return { ...base, dryRun: false, organizationId: org.id, signingKeyId, warnings };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/** Mirror plugins/ecdsa-signer.ts backend selection (this script runs outside Fastify). */
function buildSigners(): { ecdsa: EcdsaSigner; rsa: RsaSigner } {
  if (config.ecdsaSigner.backend === 'http') {
    if (!config.ecdsaSigner.url || !config.ecdsaSigner.token) {
      throw new CreateOrgError('ECDSA_SIGNER=http requires ECDSA_SIGNER_URL and ECDSA_SIGNER_TOKEN.');
    }
    return {
      ecdsa: new HttpEcdsaSigner(config.ecdsaSigner.url, config.ecdsaSigner.token),
      rsa: new HttpRsaSigner(config.ecdsaSigner.url, config.ecdsaSigner.token),
    };
  }
  return { ecdsa: new LocalEcdsaSigner(), rsa: new LocalRsaSigner() };
}

function printResult(r: CreateOrgResult): void {
  if (r.dryRun) {
    console.log('DRY RUN: nothing written.');
    console.log(`Would create org "${r.name}" (slug ${r.slug}, email ${r.orgEmail}) owned by ${r.ownerEmail} (user ${r.ownerUserId}).`);
    return;
  }
  console.log(`organization id:  ${r.organizationId}`);
  console.log(`name:             ${r.name}`);
  console.log(`slug:             ${r.slug}`);
  console.log(`org email:        ${r.orgEmail}`);
  console.log(`owner:            ${r.ownerEmail} (user ${r.ownerUserId})`);
  console.log(`signing key id:   ${r.signingKeyId ?? '(none)'}`);
  for (const w of r.warnings) console.error(`[create-org] WARNING: ${w}`);
}

async function main(): Promise<void> {
  let prisma: PrismaClient | null = null;
  try {
    const opts = parseCliArgs(process.argv.slice(2));
    prisma = new PrismaClient({ log: [{ level: 'warn', emit: 'stdout' }] });
    const db = prisma;
    const signers = buildSigners();
    const signing = new SigningService(db, signers.ecdsa, signers.rsa);
    const result = await createOrganization(db, opts, {
      createKeyPair: (organizationId) => signing.createKeyPair(organizationId),
      audit: (entry) => new AuditLogService(db).log(entry),
    });
    printResult(result);
    if (result.warnings.length > 0) process.exitCode = 1;
  } finally {
    await prisma?.$disconnect();
    // SigningService → security-webhook → lib/queue opens BullMQ/Redis
    // connections at import time; release them so the process exits on its
    // own, also after a refusal (same fix as scripts/bootstrap-platform-oidc-key.ts).
    await closeQueues();
  }
}

const isEntryPoint = process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isEntryPoint) {
  main().catch((err) => {
    console.error('[create-org] FAILED:', err instanceof Error ? err.message : err);
    process.exitCode = 1;
  });
}
