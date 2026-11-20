/**
 * Rotate ACTIVE ES256 signing keys created before prod was verified on
 * signer-side key generation (ADR-0009 D13).
 *
 * Run on the API host, from packages/api:
 *   npx --no-install tsx --env-file=.env scripts/rotate-pre-signer-keygen-keys.ts \
 *     [--before <ISO-8601 UTC, e.g. 2026-11-20T00:00:00Z>] [--org <id>] [--apply]
 *
 * --before defaults to 2026-11-20T00:00:00Z, the day prod was verified on
 * SIGNER_KEYGEN=signer; every ACTIVE ES256 key created earlier is a
 * candidate. Lists the candidate keys by default and changes nothing. With --apply it
 * rotates each candidate through SigningService.rotateKeyById, the same path
 * as the scheduled rotation: the signer generates the new pair, a sign probe
 * must pass before commit, the old row becomes ROTATED, and the rotation is
 * written to the audit log (`signingKey.rotate`, reason `manual`). No QR code
 * is re-signed; codes signed by the old key keep verifying.
 *
 * --apply refuses to run unless SIGNER_KEYGEN=signer, so new keys are always
 * generated on the signer. After the run it prints read-only verification
 * queries.
 */
import { pathToFileURL } from 'node:url';
import type { PrismaClient } from '@prisma/client';

/** Prod verified on SIGNER_KEYGEN=signer on 2026-11-20 (ADR-0009 D13). */
export const DEFAULT_CUTOFF = new Date('2026-11-20T00:00:00.000Z');

const ORG_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
/** An explicit UTC instant: `YYYY-MM-DDTHH:MM:SS[.sss]Z`. */
const ISO_UTC_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;

export class CliArgsError extends Error {}

export interface CliOptions {
  apply: boolean;
  orgId: string | null;
  before: Date;
}

export interface Candidate {
  keyId: string;
  organizationId: string;
  createdAt: Date;
}

export interface RotationResult {
  rotated: Array<{ keyId: string; newKeyId: string }>;
  failed: Array<{ keyId: string; error: string }>;
}

function assertOrgId(orgId: string): string {
  if (!ORG_ID_PATTERN.test(orgId)) {
    throw new CliArgsError(`--org must be an organization id (letters, digits, '_' or '-'), got "${orgId}"`);
  }
  return orgId;
}

function parseBefore(value: string): Date {
  const date = new Date(value);
  if (!ISO_UTC_PATTERN.test(value) || Number.isNaN(date.getTime()) || date.toISOString().slice(0, 19) !== value.slice(0, 19)) {
    throw new CliArgsError(`--before must be an ISO-8601 UTC instant like 2026-11-20T00:00:00Z, got "${value}"`);
  }
  return date;
}

function optionValue(argv: string[], i: number, name: string): string {
  const value = argv[i + 1];
  if (value === undefined || value.startsWith('--')) {
    throw new CliArgsError(`${name} needs a value`);
  }
  return value;
}

export function parseCliArgs(argv: string[]): CliOptions {
  let apply = false;
  let orgId: string | null = null;
  let before = DEFAULT_CUTOFF;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--apply') {
      apply = true;
    } else if (arg === '--org') {
      orgId = assertOrgId(optionValue(argv, i, '--org'));
      i++;
    } else if (arg === '--before') {
      before = parseBefore(optionValue(argv, i, '--before'));
      i++;
    } else {
      throw new CliArgsError(`unknown argument "${arg}"`);
    }
  }
  return { apply, orgId, before };
}

export async function findCandidates(
  prisma: PrismaClient,
  orgId: string | null,
  before: Date,
): Promise<Candidate[]> {
  return prisma.signingKey.findMany({
    where: {
      status: 'ACTIVE',
      algorithm: 'ES256',
      createdAt: { lt: before },
      ...(orgId ? { organizationId: orgId } : {}),
    },
    orderBy: { createdAt: 'asc' },
    select: { keyId: true, organizationId: true, createdAt: true },
  });
}

/** Rotate one key at a time; a failure is recorded and the run continues. */
export async function rotateCandidates(
  candidates: Candidate[],
  rotate: (keyId: string) => Promise<{ keyId: string }>,
): Promise<RotationResult> {
  const result: RotationResult = { rotated: [], failed: [] };
  for (const candidate of candidates) {
    try {
      const next = await rotate(candidate.keyId);
      result.rotated.push({ keyId: candidate.keyId, newKeyId: next.keyId });
    } catch (err) {
      result.failed.push({ keyId: candidate.keyId, error: err instanceof Error ? err.message : String(err) });
    }
  }
  return result;
}

/**
 * Read-only SQL for checking the result; run with psql after --apply.
 *
 * Prisma stores DateTime columns as UTC wall-clock `timestamp` values and the
 * prod session time zone is not UTC, so the session is set to UTC first and
 * the cutoff is a plain `timestamp` literal.
 */
export function verificationQueries(orgId: string | null, before: Date): string[] {
  const cutoff = `timestamp '${before.toISOString().slice(0, 19).replace('T', ' ')}'`;
  const orgFilter = orgId ? ` AND "organizationId" = '${assertOrgId(orgId)}'` : '';
  return [
    "SET TIME ZONE 'UTC';",
    'BEGIN READ ONLY;',
    `-- expect 0: no ACTIVE ES256 key from before the keygen switch`,
    `SELECT count(*) FROM signing_keys WHERE status = 'ACTIVE' AND algorithm = 'ES256' AND "createdAt" < ${cutoff}${orgFilter};`,
    `-- expect 0: every org has exactly one ACTIVE ES256 key`,
    `SELECT count(*) FROM (SELECT "organizationId" FROM signing_keys WHERE status = 'ACTIVE' AND algorithm = 'ES256'${orgFilter} GROUP BY 1 HAVING count(*) <> 1) x;`,
    `-- expect the number rotated: old keys now ROTATED`,
    `SELECT count(*) FROM signing_keys WHERE status = 'ROTATED' AND "createdAt" < ${cutoff} AND "rotatedAt" > now() - interval '1 hour'${orgFilter};`,
    `-- expect the number rotated: audit entries`,
    `SELECT count(*) FROM audit_logs WHERE action = 'signingKey.rotate' AND "createdAt" > now() - interval '1 hour'${orgFilter};`,
    `-- expect 0: every ACTIVE ES256 key has its SLH-DSA public key`,
    `SELECT count(*) FROM signing_keys WHERE status = 'ACTIVE' AND algorithm = 'ES256' AND "slhdsaPublicKey" IS NULL${orgFilter};`,
    'ROLLBACK;',
  ];
}

async function applyRotation(prisma: PrismaClient, candidates: Candidate[]): Promise<RotationResult> {
  const { config } = await import('../src/lib/config.js');
  if (config.keygen.backend !== 'signer') {
    throw new Error('--apply requires SIGNER_KEYGEN=signer so new keys are generated on the signer');
  }
  const { SigningService, signingKeyRotationEvent } = await import('../src/services/signing.js');
  const { recordAudit, systemAuditContext } = await import('../src/services/audit.js');
  const signingService = new SigningService(prisma);
  return rotateCandidates(candidates, (keyId) =>
    signingService.rotateKeyById(keyId, (tx, rotation) =>
      recordAudit(tx, systemAuditContext('key-rotation'), signingKeyRotationEvent(rotation, 'manual')),
    ),
  );
}

async function main(): Promise<void> {
  const opts = parseCliArgs(process.argv.slice(2));
  const { PrismaClient } = await import('@prisma/client');
  const prisma = new PrismaClient();
  try {
    const candidates = await findCandidates(prisma, opts.orgId, opts.before);
    const orgCount = new Set(candidates.map((c) => c.organizationId)).size;
    console.log(`=== ${opts.apply ? 'APPLY' : 'DRY-RUN (pass --apply to rotate)'} ===`);
    console.log(`cutoff ${opts.before.toISOString()}${opts.orgId ? `, org ${opts.orgId}` : ''}`);
    for (const c of candidates) {
      console.log(`candidate ${c.keyId} org ${c.organizationId} created ${c.createdAt.toISOString()}`);
    }
    console.log(`${candidates.length} candidate keys in ${orgCount} orgs`);

    if (opts.apply && candidates.length > 0) {
      const result = await applyRotation(prisma, candidates);
      for (const r of result.rotated) console.log(`rotated ${r.keyId} -> ${r.newKeyId}`);
      for (const f of result.failed) console.error(`FAILED ${f.keyId}: ${f.error}`);
      console.log(`${result.rotated.length} rotated, ${result.failed.length} failed`);
      if (result.failed.length > 0) process.exitCode = 2;
    }

    console.log('\nVerification (read-only, run with psql after --apply):');
    console.log(verificationQueries(opts.orgId, opts.before).join('\n'));
  } finally {
    await prisma.$disconnect();
  }
}

const isEntryPoint = process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isEntryPoint) {
  main()
    .then(() => process.exit(process.exitCode ?? 0))
    .catch((err) => {
      console.error('rotate-pre-signer-keygen-keys failed:', err instanceof Error ? err.message : err);
      process.exit(1);
    });
}
