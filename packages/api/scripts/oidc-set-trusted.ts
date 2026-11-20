/**
 * Operator script: mark a self-serve OIDC client as vetted ("trusted"), or
 * take that back (audit 2026-10 FINDING-002).
 *
 * The OP asks the user for consent before it issues anything to a client
 * registered through the dashboard. A client the operator has vetted — a
 * pilot customer under contract, QRAuth's own apps — may skip that page.
 * The decision lives in `oidc_clients.consentRequired`, which the self-serve
 * API can neither set nor read: this script is the only way to change it.
 *
 *   --trusted true   → consentRequired = false (no consent page)
 *   --trusted false  → consentRequired = true  (consent page again; users'
 *                      earlier answers, if any, still apply)
 *
 * FIRST_PARTY clients are refused: they never ask for consent and the flag
 * means nothing for them.
 *
 * Every change writes an audit row in the client's organization. AuditLog
 * needs a user id and an operator has none, so the row carries the
 * organization OWNER's id and the metadata says who actually acted
 * (actor "operator", unix user, host, script). The change and the audit row
 * are one transaction. Running it again with the same value changes nothing
 * and writes nothing.
 *
 * Usage (MANUAL ONLY, never wired into migrations/seed/CI):
 *   npm run oidc:set-trusted -w packages/api -- --client-id <id> --trusted true|false [--dry-run]
 */

import { hostname, userInfo } from 'node:os';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { PrismaClient } from '@prisma/client';

const AUDIT_ACTION = 'oidcClient.trust_set_by_operator';
const VIA = 'scripts/oidc-set-trusted.ts';

export class SetTrustedError extends Error {}

export interface SetTrustedOptions {
  clientId: string;
  trusted: boolean;
  dryRun: boolean;
}

export interface SetTrustedResult {
  clientId: string;
  dryRun: boolean;
  /** False when the client already had the requested value. */
  changed: boolean;
  previousConsentRequired: boolean;
  consentRequired: boolean;
}

export function parseCliArgs(argv: string[]): SetTrustedOptions {
  let values;
  try {
    ({ values } = parseArgs({
      args: argv,
      strict: true,
      allowPositionals: false,
      options: {
        'client-id': { type: 'string' },
        trusted: { type: 'string' },
        'dry-run': { type: 'boolean', default: false },
      },
    }));
  } catch (err) {
    throw new SetTrustedError(err instanceof Error ? err.message : String(err));
  }

  const clientId = values['client-id']?.trim();
  if (!clientId) throw new SetTrustedError('--client-id is required.');
  if (values.trusted !== 'true' && values.trusted !== 'false') {
    throw new SetTrustedError(`--trusted must be "true" or "false" (got "${values.trusted ?? ''}").`);
  }

  return { clientId, trusted: values.trusted === 'true', dryRun: values['dry-run'] ?? false };
}

export async function setClientTrusted(
  prisma: PrismaClient,
  opts: SetTrustedOptions,
): Promise<SetTrustedResult> {
  const client = await prisma.oidcClient.findUnique({
    where: { clientId: opts.clientId },
    select: { id: true, clientId: true, tier: true, consentRequired: true, organizationId: true },
  });
  if (!client) throw new SetTrustedError(`No OIDC client with client id "${opts.clientId}".`);
  if (client.tier === 'FIRST_PARTY') {
    throw new SetTrustedError(
      `Client "${opts.clientId}" is FIRST_PARTY: it never asks for consent, so there is nothing to set.`,
    );
  }

  const consentRequired = !opts.trusted;
  const result: SetTrustedResult = {
    clientId: client.clientId,
    dryRun: opts.dryRun,
    changed: client.consentRequired !== consentRequired,
    previousConsentRequired: client.consentRequired,
    consentRequired,
  };
  if (!result.changed) return result;

  // The audit row must name a user; the organization's longest-standing
  // OWNER stands in. No owner means no audit row, so no change either.
  const owner = await prisma.membership.findFirst({
    where: { organizationId: client.organizationId, role: 'OWNER' },
    orderBy: { joinedAt: 'asc' },
    select: { userId: true },
  });
  if (!owner) {
    throw new SetTrustedError(
      `The organization that owns "${opts.clientId}" has no OWNER to attribute the audit row to; nothing was changed.`,
    );
  }
  if (opts.dryRun) return result;

  await prisma.$transaction([
    prisma.oidcClient.update({ where: { id: client.id }, data: { consentRequired } }),
    prisma.auditLog.create({
      data: {
        organizationId: client.organizationId,
        userId: owner.userId,
        action: AUDIT_ACTION,
        resource: 'OidcClient',
        resourceId: client.id,
        metadata: {
          actor: 'operator',
          operator: userInfo().username,
          host: hostname(),
          via: VIA,
          clientId: client.clientId,
          previousConsentRequired: client.consentRequired,
          consentRequired,
        },
        ipAddress: null,
      },
    }),
  ]);

  return result;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function printResult(result: SetTrustedResult): void {
  const describe = (required: boolean) => (required ? 'consent required' : 'trusted (no consent page)');
  if (!result.changed) {
    console.log(`${result.clientId}: already ${describe(result.consentRequired)}. Nothing changed.`);
    return;
  }
  const prefix = result.dryRun ? 'DRY RUN, nothing written. Would change' : 'Changed';
  console.log(
    `${prefix} ${result.clientId}: ${describe(result.previousConsentRequired)} -> ${describe(result.consentRequired)}.`,
  );
}

async function main(): Promise<void> {
  const opts = parseCliArgs(process.argv.slice(2));
  // No Redis/BullMQ is imported on this path, so disconnecting Prisma is
  // enough for the process to exit on its own.
  const prisma = new PrismaClient({ log: [{ level: 'warn', emit: 'stdout' }] });
  try {
    printResult(await setClientTrusted(prisma, opts));
  } finally {
    await prisma.$disconnect();
  }
}

const isEntryPoint = process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;

if (isEntryPoint) {
  main().catch((err) => {
    console.error('[oidc-set-trusted] FAILED:', err instanceof Error ? err.message : err);
    process.exitCode = 1;
  });
}
