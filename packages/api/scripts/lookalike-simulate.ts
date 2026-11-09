/**
 * Lookalike simulation (ADR-0007 D11): runs the lookalike check of this
 * checkout over every URL code's destination in a database and prints the
 * counts and the flagged hosts. Use it before changing the rules or the
 * protected list, to see what a change would flag on real data.
 *
 * Read-only: every query runs in one transaction opened with
 * `SET TRANSACTION READ ONLY`, so Postgres rejects any write; the script
 * stops before reading if the transaction is not read-only. It creates no
 * incidents and calls no verify path (no scans, webhooks or billing).
 *
 * Output: counts (URL codes, active, verified organizations, flagged
 * active and in total), then one line per flagged code: status, token,
 * organization, host, warnings (protected domain, reason, similarity).
 * Hosts only, never full URLs (paths and queries may hold secrets).
 *
 * Usage (DATABASE_URL in the environment, e.g. through an SSH tunnel to a
 * read replica or production):
 *   npm run lookalike:simulate -w packages/api
 *   npm run lookalike:simulate -w packages/api -- --host comtel.gr
 * `--host <domain>` also counts the active codes whose destination is that
 * domain or a subdomain of it, and how many of them are flagged.
 */
import { PrismaClient } from '@prisma/client';
import { DomainService } from '../src/services/domain.js';

/** The whole run is one transaction; a large database needs more than the 5 s default. */
const TRANSACTION_TIMEOUT_MS = 10 * 60_000;

interface Options {
  host: string | null;
}

function parseArgs(argv: string[]): Options {
  const options: Options = { host: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--host' && argv[i + 1]) options.host = argv[++i].toLowerCase();
    else throw new Error(`Unknown argument: ${argv[i]} (usage: lookalike-simulate [--host <domain>])`);
  }
  return options;
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return '(invalid URL)';
  }
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const prisma = new PrismaClient();
  try {
    await prisma.$transaction(
      async (tx) => {
        await tx.$executeRawUnsafe('SET TRANSACTION READ ONLY');
        const [{ transaction_read_only: readOnly }] = await tx.$queryRawUnsafe<Array<{ transaction_read_only: string }>>('SHOW transaction_read_only');
        if (readOnly !== 'on') throw new Error('The transaction is not read-only; stopping before any read');

        const codes = await tx.qRCode.findMany({
          where: { contentType: 'url' },
          select: { token: true, status: true, destinationUrl: true, organizationId: true, organization: { select: { name: true } } },
          orderBy: { createdAt: 'asc' },
        });
        const verifiedOrgs = await tx.organization.count({ where: { domainVerified: true, domain: { not: null } } });
        const service = new DomainService(tx as unknown as PrismaClient);

        let active = 0;
        let flaggedActive = 0;
        let flaggedAll = 0;
        let watchedActive = 0;
        let watchedFlagged = 0;
        const lines: string[] = [];
        for (const code of codes) {
          const host = hostOf(code.destinationUrl);
          const isActive = code.status === 'ACTIVE';
          const watched = options.host !== null && (host === options.host || host.endsWith(`.${options.host}`));
          const result = await service.checkUrlAgainstVerifiedDomains(code.destinationUrl, code.organizationId);
          if (isActive) active++;
          if (isActive && watched) watchedActive++;
          if (!result.isSuspicious) continue;
          flaggedAll++;
          if (isActive) flaggedActive++;
          if (isActive && watched) watchedFlagged++;
          const warnings = result.warnings.map((w) => `${w.domain}:${w.reason}:${w.similarity}`).join(', ');
          lines.push(`FLAG ${code.status} ${code.token} "${code.organization.name}" ${host} ${warnings}`);
        }

        console.log(`URL codes: ${codes.length} (${active} active); verified organizations: ${verifiedOrgs}`);
        console.log(`Flagged: ${flaggedActive} active, ${flaggedAll} in total`);
        if (options.host) console.log(`${options.host}: ${watchedActive} active codes, ${watchedFlagged} flagged`);
        for (const line of lines) console.log(line);
      },
      { timeout: TRANSACTION_TIMEOUT_MS, maxWait: 30_000 },
    );
  } finally {
    await prisma.$disconnect();
  }
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
