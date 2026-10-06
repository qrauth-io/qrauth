/**
 * Remove the Phase 1 internal OIDC test client (ADR-0003 Slice 3b.2).
 *
 * Companion to seed-phase1-test-client.ts — gives a clean revert path.
 * Idempotent: no error if the client is already absent.
 *
 *   npm run oidc:teardown-test-client -w packages/api
 */

import { PrismaClient } from '@prisma/client';

const CLIENT_ID = 'phase1-test-client';

async function main(): Promise<void> {
  const prisma = new PrismaClient({ log: [{ level: 'warn', emit: 'stdout' }] });
  try {
    const { count } = await prisma.oidcClient.deleteMany({ where: { clientId: CLIENT_ID } });
    console.log(
      count > 0
        ? `Removed OIDC test client "${CLIENT_ID}".`
        : `OIDC test client "${CLIENT_ID}" not present. No action.`,
    );
  } finally {
    await prisma.$disconnect();
  }
}

main().catch((err) => {
  console.error('[teardown-phase1-test-client] FAILED:', err instanceof Error ? err.message : err);
  process.exit(1);
});
