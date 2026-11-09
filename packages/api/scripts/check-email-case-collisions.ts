/**
 * Report users whose email differs from another user's only by case
 * (audit 2026-10 FINDING-001). New addresses are stored lowercased; this
 * lists rows created before that, which need a manual decision before any
 * migration lowercases `users.email`.
 *
 * READ-ONLY: runs two SELECTs, writes nothing. Prints user ids and counts
 * only — never an email address.
 *
 *   npx tsx --env-file=.env scripts/check-email-case-collisions.ts
 *
 * Exit code: 0 when there are no collisions, 2 when there are.
 */

import { PrismaClient } from '@prisma/client';

interface CollisionGroup {
  ids: string[];
}

async function main(): Promise<void> {
  const prisma = new PrismaClient({ log: [{ level: 'warn', emit: 'stdout' }] });
  try {
    const groups = await prisma.$queryRaw<CollisionGroup[]>`
      SELECT array_agg(id ORDER BY "createdAt") AS ids
      FROM users
      GROUP BY lower(email)
      HAVING count(*) > 1
    `;
    const [{ count: mixedCase }] = await prisma.$queryRaw<Array<{ count: bigint }>>`
      SELECT count(*) AS count FROM users WHERE email <> lower(btrim(email))
    `;

    console.log(`Rows not stored in canonical form (lowercase, trimmed): ${mixedCase}`);
    console.log(`Case-insensitive duplicate groups: ${groups.length}`);
    groups.forEach((group, index) => {
      console.log(`  group ${index + 1}: ${group.ids.length} users: ${group.ids.join(', ')}`);
    });

    if (groups.length > 0) process.exitCode = 2;
  } finally {
    await prisma.$disconnect();
  }
}

main().catch((err) => {
  console.error('[check-email-case-collisions] FAILED:', err instanceof Error ? err.message : err);
  process.exit(1);
});
