/**
 * Re-MAC QR codes whose OrgMacKey version has been rotated away.
 *
 * Run with: npx tsx --env-file=.env scripts/remac-qrcodes.ts [--apply]
 *
 * Why this exists (incident 2026-09-03, token qV2zsVQM):
 *   The cleanup worker rotates each org's MAC key after 90 days, retires the
 *   old version 30 days later, and purges it 7 days after that. The verify
 *   route (AUDIT-FINDING-001) treats a MAC miss as fail-closed, so any QR
 *   minted under a purged key version permanently failed verification with
 *   "This QR code failed signature verification." even though its ECDSA and
 *   Merkle/SLH-DSA legs were intact.
 *
 * The cleanup worker now re-MACs rows at rotation time and refuses to retire
 * a key that still has dependents, so this script is an operational backstop
 * — a manual sweep after incidents or ad-hoc key operations. All logic lives
 * in MacService.remacOrgRows; this is a thin CLI over it.
 *
 * Dry-run by default; pass --apply to write.
 */
import { PrismaClient } from '@prisma/client';
import { MacService } from '../src/services/mac.js';

const isApply = process.argv.includes('--apply');

async function main() {
  const prisma = new PrismaClient();
  let totalUpdated = 0;
  let totalFlagged = 0;

  try {
    const macService = new MacService(prisma);
    const orgIds = await prisma.orgMacKey.findMany({
      distinct: ['organizationId'],
      select: { organizationId: true },
    });
    const orgs = await prisma.organization.findMany({
      where: { id: { in: orgIds.map((o) => o.organizationId) } },
      select: { id: true, name: true },
    });
    const orgNames = new Map(orgs.map((o) => [o.id, o.name]));

    const mode = isApply ? 'APPLIED' : 'DRY-RUN (pass --apply to write)';
    console.log(`=== re-MAC ${mode} ===`);

    for (const { organizationId } of orgIds) {
      const orgName = orgNames.get(organizationId) ?? organizationId;
      const { updated, flagged } = await macService.remacOrgRows(organizationId, {
        dryRun: !isApply,
      });
      for (const r of updated) {
        console.log(
          `${isApply ? 'updated' : 'would update'} ${r.token} (${orgName}) v${r.fromVersion} -> v${r.toVersion} [old MAC: ${r.oldMacCheck}]`,
        );
      }
      for (const f of flagged) {
        console.error(
          `FLAGGED (not touched) ${f.token} (${orgName}) v${f.fromVersion}: stored MAC does not reproduce under surviving key — investigate before re-MACing`,
        );
      }
      totalUpdated += updated.length;
      totalFlagged += flagged.length;
    }

    console.log(`\n${totalUpdated} rows ${isApply ? 'updated' : 'to update'}, ${totalFlagged} flagged`);
    if (totalFlagged > 0) process.exitCode = 2;
  } finally {
    await prisma.$disconnect();
  }
}

main().catch((err) => {
  console.error('remac-qrcodes failed:', err);
  process.exit(1);
});
