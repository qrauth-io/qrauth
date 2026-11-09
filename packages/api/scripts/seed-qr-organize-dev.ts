/**
 * Dev seed for search, tags and folders (Milestone 1).
 *
 * Needs the main seed first (`npm run db:seed`): it uses the
 * "Municipality of Thessaloniki" organization (admin@thessaloniki.gr /
 * password123) and its QR codes.
 *
 * Adds to that organization:
 *   - tags (one per palette colour family) and folders,
 *   - tags and folders on its existing codes,
 *   - 10,000 extra codes for search at volume (labels, hosts, content types
 *     and statuses vary; their signatures are placeholders, so they never
 *     verify), about a quarter tagged and a fifth in folders,
 *   - a VIEWER member, viewer@thessaloniki.gr / password123, to see the
 *     read-only view.
 *
 * Re-runnable: rows it created before (tokens starting `seedvol`, its tag
 * and folder names) are replaced. `--codes N` changes the volume (0 skips).
 *
 * Local databases only: refuses unless DATABASE_URL points at localhost.
 *
 *   npm run db:seed:organize -w packages/api
 */
import { PrismaClient } from '@prisma/client';

import { hashPassword } from '../src/lib/password.js';
import { seedQrVolume } from './qr-volume-seed.js';

const DEMO_ORG_SLUG = 'municipality-thessaloniki';
const DEMO_EMAIL = 'admin@thessaloniki.gr';
const VIEWER_EMAIL = 'viewer@thessaloniki.gr';
const DEV_PASSWORD = 'password123';
const TOKEN_PREFIX = 'seedvol';
const DEFAULT_CODES = 10_000;

const TAGS = [
  { name: 'Summer campaign', color: 'orange' },
  { name: 'Print', color: 'blue' },
  { name: 'Events', color: 'purple' },
  { name: 'Parking', color: 'teal' },
  { name: 'Review', color: 'red' },
] as const;
const FOLDERS = ['Town hall', 'Museums', 'Transport', 'Festivals'] as const;

function assertLocalDatabase(): void {
  const url = process.env.DATABASE_URL ?? '';
  const host = (() => {
    try {
      return new URL(url).hostname;
    } catch {
      return '';
    }
  })();
  if (process.env.NODE_ENV === 'production' || !['localhost', '127.0.0.1', '::1'].includes(host)) {
    throw new Error('seed-qr-organize-dev: refusing to run against a non-local database');
  }
}

function codeCount(): number {
  const i = process.argv.indexOf('--codes');
  if (i === -1) return DEFAULT_CODES;
  const n = Number(process.argv[i + 1]);
  if (!Number.isInteger(n) || n < 0 || n > 100_000) throw new Error('--codes takes an integer from 0 to 100000');
  return n;
}

async function ensureViewer(prisma: PrismaClient, orgId: string): Promise<void> {
  const user = await prisma.user.upsert({
    where: { email: VIEWER_EMAIL },
    update: {},
    create: {
      name: 'Read-only Viewer',
      email: VIEWER_EMAIL,
      passwordHash: await hashPassword(DEV_PASSWORD),
      emailVerified: true,
      onboardedAt: new Date(),
    },
  });
  const membership = await prisma.membership.findFirst({ where: { userId: user.id, organizationId: orgId } });
  if (!membership) await prisma.membership.create({ data: { userId: user.id, organizationId: orgId, role: 'VIEWER' } });
}

async function main(): Promise<void> {
  assertLocalDatabase();
  const count = codeCount();
  const prisma = new PrismaClient();
  try {
    const org = await prisma.organization.findUnique({ where: { slug: DEMO_ORG_SLUG } });
    if (!org) throw new Error(`Run the main seed first: organization ${DEMO_ORG_SLUG} not found`);
    const key = await prisma.signingKey.findFirst({ where: { organizationId: org.id, status: 'ACTIVE' } });
    if (!key) throw new Error(`Organization ${DEMO_ORG_SLUG} has no active signing key`);

    await prisma.user.updateMany({ where: { email: DEMO_EMAIL, onboardedAt: null }, data: { onboardedAt: new Date() } });
    await ensureViewer(prisma, org.id);

    // Replace what an earlier run created.
    await prisma.qRCode.deleteMany({ where: { organizationId: org.id, token: { startsWith: TOKEN_PREFIX } } });
    await prisma.tag.deleteMany({ where: { organizationId: org.id, name: { in: TAGS.map((t) => t.name) } } });
    await prisma.qRFolder.deleteMany({ where: { organizationId: org.id, name: { in: [...FOLDERS] } } });

    if (count > 0) {
      await seedQrVolume(prisma, { orgId: org.id, signingKeyId: key.id, count, tokenPrefix: TOKEN_PREFIX });
    }

    const tags = await Promise.all(
      TAGS.map((t) => prisma.tag.create({ data: { organizationId: org.id, name: t.name, color: t.color } })),
    );
    const folders = await Promise.all(
      FOLDERS.map((name) => prisma.qRFolder.create({ data: { organizationId: org.id, name } })),
    );
    const tagIds = tags.map((t) => t.id);
    const folderIds = folders.map((f) => f.id);

    // About a quarter of the codes get a tag, a fifth go into a folder.
    await prisma.$executeRaw`
      INSERT INTO "qr_code_tags" ("qrCodeId", "tagId")
      SELECT q."id", (${tagIds}::text[])[1 + abs(hashtext(q."id")) % ${tagIds.length}]
      FROM "qr_codes" q
      WHERE q."organizationId" = ${org.id} AND abs(hashtext(q."id" || 't')) % 4 = 0
      ON CONFLICT DO NOTHING`;
    await prisma.$executeRaw`
      UPDATE "qr_codes" SET "folderId" = (${folderIds}::text[])[1 + abs(hashtext("id")) % ${folderIds.length}]
      WHERE "organizationId" = ${org.id} AND abs(hashtext("id" || 'f')) % 5 = 0`;
    await prisma.$executeRawUnsafe('ANALYZE "qr_codes"');

    const total = await prisma.qRCode.count({ where: { organizationId: org.id } });
    console.log(`${org.slug}: ${total} QR codes, ${tags.length} tags, ${folders.length} folders`);
    console.log(`Sign in as ${DEMO_EMAIL} / ${DEV_PASSWORD} (owner) or ${VIEWER_EMAIL} / ${DEV_PASSWORD} (viewer)`);
  } finally {
    await prisma.$disconnect();
  }
  // Imported modules can hold open handles; end explicitly once the work is done.
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
