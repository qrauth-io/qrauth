/**
 * Dev seed for the analytics dashboard (ADR-0006): 90 days of realistic
 * scans on the demo organization's QR codes, plus a Free-plan organization
 * to see the locked view.
 *
 * Needs the main seed first (`npm run db:seed`): it uses the
 * "Municipality of Thessaloniki" organization (ENTERPRISE,
 * admin@thessaloniki.gr / password123) and its QR codes.
 *
 * Adds a Free organization with free@example.com / password123. QR codes
 * it has (create one in the dashboard, then re-run) get scans too, so its
 * summary shows numbers.
 *
 * Re-runnable: scans it created before (IP hash prefix `seed-analytics-`)
 * are replaced. Rollups for the 90 days are recomputed at the end, as the
 * analytics worker would.
 *
 * Local databases only: refuses unless DATABASE_URL points at localhost.
 *
 *   npm run db:seed:analytics -w packages/api
 */
import { PrismaClient } from '@prisma/client';

import { hashPassword } from '../src/lib/password.js';
import { SigningService } from '../src/services/signing.js';
import { addDays, utcDay, recomputeRollupDay } from '../src/services/scan-analytics.js';

const DEMO_ORG_SLUG = 'municipality-thessaloniki';
const DEMO_EMAIL = 'admin@thessaloniki.gr';
const FREE_ORG_SLUG = 'free-demo';
const FREE_EMAIL = 'free@example.com';
const DEV_PASSWORD = 'password123';
const SEED_HASH_PREFIX = 'seed-analytics-';
const DAYS = 90;
const MAX_CODES = 5;
/** Distinct visitors per code per day; repeats make uniques lower than totals. */
const VISITOR_POOL = 40;
const INSERT_BATCH = 1_000;

interface Weighted<T> {
  readonly value: T;
  readonly weight: number;
}

interface Place {
  readonly country: string;
  readonly region: string;
  readonly city: string;
}

interface Device {
  readonly deviceType: string;
  readonly os: string;
  readonly browser: string;
  readonly userAgent: string;
}

const PLACES: readonly Weighted<Place | null>[] = [
  { value: { country: 'GR', region: 'Central Macedonia', city: 'Thessaloniki' }, weight: 46 },
  { value: { country: 'GR', region: 'Attica', city: 'Athens' }, weight: 14 },
  { value: { country: 'GR', region: 'Crete', city: 'Heraklion' }, weight: 4 },
  { value: { country: 'DE', region: 'Bavaria', city: 'Munich' }, weight: 6 },
  { value: { country: 'DE', region: 'Berlin', city: 'Berlin' }, weight: 4 },
  { value: { country: 'GB', region: 'England', city: 'London' }, weight: 6 },
  { value: { country: 'BG', region: 'Sofia-Capital', city: 'Sofia' }, weight: 4 },
  { value: { country: 'IT', region: 'Lombardy', city: 'Milan' }, weight: 3 },
  { value: { country: 'FR', region: 'Île-de-France', city: 'Paris' }, weight: 3 },
  { value: { country: 'US', region: 'New York', city: 'New York' }, weight: 3 },
  { value: { country: 'CY', region: 'Nicosia', city: 'Nicosia' }, weight: 2 },
  // Scans whose place could not be looked up.
  { value: null, weight: 5 },
];

const DEVICES: readonly Weighted<Device>[] = [
  {
    value: {
      deviceType: 'mobile', os: 'iOS', browser: 'Safari',
      userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1',
    },
    weight: 38,
  },
  {
    value: {
      deviceType: 'mobile', os: 'Android', browser: 'Chrome',
      userAgent: 'Mozilla/5.0 (Linux; Android 15; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36',
    },
    weight: 34,
  },
  {
    value: {
      deviceType: 'mobile', os: 'Android', browser: 'Samsung Internet',
      userAgent: 'Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36',
    },
    weight: 9,
  },
  {
    value: {
      deviceType: 'tablet', os: 'iOS', browser: 'Safari',
      userAgent: 'Mozilla/5.0 (iPad; CPU OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1',
    },
    weight: 4,
  },
  {
    value: {
      deviceType: 'desktop', os: 'Windows', browser: 'Chrome',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    },
    weight: 8,
  },
  {
    value: {
      deviceType: 'desktop', os: 'macOS', browser: 'Firefox',
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.6; rv:132.0) Gecko/20100101 Firefox/132.0',
    },
    weight: 4,
  },
  {
    value: {
      deviceType: 'bot', os: 'Linux', browser: 'Googlebot',
      userAgent: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    },
    weight: 3,
  },
];

/** Deterministic pseudo-random numbers, so re-runs give the same data. */
function createRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function pick<T>(items: readonly Weighted<T>[], random: () => number): T {
  const total = items.reduce((sum, i) => sum + i.weight, 0);
  let roll = random() * total;
  for (const item of items) {
    roll -= item.weight;
    if (roll < 0) return item.value;
  }
  return items[items.length - 1].value;
}

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
    throw new Error('seed-analytics-dev: refusing to run against a non-local database');
  }
}

/** Scans per day for a code: a weekday/weekend rhythm and a slow rise, scaled per code. */
function scansOnDay(dayIndex: number, codeScale: number, random: () => number): number {
  const date = new Date(Date.now() - (DAYS - 1 - dayIndex) * 86_400_000);
  const weekday = date.getUTCDay();
  const weekendFactor = weekday === 0 || weekday === 6 ? 1.5 : 1;
  const trend = 0.6 + (dayIndex / DAYS) * 0.8;
  return Math.round((4 + random() * 10) * weekendFactor * trend * codeScale);
}

async function ensureFreeOrganization(prisma: PrismaClient): Promise<void> {
  const org = await prisma.organization.upsert({
    where: { slug: FREE_ORG_SLUG },
    update: { plan: 'FREE' },
    create: { name: 'Free Demo', slug: FREE_ORG_SLUG, email: FREE_EMAIL, plan: 'FREE' },
  });
  const user = await prisma.user.upsert({
    where: { email: FREE_EMAIL },
    update: {},
    create: {
      name: 'Free Demo',
      email: FREE_EMAIL,
      passwordHash: await hashPassword(DEV_PASSWORD),
      emailVerified: true,
      onboardedAt: new Date(),
    },
  });
  const membership = await prisma.membership.findFirst({
    where: { userId: user.id, organizationId: org.id },
  });
  if (!membership) {
    await prisma.membership.create({ data: { userId: user.id, organizationId: org.id, role: 'OWNER' } });
  }
  // Signup gives every organization a signing key; QR codes cannot be created without one.
  const key = await prisma.signingKey.findFirst({ where: { organizationId: org.id, status: 'ACTIVE' } });
  if (!key) await new SigningService(prisma).createKeyPair(org.id);
  console.log(`Free organization: ${org.slug} (${FREE_EMAIL} / ${DEV_PASSWORD})`);
}

async function main(): Promise<void> {
  assertLocalDatabase();
  const prisma = new PrismaClient();
  try {
    const org = await prisma.organization.findUnique({ where: { slug: DEMO_ORG_SLUG } });
    if (!org) throw new Error(`Run the main seed first: organization ${DEMO_ORG_SLUG} not found`);
    // Skip the onboarding wizard so the dashboard opens directly.
    await prisma.user.updateMany({
      where: { email: { in: [DEMO_EMAIL, FREE_EMAIL] }, onboardedAt: null },
      data: { onboardedAt: new Date() },
    });
    await ensureFreeOrganization(prisma);
    const codes = await prisma.qRCode.findMany({
      where: { organization: { slug: { in: [DEMO_ORG_SLUG, FREE_ORG_SLUG] } } },
      orderBy: { createdAt: 'asc' },
      take: MAX_CODES + 1,
      select: { id: true, token: true },
    });
    if (codes.length === 0) throw new Error('The demo organization has no QR codes');

    const removed = await prisma.scan.deleteMany({
      where: { clientIpHash: { startsWith: SEED_HASH_PREFIX } },
    });
    console.log(`Removed ${removed.count} earlier seeded scans`);

    const random = createRandom(20261101);
    const today = utcDay(new Date());
    const firstDay = addDays(today, -(DAYS - 1));
    const rows = [];
    for (const [codeIndex, code] of codes.entries()) {
      const codeScale = 1.6 / (codeIndex + 1);
      for (let dayIndex = 0; dayIndex < DAYS; dayIndex += 1) {
        const day = addDays(firstDay, dayIndex);
        const count = scansOnDay(dayIndex, codeScale, random);
        for (let i = 0; i < count; i += 1) {
          const place = pick(PLACES, random);
          const device = pick(DEVICES, random);
          const secondOfDay = Math.floor((0.25 + random() * 0.7) * 86_400);
          const createdAt = new Date(Date.parse(`${day}T00:00:00Z`) + secondOfDay * 1000);
          if (createdAt.getTime() > Date.now()) continue;
          rows.push({
            qrCodeId: code.id,
            clientIpHash: `${SEED_HASH_PREFIX}${Math.floor(random() * VISITOR_POOL)}`,
            userAgent: device.userAgent,
            deviceType: device.deviceType,
            os: device.os,
            browser: device.browser,
            country: place?.country ?? null,
            region: place?.region ?? null,
            city: place?.city ?? null,
            trustScore: device.deviceType === 'bot' ? 35 : 80 + Math.floor(random() * 21),
            createdAt,
          });
        }
      }
    }
    for (let i = 0; i < rows.length; i += INSERT_BATCH) {
      await prisma.scan.createMany({ data: rows.slice(i, i + INSERT_BATCH) });
    }
    console.log(`Inserted ${rows.length} scans on ${codes.map((c) => c.token).join(', ')}`);

    for (let dayIndex = 0; dayIndex < DAYS; dayIndex += 1) {
      await recomputeRollupDay(prisma, addDays(firstDay, dayIndex));
    }
    console.log(`Recomputed rollups ${firstDay} to ${today}`);
  } finally {
    await prisma.$disconnect();
  }
}

// Importing the signing service opens queue connections that keep Node
// alive; exit explicitly once the work is done.
main().then(
  () => process.exit(0),
  (err: unknown) => {
    console.error(err);
    process.exit(1);
  }
);
