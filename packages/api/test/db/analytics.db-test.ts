/**
 * Scan analytics against a real Postgres (ADR-0006): rollups match raw
 * counts, the live and rollup read paths agree, tenants never see each
 * other's scans, the CSV export streams in batches, and retention removes
 * what D5 says. Run by scripts/ci-verify.sh `db` (TEST_DATABASE_URL).
 */
import { PrismaClient } from '@prisma/client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { parseScanDevice } from '../../src/lib/scan-device.js';
import {
  addDays,
  anonymiseExpiredScans,
  backfillAnalytics,
  breakdown,
  dailySeries,
  heatmap,
  purgeExpiredRollups,
  recomputeRollupDay,
  timeSeries,
  utcDay,
  type BreakdownDimension,
} from '../../src/services/scan-analytics.js';
import { scanCsvLines } from '../../src/services/scan-export.js';

const url = process.env.TEST_DATABASE_URL;
if (!url) throw new Error('TEST_DATABASE_URL is not set');
if (!/test/i.test(new URL(url).pathname)) throw new Error('TEST_DATABASE_URL must name a test database (the suite truncates tables)');

const db = new PrismaClient({ datasources: { db: { url } } });

/** "Now" for the suite: 2026-06-15 12:00 UTC. Yesterday and today are read live. */
const NOW = new Date('2026-06-15T12:00:00.000Z');
const TODAY = utcDay(NOW);
const IPHONE = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1';
const WINDOWS = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';

interface SeedScan {
  code: 'A1' | 'A2' | 'B1';
  at: string;
  hash: string;
  country?: string;
  region?: string;
  city?: string;
  ua?: string;
  lat?: number;
  lng?: number;
}

/** Scans over six days, with day-boundary times, repeated hashes, missing place and an anonymised hash. */
const SEED: SeedScan[] = [];
function seed(): void {
  const places = [
    { country: 'GR', region: 'Attica', city: 'Athens' },
    { country: 'GR', region: 'Central Macedonia', city: 'Thessaloniki' },
    { country: 'DE', region: 'Berlin', city: 'Berlin' },
    {},
  ];
  for (let d = 5; d >= 0; d--) {
    const day = addDays(TODAY, -d);
    const times = ['00:00:00.000', '06:30:00.000', '11:59:59.999', '23:59:59.999'];
    times.forEach((t, i) => {
      if (d === 0 && t > '12') return; // nothing after "now"
      const place = places[(d + i) % places.length];
      SEED.push({ code: 'A1', at: `${day}T${t}Z`, hash: `h${(d + i) % 3}`, ...place, ua: i % 2 ? WINDOWS : IPHONE, lat: 37.9838 + i * 0.0001, lng: 23.7275 });
      if (i % 2 === 0) SEED.push({ code: 'A2', at: `${day}T${t}Z`, hash: `h${i}`, ...place, ua: IPHONE });
      SEED.push({ code: 'B1', at: `${day}T${t}Z`, hash: `b${i}`, country: 'JP', region: 'Tokyo', city: 'Tokyo', ua: WINDOWS });
    });
  }
  SEED.push({ code: 'A1', at: `${addDays(TODAY, -3)}T08:00:00.000Z`, hash: 'anonymized', country: 'GR' });
}
seed();

const ids: Record<string, { id: string; org: string; token: string }> = {};

async function reset(): Promise<void> {
  await db.$executeRawUnsafe('TRUNCATE "organizations" CASCADE');
  for (const org of ['A', 'B']) {
    const o = await db.organization.create({ data: { name: `Org ${org}`, slug: `org-${org.toLowerCase()}-test`, email: `${org}@example.test` } });
    const key = await db.signingKey.create({ data: { organizationId: o.id, publicKey: 'pk', keyId: `key-${org}-${o.id}` } });
    for (const code of org === 'A' ? ['A1', 'A2'] : ['B1']) {
      const q = await db.qRCode.create({
        data: { token: `tok${code}`, organizationId: o.id, signingKeyId: key.id, destinationUrl: 'https://example.test', signature: 'sig', algVersion: 'test', label: `Code ${code}` },
      });
      ids[code] = { id: q.id, org: o.id, token: q.token };
    }
  }
  await db.scan.createMany({
    data: SEED.map((s) => ({
      qrCodeId: ids[s.code].id,
      clientIpHash: s.hash,
      createdAt: new Date(s.at),
      country: s.country ?? null,
      region: s.region ?? null,
      city: s.city ?? null,
      userAgent: s.ua ?? null,
      clientLat: s.lat ?? null,
      clientLng: s.lng ?? null,
      ...parseScanDevice(s.ua),
    })),
  });
}

/** Expected rollup values for (code, day), computed in TypeScript from the seed. */
function expected(code: string, day: string) {
  const rows = SEED.filter((s) => s.code === code && s.at.startsWith(day));
  const count = (key: (s: SeedScan) => string) =>
    rows.reduce<Record<string, number>>((m, s) => ({ ...m, [key(s)]: (m[key(s)] ?? 0) + 1 }), {});
  return {
    total: rows.length,
    unique: new Set(rows.filter((s) => s.hash !== 'anonymized').map((s) => s.hash)).size,
    byCountry: count((s) => s.country ?? 'unknown'),
    byCity: count((s) => (s.country && s.city ? `${s.country}|${s.city}` : 'unknown')),
    byDeviceType: count((s) => parseScanDevice(s.ua).deviceType ?? 'unknown'),
    byOs: count((s) => parseScanDevice(s.ua).os ?? 'unknown'),
    byBrowser: count((s) => parseScanDevice(s.ua).browser ?? 'unknown'),
  };
}

const DAYS = Array.from({ length: 6 }, (_, i) => addDays(TODAY, i - 5));

async function rollupAll(): Promise<void> {
  for (const day of DAYS) await recomputeRollupDay(db, day);
}

beforeAll(async () => {
  await db.$connect();
});

afterAll(async () => {
  await db.$executeRawUnsafe('TRUNCATE "organizations" CASCADE');
  await db.$disconnect();
});

beforeEach(reset);

describe('rollups', () => {
  it('match raw counts for every code and day: totals, uniques and every dimension', async () => {
    await rollupAll();
    const rows = await db.scanDailyRollup.findMany();
    expect(rows.length).toBe(DAYS.length * 3);
    for (const r of rows) {
      const code = Object.keys(ids).find((k) => ids[k].id === r.qrCodeId)!;
      const day = utcDay(r.day);
      expect(r.organizationId).toBe(ids[code].org);
      const e = expected(code, day);
      expect({ total: r.total, unique: r.unique }, `${code} ${day}`).toEqual({ total: e.total, unique: e.unique });
      expect(r.byCountry).toEqual(e.byCountry);
      expect(r.byCity).toEqual(e.byCity);
      expect(r.byDeviceType).toEqual(e.byDeviceType);
      expect(r.byOs).toEqual(e.byOs);
      expect(r.byBrowser).toEqual(e.byBrowser);
    }
  });

  it('are idempotent and drop the row of a code with no scans left that day', async () => {
    await rollupAll();
    await rollupAll();
    expect(await db.scanDailyRollup.count()).toBe(DAYS.length * 3);
    const day = addDays(TODAY, -3);
    await db.scan.deleteMany({ where: { qrCodeId: ids.A2.id, createdAt: { gte: new Date(`${day}T00:00:00Z`), lt: new Date(`${addDays(day, 1)}T00:00:00Z`) } } });
    await recomputeRollupDay(db, day);
    expect(await db.scanDailyRollup.findUnique({ where: { qrCodeId_day: { qrCodeId: ids.A2.id, day: new Date(`${day}T00:00:00Z`) } } })).toBeNull();
  });
});

describe('reads', () => {
  function expectedSeries(codes: string[], days: string[]) {
    return days.map((date) => ({
      date,
      total: codes.reduce((n, c) => n + expected(c, date).total, 0),
      unique: codes.reduce((n, c) => n + expected(c, date).unique, 0),
    }));
  }

  it('daily series equals raw counts: rollups before yesterday, raw scans for yesterday and today', async () => {
    await rollupAll();
    const series = await dailySeries(db, { organizationId: ids.A1.org }, { from: DAYS[0], to: TODAY }, NOW);
    expect(series).toEqual(expectedSeries(['A1', 'A2'], DAYS));
  });

  it('the last two days are exact even when their rollups are stale or missing', async () => {
    for (const day of DAYS.slice(0, 4)) await recomputeRollupDay(db, day);
    const series = await dailySeries(db, { organizationId: ids.A1.org }, { from: DAYS[0], to: TODAY }, NOW);
    expect(series).toEqual(expectedSeries(['A1', 'A2'], DAYS));
  });

  it('per-code series and weekly sums', async () => {
    await rollupAll();
    const code = await dailySeries(db, { organizationId: ids.A1.org, qrCodeId: ids.A2.id }, { from: DAYS[0], to: TODAY }, NOW);
    expect(code).toEqual(expectedSeries(['A2'], DAYS));
    const weeks = await timeSeries(db, { organizationId: ids.A1.org }, { from: DAYS[0], to: TODAY }, 'week', NOW);
    const all = expectedSeries(['A1', 'A2'], DAYS);
    expect(weeks.reduce((n, w) => n + w.total, 0)).toBe(all.reduce((n, d) => n + d.total, 0));
    expect(weeks.every((w) => new Date(`${w.date}T00:00:00Z`).getUTCDay() === 1)).toBe(true);
  });

  it.each(['country', 'city', 'deviceType', 'os', 'browser'] as BreakdownDimension[])('%s breakdown equals raw counts', async (dimension) => {
    await rollupAll();
    const result = await breakdown(db, { organizationId: ids.A1.org }, { from: DAYS[0], to: TODAY }, dimension, NOW);
    const key = { country: 'byCountry', city: 'byCity', deviceType: 'byDeviceType', os: 'byOs', browser: 'byBrowser' }[dimension] as 'byCountry';
    const want: Record<string, number> = {};
    for (const c of ['A1', 'A2']) for (const d of DAYS) for (const [k, n] of Object.entries(expected(c, d)[key])) want[k] = (want[k] ?? 0) + n;
    expect(Object.fromEntries(result.items.map((i) => [i.key, i.count]))).toEqual(want);
    expect(result.total).toBe(SEED.filter((s) => s.code !== 'B1').length);
    expect(result.other).toBe(0);
  });

  it('keeps tenants apart: org A never sees org B scans', async () => {
    await rollupAll();
    const countries = await breakdown(db, { organizationId: ids.A1.org }, { from: DAYS[0], to: TODAY }, 'country', NOW);
    expect(countries.items.map((i) => i.key)).not.toContain('JP');
    const b = await dailySeries(db, { organizationId: ids.B1.org }, { from: DAYS[0], to: TODAY }, NOW);
    expect(b).toEqual(expectedSeries(['B1'], DAYS));
    // A code id of another organisation in the scope matches nothing.
    const crossed = await dailySeries(db, { organizationId: ids.A1.org, qrCodeId: ids.B1.id }, { from: DAYS[0], to: TODAY }, NOW);
    expect(crossed.every((p) => p.total === 0)).toBe(true);
  });

  it('heatmap groups GPS scans in SQL, organisation-scoped', async () => {
    const buckets = await heatmap(db, ids.A1.org);
    expect(buckets.reduce((n, b) => n + b.count, 0)).toBe(SEED.filter((s) => s.code !== 'B1' && s.lat !== undefined).length);
    expect(buckets.every((b) => Number.isFinite(b.lat) && Number.isFinite(b.lng))).toBe(true);
    expect(await heatmap(db, ids.B1.org)).toEqual([]);
  });
});

describe('CSV export', () => {
  it('streams every scan of the organisation in order, in batches, without hashes', async () => {
    const lines: string[] = [];
    for await (const line of scanCsvLines(db, { organizationId: ids.A1.org }, { from: DAYS[0], to: TODAY }, 3)) lines.push(line);
    const own = SEED.filter((s) => s.code !== 'B1');
    expect(lines[0]).toBe('scanned_at,code,label,country,region,city,device_type,os,browser,trust_score\r\n');
    expect(lines.length).toBe(own.length + 1);
    const times = lines.slice(1).map((l) => l.split(',')[0]);
    expect([...times].sort()).toEqual(times);
    expect(lines.join('')).not.toMatch(/tokB1|JP|\bh\d\b|anonymized/);
  });

  it('respects the code and the range', async () => {
    const lines: string[] = [];
    for await (const line of scanCsvLines(db, { organizationId: ids.A1.org, qrCodeId: ids.A2.id }, { from: TODAY, to: TODAY }, 2)) lines.push(line);
    expect(lines.length - 1).toBe(SEED.filter((s) => s.code === 'A2' && s.at.startsWith(TODAY)).length);
    expect(lines.slice(1).every((l) => l.includes(',tokA2,'))).toBe(true);
  });
});

describe('backfill and retention', () => {
  it('backfill fills device fields from the stored user agent and rolls up the window', async () => {
    await db.scan.updateMany({ data: { deviceType: null, os: null, browser: null } });
    const result = await backfillAnalytics(db, parseScanDevice, NOW);
    expect(result.scansEnriched).toBe(SEED.filter((s) => s.ua).length);
    expect(result.days).toBe(365);
    const series = await dailySeries(db, { organizationId: ids.A1.org }, { from: DAYS[0], to: addDays(TODAY, -2) }, NOW);
    expect(series.reduce((n, p) => n + p.total, 0)).toBe(SEED.filter((s) => s.code !== 'B1' && s.at < `${addDays(TODAY, -1)}`).length);
  });

  it('anonymises scans older than 365 days: hash, user agent, region and city go; country and device stay', async () => {
    const later = new Date(NOW.getTime() + 368 * 24 * 60 * 60 * 1000);
    const changed = await anonymiseExpiredScans(db, later);
    const cutoff = new Date(later.getTime() - 365 * 24 * 60 * 60 * 1000);
    // Rows already anonymised with no region or city are left alone.
    const alreadyDone = (s: SeedScan) => s.hash === 'anonymized' && !s.region && !s.city;
    expect(changed).toBe(SEED.filter((s) => new Date(s.at) < cutoff && !alreadyDone(s)).length);
    const old = await db.scan.findFirst({ where: { qrCodeId: ids.A1.id, createdAt: new Date(`${DAYS[0]}T06:30:00.000Z`) } });
    expect(old).toMatchObject({ clientIpHash: 'anonymized', userAgent: null, region: null, city: null });
    expect(old?.country).not.toBeNull();
    expect(old?.deviceType).not.toBeNull();
    expect(await anonymiseExpiredScans(db, later)).toBe(0);
  });

  it('deletes rollup rows older than 365 days and keeps the rest', async () => {
    await rollupAll();
    const later = new Date(`${addDays(DAYS[2], 364)}T12:00:00Z`);
    const deleted = await purgeExpiredRollups(db, later);
    expect(deleted).toBe(2 * 3);
    expect(await db.scanDailyRollup.count()).toBe((DAYS.length - 2) * 3);
  });
});
