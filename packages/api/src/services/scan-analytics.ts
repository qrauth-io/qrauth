/**
 * Scan analytics (ADR-0006): daily rollups and the queries that read them.
 *
 * Days are UTC. `scan_daily_rollups` holds one row per code and day, with
 * totals, the distinct keyed IP hashes (unique), and count maps per
 * dimension. Reads take days before yesterday from the rollups and
 * yesterday and today from raw scans, so the last 24 hours are exact even
 * between rollup runs (D3).
 */
import { Prisma, type PrismaClient } from '@prisma/client';

export const DAY_MS = 24 * 60 * 60 * 1000;
/** Ranges reach back this many days, today included (D5 retention). */
export const ANALYTICS_RETENTION_DAYS = 365;
/** Days read from raw scans: yesterday and today. */
export const LIVE_DAYS = 2;
/** Breakdown rows returned; the rest are summed into `other`. */
export const BREAKDOWN_LIMIT = 50;
/** Heatmap buckets returned, largest first. */
export const HEATMAP_BUCKET_LIMIT = 5000;
export const UNKNOWN = 'unknown';
/** Stored instead of the hash after the 365-day anonymisation. */
const ANONYMIZED_HASH = 'anonymized';

export const BREAKDOWN_DIMENSIONS = ['country', 'city', 'deviceType', 'os', 'browser'] as const;
export type BreakdownDimension = (typeof BREAKDOWN_DIMENSIONS)[number];
export type Granularity = 'day' | 'week';

/** The rollup column and the raw-scan expression for each dimension (fixed SQL, never user input). */
const DIMENSION_SQL: Record<BreakdownDimension, { column: Prisma.Sql; raw: Prisma.Sql }> = {
  country: { column: Prisma.raw('"byCountry"'), raw: Prisma.raw(`COALESCE(s."country", '${UNKNOWN}')`) },
  city: {
    column: Prisma.raw('"byCity"'),
    raw: Prisma.raw(`CASE WHEN s."country" IS NULL OR s."city" IS NULL THEN '${UNKNOWN}' ELSE s."country" || '|' || s."city" END`),
  },
  deviceType: { column: Prisma.raw('"byDeviceType"'), raw: Prisma.raw(`COALESCE(s."deviceType", '${UNKNOWN}')`) },
  os: { column: Prisma.raw('"byOs"'), raw: Prisma.raw(`COALESCE(s."os", '${UNKNOWN}')`) },
  browser: { column: Prisma.raw('"byBrowser"'), raw: Prisma.raw(`COALESCE(s."browser", '${UNKNOWN}')`) },
};

// ---------------------------------------------------------------------------
// UTC day helpers
// ---------------------------------------------------------------------------

/** `YYYY-MM-DD` of a date in UTC. */
export function utcDay(date: Date): string {
  return date.toISOString().slice(0, 10);
}

/** Midnight UTC of a `YYYY-MM-DD` day. */
export function dayStart(day: string): Date {
  return new Date(`${day}T00:00:00.000Z`);
}

export function addDays(day: string, days: number): string {
  return utcDay(new Date(dayStart(day).getTime() + days * DAY_MS));
}

/** Every day from `from` to `to`, both included. */
export function daysBetween(from: string, to: string): string[] {
  const out: string[] = [];
  for (let d = from; d <= to; d = addDays(d, 1)) out.push(d);
  return out;
}

/** Monday (UTC) of the ISO week containing `day`. */
export function weekStart(day: string): string {
  const weekday = (dayStart(day).getUTCDay() + 6) % 7; // Monday 0 .. Sunday 6
  return addDays(day, -weekday);
}

// ---------------------------------------------------------------------------
// Rollup maintenance
// ---------------------------------------------------------------------------

/**
 * Recomputes the rollup rows of one UTC day from raw scans: upserts a row
 * for every code scanned that day and deletes rows of codes that no longer
 * have scans on it. Idempotent. Returns the number of rows written.
 */
export async function recomputeRollupDay(db: PrismaClient, day: string): Promise<number> {
  const start = dayStart(day);
  const end = dayStart(addDays(day, 1));
  return db.$transaction(async (tx) => {
    const written = await tx.$executeRaw`
      WITH day_scans AS (
        SELECT s."qrCodeId", q."organizationId", s."clientIpHash",
               ${DIMENSION_SQL.country.raw} AS country,
               ${DIMENSION_SQL.city.raw} AS city,
               ${DIMENSION_SQL.deviceType.raw} AS device,
               ${DIMENSION_SQL.os.raw} AS os,
               ${DIMENSION_SQL.browser.raw} AS browser
        FROM "scans" s
        JOIN "qr_codes" q ON q."id" = s."qrCodeId"
        WHERE s."createdAt" >= ${start} AND s."createdAt" < ${end}
      ),
      totals AS (
        SELECT "qrCodeId", "organizationId", COUNT(*)::int AS total,
               COUNT(DISTINCT "clientIpHash") FILTER (WHERE "clientIpHash" <> ${ANONYMIZED_HASH})::int AS uniq
        FROM day_scans GROUP BY "qrCodeId", "organizationId"
      ),
      by_country AS (SELECT "qrCodeId", jsonb_object_agg(k, n) AS m FROM (SELECT "qrCodeId", country AS k, COUNT(*) AS n FROM day_scans GROUP BY 1, 2) x GROUP BY 1),
      by_city    AS (SELECT "qrCodeId", jsonb_object_agg(k, n) AS m FROM (SELECT "qrCodeId", city    AS k, COUNT(*) AS n FROM day_scans GROUP BY 1, 2) x GROUP BY 1),
      by_device  AS (SELECT "qrCodeId", jsonb_object_agg(k, n) AS m FROM (SELECT "qrCodeId", device  AS k, COUNT(*) AS n FROM day_scans GROUP BY 1, 2) x GROUP BY 1),
      by_os      AS (SELECT "qrCodeId", jsonb_object_agg(k, n) AS m FROM (SELECT "qrCodeId", os      AS k, COUNT(*) AS n FROM day_scans GROUP BY 1, 2) x GROUP BY 1),
      by_browser AS (SELECT "qrCodeId", jsonb_object_agg(k, n) AS m FROM (SELECT "qrCodeId", browser AS k, COUNT(*) AS n FROM day_scans GROUP BY 1, 2) x GROUP BY 1)
      INSERT INTO "scan_daily_rollups"
        ("organizationId", "qrCodeId", "day", "total", "unique", "byCountry", "byCity", "byDeviceType", "byOs", "byBrowser", "updatedAt")
      SELECT t."organizationId", t."qrCodeId", ${day}::date, t.total, t.uniq, c.m, ci.m, d.m, o.m, b.m, NOW()
      FROM totals t
      JOIN by_country c USING ("qrCodeId")
      JOIN by_city ci USING ("qrCodeId")
      JOIN by_device d USING ("qrCodeId")
      JOIN by_os o USING ("qrCodeId")
      JOIN by_browser b USING ("qrCodeId")
      ON CONFLICT ("qrCodeId", "day") DO UPDATE SET
        "organizationId" = EXCLUDED."organizationId",
        "total" = EXCLUDED."total",
        "unique" = EXCLUDED."unique",
        "byCountry" = EXCLUDED."byCountry",
        "byCity" = EXCLUDED."byCity",
        "byDeviceType" = EXCLUDED."byDeviceType",
        "byOs" = EXCLUDED."byOs",
        "byBrowser" = EXCLUDED."byBrowser",
        "updatedAt" = NOW()`;
    await tx.$executeRaw`
      DELETE FROM "scan_daily_rollups" r
      WHERE r."day" = ${day}::date
        AND NOT EXISTS (
          SELECT 1 FROM "scans" s
          WHERE s."qrCodeId" = r."qrCodeId" AND s."createdAt" >= ${start} AND s."createdAt" < ${end}
        )`;
    return written;
  });
}

/** Recomputes yesterday and today: the repeating job (D3). */
export async function refreshRecentRollups(db: PrismaClient, now = new Date()): Promise<number> {
  const today = utcDay(now);
  let rows = 0;
  for (let i = LIVE_DAYS - 1; i >= 0; i--) rows += await recomputeRollupDay(db, addDays(today, -i));
  return rows;
}

/**
 * Backfill (D8): device type, OS and browser from the stored user agent for
 * scans that have none, then every day of the retention window. `parse`
 * is the scan worker's parser. Returns the number of scans updated.
 */
export async function backfillAnalytics(
  db: PrismaClient,
  parse: (ua: string) => { deviceType: string | null; os: string | null; browser: string | null },
  now = new Date(),
): Promise<{ scansEnriched: number; days: number }> {
  const BATCH = 500;
  let scansEnriched = 0;
  let cursor: string | undefined;
  for (;;) {
    const rows = await db.scan.findMany({
      where: { deviceType: null, os: null, browser: null, userAgent: { not: null }, ...(cursor ? { id: { gt: cursor } } : {}) },
      select: { id: true, userAgent: true },
      orderBy: { id: 'asc' },
      take: BATCH,
    });
    if (rows.length === 0) break;
    for (const row of rows) {
      const device = parse(row.userAgent!);
      if (device.deviceType || device.os || device.browser) {
        await db.scan.update({ where: { id: row.id }, data: device });
        scansEnriched++;
      }
    }
    cursor = rows[rows.length - 1].id;
  }
  const today = utcDay(now);
  const days = daysBetween(addDays(today, -(ANALYTICS_RETENTION_DAYS - 1)), today);
  for (const day of days) await recomputeRollupDay(db, day);
  return { scansEnriched, days: days.length };
}

/** Scans older than this are anonymised (CLAUDE.md data retention; ADR-0006 D5). */
export const SCAN_ANONYMISE_AFTER_DAYS = 365;

/**
 * Anonymises scans older than 365 days: the IP hash, user agent, region
 * and city go; country and the device fields stay (D5). The scan
 * row is kept. Returns the number of scans changed.
 */
export async function anonymiseExpiredScans(db: PrismaClient, now = new Date()): Promise<number> {
  const cutoff = new Date(now.getTime() - SCAN_ANONYMISE_AFTER_DAYS * DAY_MS);
  const { count } = await db.scan.updateMany({
    where: {
      createdAt: { lt: cutoff },
      OR: [{ clientIpHash: { not: ANONYMIZED_HASH } }, { region: { not: null } }, { city: { not: null } }],
    },
    // metadata is left as it is, as before ADR-0006.
    data: { clientIpHash: ANONYMIZED_HASH, userAgent: null, region: null, city: null },
  });
  return count;
}

/** Deletes rollup rows older than the retention window (D5). */
export async function purgeExpiredRollups(db: PrismaClient, now = new Date()): Promise<number> {
  const oldest = addDays(utcDay(now), -(ANALYTICS_RETENTION_DAYS - 1));
  return db.$executeRaw`DELETE FROM "scan_daily_rollups" WHERE "day" < ${oldest}::date`;
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

export interface AnalyticsScope {
  readonly organizationId: string;
  /** Restricts to one code (already checked to belong to the organisation). */
  readonly qrCodeId?: string;
}

export interface DayRange {
  readonly from: string;
  readonly to: string;
}

export interface SeriesPoint {
  /** The day, or the Monday of the week. */
  readonly date: string;
  readonly total: number;
  readonly unique: number;
}

/** Splits a range into the rollup part and the live (raw-scan) part. */
export function splitRange(range: DayRange, now = new Date()): { rollup: DayRange | null; live: DayRange | null } {
  const liveFrom = addDays(utcDay(now), -(LIVE_DAYS - 1));
  const rollupTo = addDays(liveFrom, -1);
  return {
    rollup: range.from <= rollupTo ? { from: range.from, to: range.to < rollupTo ? range.to : rollupTo } : null,
    live: range.to >= liveFrom ? { from: range.from > liveFrom ? range.from : liveFrom, to: range.to } : null,
  };
}

function codeFilter(alias: string, scope: AnalyticsScope): Prisma.Sql {
  return scope.qrCodeId ? Prisma.sql`AND ${Prisma.raw(alias)}."qrCodeId" = ${scope.qrCodeId}` : Prisma.empty;
}

interface DayRow {
  day: Date | string;
  total: number;
  uniq: number;
}

function dayKey(value: Date | string): string {
  return typeof value === 'string' ? value.slice(0, 10) : utcDay(value);
}

/** Daily totals and uniques for the scope, every day of the range present (zeros included). */
export async function dailySeries(db: PrismaClient, scope: AnalyticsScope, range: DayRange, now = new Date()): Promise<SeriesPoint[]> {
  const { rollup, live } = splitRange(range, now);
  const rows: DayRow[] = [];
  if (rollup) {
    rows.push(
      ...(await db.$queryRaw<DayRow[]>`
        SELECT r."day" AS day, SUM(r."total")::int AS total, SUM(r."unique")::int AS uniq
        FROM "scan_daily_rollups" r
        WHERE r."organizationId" = ${scope.organizationId} ${codeFilter('r', scope)}
          AND r."day" BETWEEN ${rollup.from}::date AND ${rollup.to}::date
        GROUP BY r."day"`),
    );
  }
  if (live) {
    rows.push(
      ...(await db.$queryRaw<DayRow[]>`
        SELECT day, SUM(total)::int AS total, SUM(uniq)::int AS uniq FROM (
          SELECT s."qrCodeId", (s."createdAt" AT TIME ZONE 'UTC')::date AS day, COUNT(*) AS total,
                 COUNT(DISTINCT s."clientIpHash") FILTER (WHERE s."clientIpHash" <> ${ANONYMIZED_HASH}) AS uniq
          FROM "scans" s JOIN "qr_codes" q ON q."id" = s."qrCodeId"
          WHERE q."organizationId" = ${scope.organizationId} ${codeFilter('s', scope)}
            AND s."createdAt" >= ${dayStart(live.from)} AND s."createdAt" < ${dayStart(addDays(live.to, 1))}
          GROUP BY 1, 2
        ) per_code GROUP BY day`),
    );
  }
  const byDay = new Map(rows.map((r) => [dayKey(r.day), r]));
  return daysBetween(range.from, range.to).map((date) => {
    const r = byDay.get(date);
    return { date, total: r?.total ?? 0, unique: r?.uniq ?? 0 };
  });
}

/** Sums daily points into ISO weeks (Monday start); a weekly unique is the sum of daily uniques (D4). */
export function toWeeks(points: readonly SeriesPoint[]): SeriesPoint[] {
  const weeks = new Map<string, { total: number; unique: number }>();
  for (const p of points) {
    const key = weekStart(p.date);
    const w = weeks.get(key) ?? { total: 0, unique: 0 };
    weeks.set(key, { total: w.total + p.total, unique: w.unique + p.unique });
  }
  return [...weeks.entries()].map(([date, w]) => ({ date, ...w }));
}

export async function timeSeries(
  db: PrismaClient,
  scope: AnalyticsScope,
  range: DayRange,
  granularity: Granularity,
  now = new Date(),
): Promise<SeriesPoint[]> {
  const days = await dailySeries(db, scope, range, now);
  return granularity === 'week' ? toWeeks(days) : days;
}

export interface BreakdownItem {
  readonly key: string;
  readonly count: number;
}

export interface Breakdown {
  readonly dimension: BreakdownDimension;
  readonly total: number;
  readonly items: BreakdownItem[];
  /** Scans in values beyond the first BREAKDOWN_LIMIT. */
  readonly other: number;
}

/** Scan counts per value of a dimension over the range, largest first. */
export async function breakdown(
  db: PrismaClient,
  scope: AnalyticsScope,
  range: DayRange,
  dimension: BreakdownDimension,
  now = new Date(),
  limit = BREAKDOWN_LIMIT,
): Promise<Breakdown> {
  const sql = DIMENSION_SQL[dimension];
  const { rollup, live } = splitRange(range, now);
  const counts = new Map<string, number>();
  const add = (rows: Array<{ k: string; n: number }>) => {
    for (const r of rows) counts.set(r.k, (counts.get(r.k) ?? 0) + Number(r.n));
  };
  if (rollup) {
    add(
      await db.$queryRaw<Array<{ k: string; n: number }>>`
        SELECT e.key AS k, SUM(e.value::int)::int AS n
        FROM "scan_daily_rollups" r, jsonb_each_text(r.${sql.column}) e
        WHERE r."organizationId" = ${scope.organizationId} ${codeFilter('r', scope)}
          AND r."day" BETWEEN ${rollup.from}::date AND ${rollup.to}::date
        GROUP BY e.key`,
    );
  }
  if (live) {
    add(
      await db.$queryRaw<Array<{ k: string; n: number }>>`
        SELECT ${sql.raw} AS k, COUNT(*)::int AS n
        FROM "scans" s JOIN "qr_codes" q ON q."id" = s."qrCodeId"
        WHERE q."organizationId" = ${scope.organizationId} ${codeFilter('s', scope)}
          AND s."createdAt" >= ${dayStart(live.from)} AND s."createdAt" < ${dayStart(addDays(live.to, 1))}
        GROUP BY 1`,
    );
  }
  const sorted = [...counts.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key));
  const total = sorted.reduce((sum, i) => sum + i.count, 0);
  const items = sorted.slice(0, limit);
  return { dimension, total, items, other: total - items.reduce((sum, i) => sum + i.count, 0) };
}

/** The last 7 UTC days, today included: the overview sparkline (D7). */
export async function lastSevenDays(db: PrismaClient, organizationId: string, now = new Date()): Promise<SeriesPoint[]> {
  const to = utcDay(now);
  return dailySeries(db, { organizationId }, { from: addDays(to, -6), to }, now);
}

export interface HeatmapBucket {
  readonly lat: number;
  readonly lng: number;
  readonly count: number;
}

/**
 * GPS scan density, grouped in SQL by coordinates rounded to 3 decimals
 * (about 111 m), largest first and capped at HEATMAP_BUCKET_LIMIT buckets.
 */
export async function heatmap(db: PrismaClient, organizationId: string, limit = HEATMAP_BUCKET_LIMIT): Promise<HeatmapBucket[]> {
  return db.$queryRaw<HeatmapBucket[]>`
    SELECT ROUND(s."clientLat"::numeric, 3)::float8 AS lat,
           ROUND(s."clientLng"::numeric, 3)::float8 AS lng,
           COUNT(*)::int AS count
    FROM "scans" s JOIN "qr_codes" q ON q."id" = s."qrCodeId"
    WHERE q."organizationId" = ${organizationId}
      AND s."clientLat" IS NOT NULL AND s."clientLng" IS NOT NULL
    GROUP BY 1, 2
    ORDER BY count DESC, lat, lng
    LIMIT ${limit}`;
}
