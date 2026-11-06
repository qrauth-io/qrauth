/**
 * CSV export of scans (ADR-0006 D6), streamed: rows are read in keyset
 * batches over (createdAt, id) and written as they arrive, so memory stays
 * flat whatever the range. Organisation-scoped; no IP hash and no user agent.
 */
import type { PrismaClient } from '@prisma/client';

import { csvLine } from '../lib/csv.js';
import { addDays, dayStart, type AnalyticsScope, type DayRange } from './scan-analytics.js';

export const CSV_COLUMNS = [
  'scanned_at',
  'code',
  'label',
  'country',
  'region',
  'city',
  'device_type',
  'os',
  'browser',
  'trust_score',
] as const;

export const CSV_BATCH_SIZE = 1000;

/** Header line, then one line per scan in the range, oldest first. */
export async function* scanCsvLines(
  db: PrismaClient,
  scope: AnalyticsScope,
  range: DayRange,
  batchSize = CSV_BATCH_SIZE,
): AsyncGenerator<string> {
  yield csvLine(CSV_COLUMNS);
  const start = dayStart(range.from);
  const end = dayStart(addDays(range.to, 1));
  let last: { createdAt: Date; id: string } | null = null;
  for (;;) {
    const rows: Array<{
      id: string;
      createdAt: Date;
      country: string | null;
      region: string | null;
      city: string | null;
      deviceType: string | null;
      os: string | null;
      browser: string | null;
      trustScore: number;
      qrCode: { token: string; label: string | null };
    }> = await db.scan.findMany({
      where: {
        qrCode: { organizationId: scope.organizationId },
        ...(scope.qrCodeId ? { qrCodeId: scope.qrCodeId } : {}),
        createdAt: { gte: start, lt: end },
        ...(last
          ? { OR: [{ createdAt: { gt: last.createdAt } }, { createdAt: last.createdAt, id: { gt: last.id } }] }
          : {}),
      },
      orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
      take: batchSize,
      select: {
        id: true,
        createdAt: true,
        country: true,
        region: true,
        city: true,
        deviceType: true,
        os: true,
        browser: true,
        trustScore: true,
        qrCode: { select: { token: true, label: true } },
      },
    });
    for (const r of rows) {
      yield csvLine([
        r.createdAt.toISOString(),
        r.qrCode.token,
        r.qrCode.label,
        r.country,
        r.region,
        r.city,
        r.deviceType,
        r.os,
        r.browser,
        r.trustScore,
      ]);
    }
    if (rows.length < batchSize) return;
    const tail = rows[rows.length - 1];
    last = { createdAt: tail.createdAt, id: tail.id };
  }
}
