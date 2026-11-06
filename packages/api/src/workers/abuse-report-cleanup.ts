import type { Prisma, PrismaClient } from '@prisma/client';

/**
 * Retention for abuse reports.
 *
 * Closed reports (RESOLVED or DISMISSED) are deleted 730 days after they were
 * closed. The clock starts at resolvedAt, not createdAt: a report filed long
 * ago but closed recently is still the current record of that decision. Rows
 * closed without a resolvedAt fall back to createdAt.
 *
 * OPEN reports are never deleted automatically; they wait for review.
 */

export const ABUSE_REPORT_RETENTION_DAYS = 730;

const DAY_MS = 24 * 60 * 60 * 1000;
const CLOSED_STATUSES = ['RESOLVED', 'DISMISSED'] as const;

export function abuseReportPurgeWhere(now: Date): Prisma.AbuseReportWhereInput {
  const cutoff = new Date(now.getTime() - ABUSE_REPORT_RETENTION_DAYS * DAY_MS);
  return {
    status: { in: [...CLOSED_STATUSES] },
    OR: [
      { resolvedAt: { lt: cutoff } },
      { resolvedAt: null, createdAt: { lt: cutoff } },
    ],
  };
}

export async function purgeAbuseReports(
  db: Pick<PrismaClient, 'abuseReport'>,
  now: Date = new Date(),
): Promise<number> {
  const { count } = await db.abuseReport.deleteMany({ where: abuseReportPurgeWhere(now) });
  return count;
}
