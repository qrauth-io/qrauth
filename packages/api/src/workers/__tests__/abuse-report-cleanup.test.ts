import { describe, it, expect, vi } from 'vitest';
import {
  ABUSE_REPORT_RETENTION_DAYS,
  abuseReportPurgeWhere,
  purgeAbuseReports,
} from '../abuse-report-cleanup.js';

/**
 * Closed abuse reports (RESOLVED / DISMISSED) are deleted 730 days after they
 * were closed. OPEN reports are never deleted automatically.
 */

const NOW = new Date('2026-10-29T12:00:00.000Z');
const DAY = 24 * 60 * 60 * 1000;
const CUTOFF = new Date(NOW.getTime() - 730 * DAY);

type Report = { status: 'OPEN' | 'RESOLVED' | 'DISMISSED'; createdAt: Date; resolvedAt: Date | null };

type DateFilter = { lt: Date };
type Where = {
  status: { in: string[] };
  OR: Array<{ resolvedAt: DateFilter } | { resolvedAt: null; createdAt: DateFilter }>;
};

/** Evaluates the Prisma filter the purge builds against an in-memory row. */
function matches(where: Where, r: Report): boolean {
  if (!where.status.in.includes(r.status)) return false;
  return where.OR.some((clause) => {
    if (clause.resolvedAt === null) {
      return r.resolvedAt === null && r.createdAt < (clause as { createdAt: DateFilter }).createdAt.lt;
    }
    return r.resolvedAt !== null && r.resolvedAt < clause.resolvedAt.lt;
  });
}

const daysAgo = (n: number) => new Date(NOW.getTime() - n * DAY);
const where = () => abuseReportPurgeWhere(NOW) as unknown as Where;

describe('purgeAbuseReports', () => {
  it('uses a 730-day retention window', () => {
    expect(ABUSE_REPORT_RETENTION_DAYS).toBe(730);
  });

  it('deletes resolved and dismissed reports closed more than 730 days ago', () => {
    expect(matches(where(), { status: 'RESOLVED', createdAt: daysAgo(900), resolvedAt: daysAgo(731) })).toBe(true);
    expect(matches(where(), { status: 'DISMISSED', createdAt: daysAgo(900), resolvedAt: daysAgo(800) })).toBe(true);
  });

  it('keeps closed reports closed within the last 730 days, even if filed earlier', () => {
    expect(matches(where(), { status: 'RESOLVED', createdAt: daysAgo(1100), resolvedAt: daysAgo(1) })).toBe(false);
    expect(matches(where(), { status: 'DISMISSED', createdAt: daysAgo(1100), resolvedAt: daysAgo(729) })).toBe(false);
  });

  it('never deletes OPEN reports, whatever their age', () => {
    expect(matches(where(), { status: 'OPEN', createdAt: daysAgo(5000), resolvedAt: null })).toBe(false);
    expect(matches(where(), { status: 'OPEN', createdAt: daysAgo(5000), resolvedAt: daysAgo(5000) })).toBe(false);
  });

  it('falls back to createdAt for closed reports without a resolvedAt', () => {
    expect(matches(where(), { status: 'RESOLVED', createdAt: daysAgo(731), resolvedAt: null })).toBe(true);
    expect(matches(where(), { status: 'DISMISSED', createdAt: daysAgo(10), resolvedAt: null })).toBe(false);
  });

  it('keeps a report closed exactly at the cutoff and deletes one closed a millisecond earlier', () => {
    const atCutoff = new Date(CUTOFF.getTime());
    const justBefore = new Date(CUTOFF.getTime() - 1);
    expect(matches(where(), { status: 'RESOLVED', createdAt: daysAgo(1000), resolvedAt: atCutoff })).toBe(false);
    expect(matches(where(), { status: 'RESOLVED', createdAt: daysAgo(1000), resolvedAt: justBefore })).toBe(true);
    expect(matches(where(), { status: 'DISMISSED', createdAt: atCutoff, resolvedAt: null })).toBe(false);
    expect(matches(where(), { status: 'DISMISSED', createdAt: justBefore, resolvedAt: null })).toBe(true);
  });

  it('deletes with that filter and returns the number of rows removed', async () => {
    const deleteMany = vi.fn(async () => ({ count: 4 }));

    const count = await purgeAbuseReports({ abuseReport: { deleteMany } } as never, NOW);

    expect(count).toBe(4);
    expect(deleteMany).toHaveBeenCalledTimes(1);
    expect(deleteMany).toHaveBeenCalledWith({ where: abuseReportPurgeWhere(NOW) });
  });
});
