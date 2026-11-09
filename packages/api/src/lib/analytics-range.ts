/**
 * Query parameters of the analytics endpoints (ADR-0006): a UTC day range
 * within the 365-day retention window, the series granularity, and an
 * optional code token.
 */
import { z } from 'zod';

import {
  ANALYTICS_RETENTION_DAYS,
  BREAKDOWN_DIMENSIONS,
  addDays,
  utcDay,
  type DayRange,
} from '../services/scan-analytics.js';

/** Range when none is given: the last 30 days, today included. */
export const DEFAULT_RANGE_DAYS = 30;

const DAY = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'must be a date as YYYY-MM-DD');
const TOKEN = z.string().min(1).max(64);

export const analyticsRangeQuerySchema = z
  .object({
    from: DAY.optional(),
    to: DAY.optional(),
    token: TOKEN.optional(),
  })
  .strict();

export const timeSeriesQuerySchema = analyticsRangeQuerySchema.extend({
  granularity: z.enum(['day', 'week']).default('day'),
});

export const breakdownQuerySchema = analyticsRangeQuerySchema.extend({
  dimension: z.enum(BREAKDOWN_DIMENSIONS),
});

export const codeAnalyticsQuerySchema = z
  .object({ from: DAY.optional(), to: DAY.optional(), granularity: z.enum(['day', 'week']).default('day') })
  .strict();

function isRealDay(day: string): boolean {
  const d = new Date(`${day}T00:00:00.000Z`);
  return !Number.isNaN(d.getTime()) && utcDay(d) === day;
}

/**
 * The day range for a query, or the reason it is refused (400). `to`
 * defaults to today and `from` to 29 days before `to`, kept inside the
 * retention window. Neither may be in the future or older than the window.
 */
export function resolveRange(query: { from?: string; to?: string }, now = new Date()): DayRange | { error: string } {
  const today = utcDay(now);
  const oldest = addDays(today, -(ANALYTICS_RETENTION_DAYS - 1));
  const to = query.to ?? today;
  const defaultFrom = addDays(to, -(DEFAULT_RANGE_DAYS - 1));
  const from = query.from ?? (defaultFrom < oldest ? oldest : defaultFrom);
  if (!isRealDay(from) || !isRealDay(to)) return { error: 'from and to must be real dates (YYYY-MM-DD).' };
  if (from > to) return { error: 'from must not be after to.' };
  if (to > today) return { error: 'to must not be in the future (days are UTC).' };
  if (from < oldest) return { error: `from must be on or after ${oldest}: analytics cover the last ${ANALYTICS_RETENTION_DAYS} days.` };
  return { from, to };
}
