import { redis } from '../lib/cache.js';
import type { PrismaClient } from '@prisma/client';
import {
  PLAN_LIMITS,
  getPlanLimit,
  isUnlimited,
  type PlanTier,
  type UsageMetric,
  type Limit,
} from '../config/plan-limits.js';

export type { PlanTier, UsageMetric, Limit } from '../config/plan-limits.js';

const KEY_PREFIX = 'qrauth:usage:';

/**
 * Soft-meter persistence: 35 days covers the period (≤31) plus a buffer
 * so end-of-month + early-next-month reads on the same key still resolve
 * before Redis evicts. The UsageSnapshot worker (#83) is the long-term
 * archive; this TTL is just for the live counter.
 */
const TTL_SECONDS = 35 * 24 * 60 * 60;

function monthKey(now: Date = new Date()): string {
  return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
}

function redisKey(orgId: string, metric: UsageMetric, period: string): string {
  return `${KEY_PREFIX}${orgId}:${metric}:${period}`;
}

/**
 * Bag for the structured warn-log calls below. Lets the route plug in
 * `fastify.log` while unit tests inject a vi.fn spy. Default is a
 * console-shaped no-op.
 */
export interface UsageLogger {
  warn: (obj: Record<string, unknown>, msg: string) => void;
}

const defaultLogger: UsageLogger = {
  warn: () => {
    // No console output by default — fail-quiet is the contract.
    // Real callers wire in fastify.log so failures surface in pino.
  },
};

/**
 * Issue #65. Type-safe, multi-metric, error-tolerant usage counters.
 *
 * - All metric names are pinned to the `UsageMetric` union; the compiler
 *   refuses unknown strings at every call site.
 * - Every Redis call is wrapped in try/catch. Failures log via the
 *   injected `UsageLogger` and return a safe fallback (0 for reads,
 *   the would-be-incremented value if it's known). The contract is:
 *   the verification path NEVER fails because the meter is broken.
 * - The QR-code total is sourced from Prisma rather than Redis; QR
 *   codes are an enduring count, not a per-period meter.
 */
export class UsageService {
  constructor(
    private prisma: PrismaClient,
    private logger: UsageLogger = defaultLogger,
  ) {}

  /**
   * Atomic INCR + lazy expire. Returns the new count.
   *
   * On Redis failure: logs a warn line tagged with `{orgId, metric}`,
   * returns 0. The caller MUST treat this as a non-fatal hint, not as
   * an authoritative count. Quota-enforcement code (qrcodes, auth-sessions,
   * ephemeral) reads `current()` separately to decide on 429s, so a 0
   * here does not produce false-positive caps.
   */
  async increment(orgId: string, metric: UsageMetric): Promise<number> {
    const key = redisKey(orgId, metric, monthKey());
    try {
      const count = await redis.incr(key);
      if (count === 1) {
        // First write of the period — set the TTL. INCR returns 1 on a
        // fresh key, so this branch triggers exactly once per period
        // per orgId/metric pair.
        try {
          await redis.expire(key, TTL_SECONDS);
        } catch (err) {
          // Failing to set the TTL is annoying (the key will live until
          // a future TTL gets set on a re-entry) but does not break
          // counting. Log and keep the count.
          this.logger.warn(
            { orgId, metric, err: errMessage(err) },
            'usage: failed to set TTL on counter key',
          );
        }
      }
      return count;
    } catch (err) {
      this.logger.warn(
        { orgId, metric, err: errMessage(err) },
        'usage: increment failed (counter unchanged)',
      );
      return 0;
    }
  }

  /**
   * Read the current count for the live period. 0 on key miss or on
   * Redis failure. Never throws.
   */
  async current(orgId: string, metric: UsageMetric): Promise<number> {
    if (metric === 'qrcodes') {
      // QR codes aren't a per-period counter — count the live rows.
      try {
        return await this.prisma.qRCode.count({
          where: { organizationId: orgId, status: { not: 'REVOKED' } },
        });
      } catch (err) {
        this.logger.warn(
          { orgId, metric, err: errMessage(err) },
          'usage: prisma qRCode.count failed',
        );
        return 0;
      }
    }
    const key = redisKey(orgId, metric, monthKey());
    try {
      const raw = await redis.get(key);
      const n = raw == null ? 0 : parseInt(raw, 10);
      return Number.isFinite(n) ? n : 0;
    } catch (err) {
      this.logger.warn(
        { orgId, metric, err: errMessage(err) },
        'usage: current() read failed',
      );
      return 0;
    }
  }

  /**
   * All four metrics in one call. Used by the dashboard `/usage` endpoint
   * and the X-Quota-* response-header hook on /verify. Each metric is
   * read independently — a per-metric failure does not abort the others.
   */
  async snapshot(orgId: string): Promise<Record<UsageMetric, number>> {
    const [verifications, qrcodes, authSessions, ephemeralSessions] = await Promise.all([
      this.current(orgId, 'verifications'),
      this.current(orgId, 'qrcodes'),
      this.current(orgId, 'authSessions'),
      this.current(orgId, 'ephemeralSessions'),
    ]);
    return { verifications, qrcodes, authSessions, ephemeralSessions };
  }

  /**
   * Hard-cap check. Returns null when the operation is allowed, or an
   * operator-shaped error message when the org is at/over its limit.
   * Used by qrcodes / auth-sessions / ephemeral routes. NOT used on the
   * /verify path — verification is a soft meter.
   */
  async checkQuota(
    orgId: string,
    plan: string,
    metric: UsageMetric,
  ): Promise<string | null> {
    const limit = getPlanLimit(plan, metric);
    if (limit === 'unlimited') return null;
    const used = await this.current(orgId, metric);
    if (used >= limit) {
      return `${humanMetric(metric)} limit reached (${limit}). Upgrade your plan at https://qrauth.io/dashboard/settings.`;
    }
    return null;
  }

  /** Read the full plan-limits row for the supplied plan tier. */
  getLimits(plan: string): Record<UsageMetric, Limit> {
    return (PLAN_LIMITS as Record<string, Record<UsageMetric, Limit>>)[plan] ?? PLAN_LIMITS.FREE;
  }
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function humanMetric(m: UsageMetric): string {
  switch (m) {
    case 'verifications':
      return 'Monthly verification';
    case 'qrcodes':
      return 'QR code';
    case 'authSessions':
      return 'Monthly auth session';
    case 'ephemeralSessions':
      return 'Monthly ephemeral session';
  }
}

export { isUnlimited, getPlanLimit, PLAN_LIMITS };
