/**
 * Plan-tier limits — single source of truth for what FREE/PRO/ENTERPRISE
 * organizations are allowed to do per metric per period.
 *
 * Issue #65. The previous PLAN_LIMITS in services/usage.ts used a
 * mixed shape (`-1` sentinel for "unlimited", missing metrics for the
 * ephemeral-sessions surface that landed during Q2) and was the only
 * place these numbers were defined. Routes that wanted to enforce the
 * cap reached into UsageService.getLimits and branched on `-1`. Adding
 * a new metric meant editing every caller. This file lifts the values
 * out and standardises the "unlimited" representation as the literal
 * string so a missing entry fails compilation instead of silently
 * defaulting to zero.
 *
 * The verifications metric is a SOFT meter. The cap below is reflected
 * in the `X-Quota-Limit` response header on `/verify` but no 429 is
 * returned at the limit. Anti-abuse hard cap is filed as #84.
 *
 * The qrcodes / authSessions / ephemeralSessions metrics are HARD
 * caps. The owning route returns 429 when the cap is reached. See
 * routes/qrcodes.ts, routes/auth-sessions.ts, routes/ephemeral.ts.
 */

export type PlanTier = 'FREE' | 'PRO' | 'ENTERPRISE';

export type UsageMetric =
  | 'verifications'
  | 'qrcodes'
  | 'authSessions'
  | 'ephemeralSessions';

export type Limit = number | 'unlimited';

export const PLAN_LIMITS: Record<PlanTier, Record<UsageMetric, Limit>> = {
  FREE: {
    verifications: 1000,
    qrcodes: 100,
    authSessions: 1000,
    ephemeralSessions: 1000,
  },
  PRO: {
    verifications: 50_000,
    qrcodes: 'unlimited',
    authSessions: 50_000,
    ephemeralSessions: 50_000,
  },
  ENTERPRISE: {
    verifications: 'unlimited',
    qrcodes: 'unlimited',
    authSessions: 'unlimited',
    ephemeralSessions: 'unlimited',
  },
};

/**
 * Resolve a plan + metric to its concrete limit. Falls back to FREE
 * when the plan string isn't one of the three known tiers — a row
 * with a typo'd plan column is treated as the most restrictive tier
 * rather than getting accidental ENTERPRISE access.
 */
export function getPlanLimit(plan: string, metric: UsageMetric): Limit {
  const tier = (PLAN_LIMITS as Record<string, Record<UsageMetric, Limit>>)[plan];
  if (!tier) return PLAN_LIMITS.FREE[metric];
  return tier[metric];
}

/** Convenience: true iff the plan/metric combination has an unlimited cap. */
export function isUnlimited(plan: string, metric: UsageMetric): boolean {
  return getPlanLimit(plan, metric) === 'unlimited';
}

/**
 * Wire-format serializer for plan limits.
 *
 * Internally we model limits as `number | 'unlimited'` (typed enum,
 * compiler-checked at every call site). The JSON wire contract,
 * however, has historically used `-1` as the unlimited sentinel and
 * predates this typed shape — `packages/web/src/pages/dashboard/usage.tsx`
 * checks `meter.limit === -1` to switch into its "Unlimited" render
 * branch. Emitting the `'unlimited'` literal directly would produce
 * `"12 / unlimited (NaN%)"` instead. Unaudited API consumers
 * (support tooling, third-party integrations, browser bookmarks)
 * could be relying on the same convention.
 *
 * Apply this function at every JSON response boundary that emits a
 * limit value. It MUST NOT be called at the X-Quota-Limit header
 * boundary — that header is omitted entirely for unlimited tiers
 * (header absence is the contract for callers, see
 * routes/verify-quota-headers.ts).
 *
 * Future migration path: introduce a v2 `/usage` response shape that
 * carries the `'unlimited'` literal (or `null`) on a versioned
 * endpoint, deprecate v1 with a sunset header, retire the sentinel
 * when consumers have moved. Tracking context: PR #86 / issue #65.
 */
export function serializeLimit(limit: Limit): number {
  return limit === 'unlimited' ? -1 : limit;
}
