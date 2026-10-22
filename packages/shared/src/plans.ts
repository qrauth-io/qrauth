/**
 * Plan catalogue — the single source of truth for plan tiers, self-serve
 * prices and quotas.
 *
 * The API enforces and meters these numbers (api/src/config/plan-limits.ts
 * re-exports them), the Stripe checkout refuses a price whose amount does
 * not match PLAN_PRICES_EUR, and both pricing pages render their cards from
 * here. A quota shown on a pricing card must come from this file.
 *
 * Quota semantics per metric:
 * - qrcodes, oidcClients: standing counts (live rows), HARD cap at creation.
 * - authSessions, ephemeralSessions: per calendar month (UTC), HARD cap.
 * - verifications: per calendar month (UTC), SOFT meter. Verification keeps
 *   working past the allowance; owners are emailed at 80% and 100%.
 */

export const PLAN_TIERS = ['FREE', 'PRO', 'BUSINESS', 'ENTERPRISE'] as const;
export type PlanTier = (typeof PLAN_TIERS)[number];

/** Tiers a customer can buy through Stripe Checkout. */
export const SELF_SERVE_PLANS = ['PRO', 'BUSINESS'] as const;
export type SelfServePlan = (typeof SELF_SERVE_PLANS)[number];

export const BILLING_INTERVALS = ['month', 'year'] as const;
export type BillingInterval = (typeof BILLING_INTERVALS)[number];

export const PLAN_RANK: Record<PlanTier, number> = {
  FREE: 0,
  PRO: 1,
  BUSINESS: 2,
  ENTERPRISE: 3,
};

/** Customer-facing names. ENTERPRISE is sold as "Regulated". */
export const PLAN_DISPLAY_NAMES: Record<PlanTier, string> = {
  FREE: 'Free',
  PRO: 'Pro',
  BUSINESS: 'Business',
  ENTERPRISE: 'Regulated',
};

export type QuotaMetric =
  | 'verifications'
  | 'qrcodes'
  | 'authSessions'
  | 'ephemeralSessions'
  | 'oidcClients';

export type QuotaLimit = number | 'unlimited';

export const PLAN_QUOTAS: Record<PlanTier, Record<QuotaMetric, QuotaLimit>> = {
  FREE: {
    verifications: 1_000,
    qrcodes: 100,
    authSessions: 1_000,
    ephemeralSessions: 1_000,
    oidcClients: 2,
  },
  PRO: {
    verifications: 50_000,
    qrcodes: 'unlimited',
    authSessions: 50_000,
    ephemeralSessions: 50_000,
    oidcClients: 5,
  },
  BUSINESS: {
    verifications: 250_000,
    qrcodes: 'unlimited',
    authSessions: 250_000,
    ephemeralSessions: 250_000,
    oidcClients: 20,
  },
  ENTERPRISE: {
    verifications: 'unlimited',
    qrcodes: 'unlimited',
    authSessions: 'unlimited',
    ephemeralSessions: 'unlimited',
    oidcClients: 'unlimited',
  },
};

/** Whole euros, VAT excluded. Annual is ten months' price. */
export const PLAN_PRICES_EUR: Record<SelfServePlan, Record<BillingInterval, number>> = {
  PRO: { month: 99, year: 990 },
  BUSINESS: { month: 399, year: 3_990 },
};

/** Regulated is an annual licence sold by contract, not through Stripe. */
export const REGULATED_FROM_EUR_PER_YEAR = 12_000;

/** Verification-meter alert thresholds, as a percentage of the allowance. */
export const VERIFICATION_ALERT_THRESHOLDS = [80, 100] as const;

export function isPlanTier(value: unknown): value is PlanTier {
  return typeof value === 'string' && (PLAN_TIERS as readonly string[]).includes(value);
}

/**
 * Stripe Price lookup key for a self-serve plan, e.g. `qrauth_pro_month`.
 * Each live Price carries this lookup key plus `metadata.plan`.
 */
export function stripeLookupKey(plan: SelfServePlan, interval: BillingInterval): string {
  return `qrauth_${plan.toLowerCase()}_${interval}`;
}

/** Inverse of stripeLookupKey. Null for any key this catalogue does not define. */
export function parseStripeLookupKey(
  key: string | null | undefined,
): { plan: SelfServePlan; interval: BillingInterval } | null {
  if (!key) return null;
  for (const plan of SELF_SERVE_PLANS) {
    for (const interval of BILLING_INTERVALS) {
      if (stripeLookupKey(plan, interval) === key) return { plan, interval };
    }
  }
  return null;
}

/** FREE may only create content types flagged freeTierAllowed. */
export function planAllowsContentType(plan: string, freeTierAllowed: boolean): boolean {
  return freeTierAllowed || (isPlanTier(plan) && plan !== 'FREE');
}

/** "50,000" / "Unlimited" — the one formatter the pricing cards use. */
export function formatQuota(limit: QuotaLimit): string {
  return limit === 'unlimited' ? 'Unlimited' : limit.toLocaleString('en-US');
}
