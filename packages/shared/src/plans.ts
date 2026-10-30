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

import { isIssuerVerified, type IssuerVerificationFields } from './issuer.js';

export const PLAN_TIERS =['FREE', 'PRO', 'BUSINESS', 'ENTERPRISE'] as const;
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

/**
 * QR module and eye styles on FREE (ADR-0005 D9): square and rounded. Paid
 * plans draw all four. The API enforces this on style writes; the dashboard
 * mirrors it to disable the other shapes.
 */
export const FREE_QR_SHAPES = ['square', 'rounded'] as const;

/** True when `plan` may save a style using `shape` as its module or eye style. */
export function planAllowsQrShape(plan: string, shape: string): boolean {
  return (FREE_QR_SHAPES as readonly string[]).includes(shape) || (isPlanTier(plan) && plan !== 'FREE');
}

/**
 * Customer logos (ADR-0005 D9): uploading one, and saving a style that draws
 * one (`logo.kind = "asset"`), need a paid plan. The QRAuth logo is on every
 * plan. A stored style keeps rendering after a downgrade.
 */
export function planAllowsCustomerLogo(plan: string): boolean {
  return isPlanTier(plan) && plan !== 'FREE';
}

/**
 * Frames and CTA templates (ADR-0005 D9): any template but `none` needs a
 * paid plan. A stored frame keeps rendering after a downgrade; only saving a
 * changed style that draws one is refused.
 */
export function planAllowsFrame(plan: string, template: string | undefined): boolean {
  return template === undefined || template === 'none' || (isPlanTier(plan) && plan !== 'FREE');
}

/**
 * Print exports (ADR-0005 D9): a PNG at print size (`size_mm`, `size_in` or
 * `dpi` given, or wider than 1024 px) and the vector PDF need a paid plan.
 * Every plan exports SVG and PNG up to 1024 px. The image endpoint enforces
 * this; the dashboard mirrors it to disable the print options.
 */
export function planAllowsPrintExport(plan: string): boolean {
  return isPlanTier(plan) && plan !== 'FREE';
}

/** The frame fields the frame gate compares (a v2 `frame`, or a stored v1 caption upgraded). */
export interface GatedFrame {
  readonly template: string;
  readonly text?: string;
  readonly color?: string;
  readonly textColor?: string;
}

/**
 * Why a style's frame may not be saved: `plan` (frames are paid) or
 * `caption-locked` (FREE changed a grandfathered caption's template or
 * colours).
 */
export type FrameRefusal = 'plan' | 'caption-locked';

/**
 * A grandfathered caption (ADR-0005 D9, amendment of 2026-10-30): the code's
 * STORED frame is a caption, from a v1 `captionText` or a stored v2 caption
 * frame. It keeps rendering on every plan, and FREE may still edit its text.
 */
export function isGrandfatheredCaption(stored: GatedFrame | null | undefined): boolean {
  return stored?.template === 'caption';
}

function sameColour(a: string | undefined, b: string | undefined): boolean {
  return (a ?? '').toUpperCase() === (b ?? '').toUpperCase();
}

/**
 * The frame gate on a style write (ADR-0005 D9, amended 2026-10-30). Paid
 * plans may save any frame. FREE may save no frame (absent or `none`, which
 * also removes a stored one) and may not add a frame or change a frame's
 * template; on a code whose stored frame is a caption, FREE may change the
 * caption's text only: template and colours must equal the stored values
 * (colours compared case-insensitively). `stored` is the code's stored
 * frame, null on create. Null when allowed.
 */
export function frameChangeRefusal(
  plan: string,
  stored: GatedFrame | null | undefined,
  next: GatedFrame | null | undefined,
): FrameRefusal | null {
  if (planAllowsFrame(plan, next?.template)) return null;
  if (!next || !isGrandfatheredCaption(stored)) return 'plan';
  const keepsCaption =
    next.template === 'caption' && sameColour(next.color, stored?.color) && sameColour(next.textColor, stored?.textColor);
  return keepsCaption ? null : 'caption-locked';
}

/** Why an organization may not use customer logos: its plan, or an unverified issuer. */
export type CustomerLogoRefusal = 'plan' | 'verification';

export interface CustomerLogoEligibility extends IssuerVerificationFields {
  plan: string;
}

/**
 * Customer logos need a paid plan AND a verified issuer (ADR-0005 D9,
 * amended 2026-10-29): a printed code carrying a brand's logo is an
 * impersonation vector, and a verified issuer is what QRAuth already attests
 * on scan. Null when allowed; otherwise the first unmet requirement, the plan
 * before verification. Uploading a logo and saving a changed style that
 * draws one are gated; stored styles keep rendering.
 */
export function customerLogoRefusal(org: CustomerLogoEligibility): CustomerLogoRefusal | null {
  if (!planAllowsCustomerLogo(org.plan)) return 'plan';
  if (!isIssuerVerified(org)) return 'verification';
  return null;
}

/** "50,000" / "Unlimited" — the one formatter the pricing cards use. */
export function formatQuota(limit: QuotaLimit): string {
  return limit === 'unlimited' ? 'Unlimited' : limit.toLocaleString('en-US');
}
