/**
 * Plan-tier limits — what FREE/PRO/BUSINESS/ENTERPRISE
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
 * The oidcClients metric is a HARD cap enforced inside the create
 * transaction in services/oidc-client-admin.ts (409 Conflict).
 */

import {
  PLAN_QUOTAS,
  getContentType,
  planAllowsContentType,
  customerLogoRefusal,
  frameChangeRefusal,
  isIssuerVerified,
  planAllowsCustomerLogo,
  planAllowsPrintExport,
  planAllowsQrShape,
  type CustomerLogoEligibility,
  type GatedFrame,
  type PlanTier,
  type QuotaMetric,
  type QuotaLimit,
} from '@qrauth/shared';
import { FRAME_QRAUTH_CLAIM_MESSAGE, isFrameClaimRefused } from '@qrauth/shared/qr-render';

export type { PlanTier };
export type UsageMetric = QuotaMetric;
export type Limit = QuotaLimit;

/** Values live in @qrauth/shared (plans.ts) so the pricing pages render the same numbers. */
export const PLAN_LIMITS: Record<PlanTier, Record<UsageMetric, Limit>> = PLAN_QUOTAS;

/**
 * Resolve a plan + metric to its concrete limit. Falls back to FREE
 * when the plan string isn't one of the known tiers — a row
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

/**
 * Server-side content-type gate. FREE may only create the types flagged
 * `freeTierAllowed` in the shared registry (URL, vCard); the dashboard's
 * locked tiles are a hint, this is the enforcement. Returns an operator-
 * facing message when refused, null when allowed. Unknown types return null
 * so generateQRCode's own "Unknown content type" error still applies.
 */
export function contentTypeGateMessage(plan: string, contentType: string | undefined): string | null {
  const resolved = contentType || 'url';
  const def = getContentType(resolved);
  if (!def || planAllowsContentType(plan, def.freeTierAllowed)) return null;
  return `The ${def.label} content type is not included in the Free plan. Upgrade at https://qrauth.io/dashboard/pricing.`;
}

const UPGRADE_HINT = 'Upgrade at https://qrauth.io/dashboard/pricing.';

/** The style fields the plan gates read. */
export interface GatedStyle {
  readonly modules: string;
  readonly eyes: string;
  readonly logo?: { readonly kind: string } | null;
  readonly frame?: GatedFrame | null;
}

/** 403 message: a frame on FREE (none stored, or a stored frame that is not a caption). */
export const FRAME_PLAN_MESSAGE = `Frames and call-to-action templates are not included in the Free plan. ${UPGRADE_HINT}`;
/** 403 message: FREE changed a grandfathered caption's template or colours (ADR-0005 D9, 2026-10-30). */
export const CAPTION_LOCKED_MESSAGE =
  `On the Free plan, this code's caption can have its text edited or be removed; its template and colours cannot change. ${UPGRADE_HINT}`;

/**
 * The 403 message for a style whose module or eye style, customer logo or
 * frame the plan does not include (ADR-0005 D9), or null when the plan
 * allows it. Same shape as contentTypeGateMessage. `storedFrame` is the
 * code's stored frame on PATCH (null on create): a stored caption is
 * grandfathered on FREE, which may edit its text or remove it
 * (frameChangeRefusal, D9 amendment of 2026-10-30).
 */
export function qrStyleGateMessage(plan: string, style: GatedStyle, storedFrame: GatedFrame | null = null): string | null {
  if (style.logo?.kind === 'asset') {
    const logoError = customerLogoGateMessage(plan);
    if (logoError) return logoError;
  }
  const frameRefusal = frameChangeRefusal(plan, storedFrame, style.frame);
  if (frameRefusal === 'plan') return FRAME_PLAN_MESSAGE;
  if (frameRefusal === 'caption-locked') return CAPTION_LOCKED_MESSAGE;
  const blocked = !planAllowsQrShape(plan, style.modules)
    ? `${style.modules} module style`
    : !planAllowsQrShape(plan, style.eyes)
      ? `${style.eyes} eye style`
      : null;
  if (!blocked) return null;
  return `The ${blocked} is not included in the Free plan. ${UPGRADE_HINT}`;
}

/**
 * The 403 message for uploading a customer logo, or saving a style that
 * draws one, on a plan without customer logos (D9); null when allowed.
 */
export function customerLogoGateMessage(plan: string): string | null {
  if (planAllowsCustomerLogo(plan)) return null;
  return `Customer logos are not included in the Free plan. ${UPGRADE_HINT}`;
}

/** What an image export asks for, as the print-export gate reads it (ADR-0005 D9). */
export interface GatedExport {
  readonly format: 'svg' | 'png' | 'pdf';
  /** A print size was requested (`size_mm`, `size_in` or `dpi`). */
  readonly isPrintSize: boolean;
}

export const PDF_EXPORT_PLAN_MESSAGE = `PDF export is not included in the Free plan. ${UPGRADE_HINT}`;
export const PRINT_PNG_PLAN_MESSAGE =
  `Print-size PNG export (size_mm, size_in or dpi) is not included in the Free plan; the Free plan exports SVG and PNG up to 1024 px. ${UPGRADE_HINT}`;

/**
 * The 403 message for an image export the plan does not include, or null
 * (D9): the vector PDF and print-size PNG need a paid plan. SVG (also at a
 * physical size) and PNG up to 1024 px are on every plan. Same body shape
 * as contentTypeGateMessage.
 */
export function exportGateMessage(plan: string, request: GatedExport): string | null {
  if (planAllowsPrintExport(plan)) return null;
  if (request.format === 'pdf') return PDF_EXPORT_PLAN_MESSAGE;
  if (request.format === 'png' && request.isPrintSize) return PRINT_PNG_PLAN_MESSAGE;
  return null;
}

/** Stable `code` of the 403 for a customer logo when the issuer is not verified. */
export const LOGO_VERIFICATION_REQUIRED_CODE = 'logo-verification-required';
export const LOGO_VERIFICATION_REQUIRED_MESSAGE = 'Custom logos require a verified domain or completed verification';

/** A 403 refusal: the message, and a stable code where clients must tell refusals apart. */
export interface GateRefusal {
  readonly message: string;
  readonly code?: string;
}

/** The organization fields the customer-logo gate reads. */
export const CUSTOMER_LOGO_ORG_SELECT = { plan: true, domainVerified: true, kycStatus: true } as const;

/** Eligibility input from an organization row; a missing row is FREE and unverified. */
export function logoEligibility(
  org: { plan?: string | null; domainVerified?: boolean | null; kycStatus?: string | null } | null,
): CustomerLogoEligibility {
  return {
    plan: org?.plan || 'FREE',
    domainVerified: org?.domainVerified === true,
    kycStatus: org?.kycStatus ?? 'PENDING',
  };
}

/**
 * The 403 for uploading a customer logo, or saving a style that draws one:
 * the plan gate on FREE (the same body as before), then the verified-issuer
 * gate (ADR-0005 D9 amendment, code `logo-verification-required`); null
 * when allowed.
 */
export function customerLogoGate(org: CustomerLogoEligibility): GateRefusal | null {
  const refusal = customerLogoRefusal(org);
  if (refusal === 'plan') return { message: customerLogoGateMessage(org.plan) as string };
  if (refusal === 'verification') {
    return { code: LOGO_VERIFICATION_REQUIRED_CODE, message: LOGO_VERIFICATION_REQUIRED_MESSAGE };
  }
  return null;
}

/** Stable `code` of the 403 for frame text that references QRAuth on an unverified issuer. */
export const FRAME_CLAIM_VERIFICATION_REQUIRED_CODE = 'frame-claim-verification-required';

/**
 * The 403 for a frame whose text references QRAuth when the issuer is not
 * verified (ADR-0005 D9, 2026-10-30; `isFrameClaimRefused`), or null.
 */
export function frameClaimGate(org: CustomerLogoEligibility, frame: GatedFrame | null | undefined): GateRefusal | null {
  const refused = isFrameClaimRefused(isIssuerVerified(org), frame ? { template: frame.template, text: frame.text ?? '' } : null);
  return refused ? { code: FRAME_CLAIM_VERIFICATION_REQUIRED_CODE, message: FRAME_QRAUTH_CLAIM_MESSAGE } : null;
}

/**
 * The 403 for saving `style`: the plan's shapes, frame and customer logo
 * (qrStyleGateMessage, with the code's stored frame on PATCH), then frame
 * text that references QRAuth and, for a customer logo, the verified
 * issuer. Callers pass changed styles only (an unchanged stored style is
 * exempt).
 */
export function qrStyleGate(org: CustomerLogoEligibility, style: GatedStyle, storedFrame: GatedFrame | null = null): GateRefusal | null {
  const planMessage = qrStyleGateMessage(org.plan, style, storedFrame);
  if (planMessage) return { message: planMessage };
  const claimRefusal = frameClaimGate(org, style.frame);
  if (claimRefusal) return claimRefusal;
  return style.logo?.kind === 'asset' ? customerLogoGate(org) : null;
}

export interface GateRefusalBody {
  readonly statusCode: 403;
  readonly error: 'Forbidden';
  readonly code?: string;
  readonly message: string;
}

/** The 403 body for a refusal, shaped like the content-type gate, plus `code` when there is one. */
export function gateRefusalBody(refusal: GateRefusal): GateRefusalBody {
  return {
    statusCode: 403,
    error: 'Forbidden',
    ...(refusal.code ? { code: refusal.code } : {}),
    message: refusal.message,
  };
}
