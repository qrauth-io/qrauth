/**
 * Quota response-header helpers for the /verify route (Issue #65).
 *
 * Lifted out of routes/verify.ts so the header logic can be unit-tested
 * without spinning up the whole route's dependency graph (Prisma, MAC
 * service, hybrid signing, transparency log, fraud detection, etc.).
 */
import type { FastifyReply } from 'fastify';
import type { UsageService } from '../services/usage.js';
import { getPlanLimit } from '../config/plan-limits.js';

/**
 * Soft-meter gate (Issue #65, 5A).
 *
 * Counts SUCCESSFUL verifications only. A failed-signature attempt is
 * not chargeable and would otherwise let an attacker spam the meter
 * for free. Returns true iff `signatureValid` — the verify route
 * branches on this to decide whether to call UsageService.increment.
 *
 * Trivial helper, exported so tests can pin the decision in case the
 * route's call-site is later wrapped in additional logic that might
 * accidentally re-introduce the unconditional increment.
 */
export function shouldMeterVerification(signatureValid: boolean): boolean {
  return signatureValid === true;
}

/**
 * First day of next UTC month at 00:00:00.000Z. Used as `X-Quota-Reset`:
 * the timestamp at which the verifications meter rolls over.
 *
 * Pure function with an injectable clock so tests can pin specific
 * timestamps without touching `Date.now()`.
 */
export function nextMonthResetIso(now: Date = new Date()): string {
  const y = now.getUTCFullYear();
  const m = now.getUTCMonth(); // 0-based; (m + 1) on 11 wraps to year+1, month 0
  const next = new Date(Date.UTC(y, m + 1, 1, 0, 0, 0, 0));
  return next.toISOString();
}

/**
 * Attach `X-Quota-*` headers to a /verify response.
 *
 *   X-Quota-Plan   — always present, the org's plan tier
 *   X-Quota-Used   — current verifications count for the live period
 *   X-Quota-Reset  — ISO8601 instant the meter rolls over (start of next month UTC)
 *   X-Quota-Limit  — the cap, OR omitted entirely when the plan is unlimited.
 *                    Header absence signals "no cap" — the SDK and dashboard
 *                    branch on `headers.has('X-Quota-Limit')`.
 *
 * Errors are absorbed by design. A header miss is preferable to a
 * failed verify response.
 */
export async function attachQuotaHeaders(
  reply: Pick<FastifyReply, 'header'>,
  usageService: Pick<UsageService, 'current'>,
  orgId: string,
  plan: string,
  now: Date = new Date(),
): Promise<void> {
  try {
    const used = await usageService.current(orgId, 'verifications');
    const limit = getPlanLimit(plan, 'verifications');
    reply.header('X-Quota-Used', String(used));
    reply.header('X-Quota-Reset', nextMonthResetIso(now));
    reply.header('X-Quota-Plan', plan);
    if (limit !== 'unlimited') {
      reply.header('X-Quota-Limit', String(limit));
    }
  } catch {
    // Never block the verify response on a header read.
  }
}
