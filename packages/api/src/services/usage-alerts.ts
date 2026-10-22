import type { PrismaClient } from '@prisma/client';
import { VERIFICATION_ALERT_THRESHOLDS } from '@qrauth/shared';
import { getPlanLimit } from '../config/plan-limits.js';
import { sendUsageThresholdEmail } from '../lib/email.js';
import type { UsageLogger } from './usage.js';

/**
 * The alert threshold (percent) that this exact count crosses, or null.
 *
 * The meter is a Redis INCR, so each count value is returned to exactly one
 * request per period. Alerting on equality with the threshold's count sends
 * each alert once per org per month without any extra dedupe state. A count
 * of 0 (Redis failure) never alerts.
 */
export function crossedThreshold(
  count: number,
  limit: number,
  thresholds: readonly number[] = VERIFICATION_ALERT_THRESHOLDS,
): number | null {
  if (count <= 0 || limit <= 0) return null;
  // Highest first: when a small limit makes two thresholds land on the same
  // count, the more severe alert is the one sent.
  const highestFirst = [...thresholds].sort((a, b) => b - a);
  return highestFirst.find((threshold) => count === Math.ceil((limit * threshold) / 100)) ?? null;
}

/**
 * Email the org when a verification increment lands exactly on an alert
 * threshold. Never throws: the verify path must not fail because of an alert.
 */
export async function notifyVerificationThreshold(
  prisma: PrismaClient,
  logger: UsageLogger,
  orgId: string,
  plan: string,
  count: number,
): Promise<void> {
  const limit = getPlanLimit(plan, 'verifications');
  if (limit === 'unlimited') return;
  const threshold = crossedThreshold(count, limit);
  if (threshold === null) return;

  try {
    const org = await prisma.organization.findUnique({
      where: { id: orgId },
      select: { name: true, email: true, billingEmail: true },
    });
    if (!org) return;
    await sendUsageThresholdEmail(org.billingEmail || org.email, org.name, {
      threshold,
      used: count,
      limit,
      plan,
    });
  } catch (err) {
    logger.warn(
      { orgId, threshold, err: err instanceof Error ? err.message : String(err) },
      'usage: verification threshold email failed',
    );
  }
}
