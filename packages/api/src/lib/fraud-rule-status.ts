import type { FraudRuleStatus } from '@prisma/client';

/**
 * Fraud rule lifecycle helpers.
 *
 * SHADOW  evaluated; incidents are recorded with shadow = true (internal only)
 * ACTIVE  evaluated; incidents are live (trust score, customer views)
 * DISABLED not evaluated
 *
 * The deprecated `enabled` column is kept in step (true exactly when ACTIVE)
 * so a process that predates `status` (e.g. during a deploy) evaluates only
 * ACTIVE rules. Every status write goes through ruleStatusData().
 */

export const EVALUATED_RULE_STATUSES: readonly FraudRuleStatus[] = ['ACTIVE', 'SHADOW'];

export const FRAUD_RULE_CACHE_KEY = 'fraud_rules:active';

export function statusFromEnabled(enabled: boolean): FraudRuleStatus {
  return enabled ? 'ACTIVE' : 'DISABLED';
}

export function ruleStatusData(status: FraudRuleStatus): { status: FraudRuleStatus; enabled: boolean } {
  return { status, enabled: status === 'ACTIVE' };
}

/** Rules cached before the upgrade carry no status; they were all live. */
export function isShadowStatus(status: FraudRuleStatus | string | null | undefined): boolean {
  return status === 'SHADOW';
}
