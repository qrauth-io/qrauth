import type { PrismaClient } from '@prisma/client';
import type { FeatureVector } from './feature-extraction.js';
import type { RuleEvalResult } from './dynamic-rules.js';

type IncidentDb = { fraudIncident: Pick<PrismaClient['fraudIncident'], 'create'> };

/**
 * Persist one FraudIncident per fired dynamic rule.
 *
 * Incidents from SHADOW rules are stored with shadow = true: they are for
 * superadmin review only, so they are left out of trust scores and customer
 * views. No alerts are sent from here for any dynamic-rule incident (ACTIVE
 * or SHADOW); alerting stays with FraudDetectionService.analyzeScan /
 * reportIncident.
 */
export async function recordRuleIncidents(
  db: IncidentDb,
  scan: { qrCodeId: string; scanId?: string | null; features: FeatureVector },
  firedRules: RuleEvalResult[],
): Promise<void> {
  for (const result of firedRules) {
    try {
      await db.fraudIncident.create({
        data: {
          qrCodeId: scan.qrCodeId,
          scanId: scan.scanId,
          type: result.action.type as never,
          severity: result.action.severity as never,
          shadow: result.shadow,
          details: {
            reason: result.action.reason,
            ruleName: result.ruleName,
            ruleId: result.ruleId,
            features: scan.features,
          } as never,
        },
      });
    } catch (err) {
      // One failed insert (e.g. the scan row is gone) must not drop the rest.
      console.warn(
        '[fraud.rule_incident] insert failed ' +
          JSON.stringify({ ruleId: result.ruleId, qrCodeId: scan.qrCodeId, error: (err as Error).message }),
      );
    }
  }
}
