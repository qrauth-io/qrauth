import { redis } from '../lib/cache.js';

const DEFAULT_WEIGHTS: Record<string, number> = {
  DUPLICATE_LOCATION: 30,
  PROXY_DETECTED: 25,
  GEO_IMPOSSIBLE: 40,
  PATTERN_ANOMALY: 20,
  MANUAL_REPORT: 15,
};

// F-004 (audit 2026-05-17): bound which signal keys the adaptive scorer is
// allowed to touch. Without this, a future caller could pollute the Redis
// hash with arbitrary keys, growing memory and contaminating analytics.
const VALID_SIGNAL_TYPES = new Set(Object.keys(DEFAULT_WEIGHTS));

const WEIGHT_FLOOR = 5;
const WEIGHT_CEILING = 50;
const ADJUSTMENT_PCT = 0.1;

export class AdaptiveScoringService {
  /**
   * Get the current weight for a signal type for an organization.
   */
  async getWeight(orgId: string, signalType: string): Promise<number> {
    const key = `qrauth:weights:${orgId}`;
    const stored = await redis.hget(key, signalType);
    if (stored) return parseFloat(stored);
    return DEFAULT_WEIGHTS[signalType] ?? 15;
  }

  /**
   * Get all weights for an organization.
   */
  async getAllWeights(orgId: string): Promise<Record<string, number>> {
    const key = `qrauth:weights:${orgId}`;
    const stored = await redis.hgetall(key);
    const weights = { ...DEFAULT_WEIGHTS };
    for (const [k, v] of Object.entries(stored)) {
      weights[k] = parseFloat(v);
    }
    return weights;
  }

  /**
   * Adjust weight after incident resolution.
   * False positive → decrease weight (less aggressive)
   * True positive → increase weight slightly (more aggressive)
   */
  async adjustWeight(
    orgId: string,
    signalType: string,
    isFalsePositive: boolean,
  ): Promise<number> {
    // F-004: reject unknown signal types up front. Prevents arbitrary key
    // pollution in the per-org Redis hash and keeps audit logs interpretable.
    if (!VALID_SIGNAL_TYPES.has(signalType)) {
      throw new Error(
        `adaptive-scoring: unknown signalType "${signalType}". ` +
          `Allowed: ${Array.from(VALID_SIGNAL_TYPES).join(', ')}.`,
      );
    }

    const current = await this.getWeight(orgId, signalType);

    // Adjust by ADJUSTMENT_PCT in the appropriate direction, clamped to
    // [WEIGHT_FLOOR, WEIGHT_CEILING].
    const adjustment = current * ADJUSTMENT_PCT;
    const newWeight = isFalsePositive
      ? Math.max(WEIGHT_FLOOR, current - adjustment)
      : Math.min(WEIGHT_CEILING, current + adjustment);

    const key = `qrauth:weights:${orgId}`;
    await redis.hset(key, signalType, newWeight.toFixed(1));

    // F-004: structured audit log. The AuditLog table requires non-null
    // organizationId + userId (FK constraints); this adjustment is an
    // automated background mutation with no acting user, so we emit a
    // pino/console line operators can grep on. The line is intentionally
    // single-line JSON so it survives log aggregation cleanly.
    console.info(
      '[fraud_weight.adjust] ' +
        JSON.stringify({
          organizationId: orgId,
          signalType,
          previousWeight: current,
          newWeight,
          deltaPct: ADJUSTMENT_PCT * 100,
          direction: isFalsePositive ? 'decrease' : 'increase',
          floor: WEIGHT_FLOOR,
          ceiling: WEIGHT_CEILING,
          at: new Date().toISOString(),
        }),
    );

    return newWeight;
  }
}
