import { redis } from '../lib/cache.js';

const DEFAULT_WEIGHTS: Record<string, number> = {
  DUPLICATE_LOCATION: 30,
  PROXY_DETECTED: 25,
  GEO_IMPOSSIBLE: 40,
  PATTERN_ANOMALY: 20,
  MANUAL_REPORT: 15,
};

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
    const current = await this.getWeight(orgId, signalType);

    // Adjust by 10% in the appropriate direction
    const adjustment = current * 0.1;
    const newWeight = isFalsePositive
      ? Math.max(5, current - adjustment)   // Floor of 5
      : Math.min(50, current + adjustment); // Ceiling of 50

    const key = `qrauth:weights:${orgId}`;
    await redis.hset(key, signalType, newWeight.toFixed(1));
    return newWeight;
  }
}
