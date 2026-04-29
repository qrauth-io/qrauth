import { redis } from '../lib/cache.js';
import type { PrismaClient } from '@prisma/client';

const KEY_PREFIX = 'qrauth:usage:';

// Plan limits
const PLAN_LIMITS: Record<string, { qrCodes: number; verifications: number; authSessions: number }> = {
  FREE: { qrCodes: 100, verifications: 1_000, authSessions: 1_000 },
  PRO: { qrCodes: -1, verifications: 50_000, authSessions: 50_000 }, // -1 = unlimited
  ENTERPRISE: { qrCodes: -1, verifications: -1, authSessions: -1 },
};

function monthKey(): string {
  const now = new Date();
  return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
}

export class UsageService {
  constructor(private prisma: PrismaClient) {}

  /**
   * Increment a usage counter for the org. Returns the new count.
   */
  async increment(orgId: string, metric: 'verifications' | 'authSessions'): Promise<number> {
    const key = `${KEY_PREFIX}${orgId}:${metric}:${monthKey()}`;
    const count = await redis.incr(key);
    // Set TTL to 35 days on first increment (covers the month + buffer)
    if (count === 1) {
      await redis.expire(key, 35 * 24 * 60 * 60);
    }
    return count;
  }

  /**
   * Get current usage counts for the org.
   */
  async getUsage(orgId: string): Promise<{
    verifications: number;
    authSessions: number;
    qrCodes: number;
    period: string;
  }> {
    const period = monthKey();
    const [verifications, authSessions] = await Promise.all([
      redis.get(`${KEY_PREFIX}${orgId}:verifications:${period}`),
      redis.get(`${KEY_PREFIX}${orgId}:authSessions:${period}`),
    ]);

    // QR codes count is a total (not monthly), get from DB
    const qrCodes = await this.prisma.qRCode.count({
      where: { organizationId: orgId, status: { not: 'REVOKED' } },
    });

    return {
      verifications: parseInt(verifications || '0', 10),
      authSessions: parseInt(authSessions || '0', 10),
      qrCodes,
      period,
    };
  }

  /**
   * Check if the org can perform an operation. Returns null if allowed,
   * or an error message string if quota is exceeded.
   */
  async checkQuota(
    orgId: string,
    plan: string,
    metric: 'qrCodes' | 'verifications' | 'authSessions',
  ): Promise<string | null> {
    const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.FREE;
    const limit = limits[metric];

    if (limit === -1) return null; // unlimited

    if (metric === 'qrCodes') {
      const count = await this.prisma.qRCode.count({
        where: { organizationId: orgId, status: { not: 'REVOKED' } },
      });
      if (count >= limit) {
        return `QR code limit reached (${limit}). Upgrade your plan at https://qrauth.io/dashboard/settings.`;
      }
      return null;
    }

    // Monthly metrics
    const period = monthKey();
    const current = await redis.get(`${KEY_PREFIX}${orgId}:${metric}:${period}`);
    const count = parseInt(current || '0', 10);

    if (count >= limit) {
      return `Monthly ${metric} limit reached (${limit}). Upgrade your plan at https://qrauth.io/dashboard/settings.`;
    }
    return null;
  }

  /**
   * Get plan limits for a given plan.
   */
  getLimits(plan: string): { qrCodes: number; verifications: number; authSessions: number } {
    return PLAN_LIMITS[plan] || PLAN_LIMITS.FREE;
  }
}
