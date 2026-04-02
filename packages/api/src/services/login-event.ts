import type { PrismaClient } from '@prisma/client';
import { MAX_FAILED_LOGIN_ATTEMPTS, ACCOUNT_LOCKOUT_MINUTES } from '@vqr/shared';
import type { RequestMetadata } from '../lib/metadata.js';

export class LoginEventService {
  constructor(private prisma: PrismaClient) {}

  /**
   * Record a login event (success or failure).
   */
  async record(userId: string, success: boolean, provider: string, meta: RequestMetadata) {
    await this.prisma.loginEvent.create({
      data: {
        userId,
        success,
        provider: provider as any,
        ipAddress: meta.ipAddress || null,
        ipCountry: meta.ipCountry || null,
        ipCity: meta.ipCity || null,
        userAgent: meta.userAgent || null,
        deviceType: meta.deviceType || null,
        browser: meta.browser || null,
        os: meta.os || null,
        fingerprint: meta.fingerprint || null,
      },
    });
  }

  /**
   * Check if account is locked. Returns lockout expiry or null.
   */
  async checkLockout(userId: string): Promise<Date | null> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { lockedUntil: true },
    });

    if (user?.lockedUntil && user.lockedUntil > new Date()) {
      return user.lockedUntil;
    }

    return null;
  }

  /**
   * Increment failed login attempts. Lock account if threshold exceeded.
   */
  async recordFailedAttempt(userId: string): Promise<{ locked: boolean; lockedUntil?: Date }> {
    const user = await this.prisma.user.update({
      where: { id: userId },
      data: { failedLoginAttempts: { increment: 1 } },
      select: { failedLoginAttempts: true },
    });

    if (user.failedLoginAttempts >= MAX_FAILED_LOGIN_ATTEMPTS) {
      const lockedUntil = new Date(Date.now() + ACCOUNT_LOCKOUT_MINUTES * 60 * 1000);
      await this.prisma.user.update({
        where: { id: userId },
        data: { lockedUntil },
      });
      return { locked: true, lockedUntil };
    }

    return { locked: false };
  }

  /**
   * Reset failed attempts on successful login.
   */
  async resetFailedAttempts(userId: string) {
    await this.prisma.user.update({
      where: { id: userId },
      data: { failedLoginAttempts: 0, lockedUntil: null },
    });
  }

  /**
   * Get recent login events for a user.
   */
  async getHistory(userId: string, limit: number = 50) {
    return this.prisma.loginEvent.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
      take: limit,
    });
  }

  /**
   * Check if login is from a new device/location (suspicious login detection).
   */
  async isSuspiciousLogin(userId: string, meta: RequestMetadata): Promise<boolean> {
    // Check if we've seen this country before for this user
    if (!meta.ipCountry) return false;

    const previousCountries = await this.prisma.loginEvent.findMany({
      where: { userId, success: true, ipCountry: { not: null } },
      select: { ipCountry: true },
      distinct: ['ipCountry'],
      take: 20,
    });

    const knownCountries = new Set(previousCountries.map((e) => e.ipCountry));

    // If user has login history and this is a new country, flag it
    if (knownCountries.size > 0 && !knownCountries.has(meta.ipCountry)) {
      return true;
    }

    return false;
  }
}
