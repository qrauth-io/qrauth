import type { PrismaClient } from '@prisma/client';
import type { RequestMetadata } from '../lib/metadata.js';

export class DeviceService {
  constructor(private prisma: PrismaClient) {}

  /**
   * Identify or create a device record for the given user and request metadata.
   * Returns the device and whether it was newly created.
   */
  async identifyDevice(userId: string, meta: RequestMetadata) {
    // Build a composite fingerprint from available signals
    const fingerprint = meta.fingerprint
      || this.buildFallbackFingerprint(meta);

    if (!fingerprint) {
      return { device: null, isNew: false };
    }

    const existing = await this.prisma.trustedDevice.findUnique({
      where: { userId_fingerprint: { userId, fingerprint } },
    });

    if (existing) {
      // Don't update revoked devices
      if (existing.revokedAt) {
        return { device: existing, isNew: false };
      }

      const updated = await this.prisma.trustedDevice.update({
        where: { id: existing.id },
        data: {
          lastSeenAt: new Date(),
          ipCountry: meta.ipCountry || existing.ipCountry,
          ipCity: meta.ipCity || existing.ipCity,
          browser: meta.browser || existing.browser,
          os: meta.os || existing.os,
          deviceType: meta.deviceType || existing.deviceType,
        },
      });

      return { device: updated, isNew: false };
    }

    const device = await this.prisma.trustedDevice.create({
      data: {
        userId,
        fingerprint,
        deviceType: meta.deviceType,
        browser: meta.browser,
        os: meta.os,
        ipCountry: meta.ipCountry,
        ipCity: meta.ipCity,
      },
    });

    return { device, isNew: true };
  }

  /**
   * List all non-revoked devices for a user, with passkey counts.
   */
  async listDevices(userId: string) {
    const devices = await this.prisma.trustedDevice.findMany({
      where: { userId, revokedAt: null },
      orderBy: { lastSeenAt: 'desc' },
      include: { _count: { select: { passkeys: true } } },
    });

    return devices.map((d) => ({
      ...d,
      passkeyCount: d._count.passkeys,
      _count: undefined,
    }));
  }

  /**
   * Update a device's name or trust level.
   */
  async updateDevice(
    deviceId: string,
    userId: string,
    data: { name?: string; trustLevel?: 'TRUSTED' | 'SUSPICIOUS' },
  ) {
    const device = await this.prisma.trustedDevice.findFirst({
      where: { id: deviceId, userId, revokedAt: null },
    });

    if (!device) return null;

    return this.prisma.trustedDevice.update({
      where: { id: deviceId },
      data: {
        name: data.name ?? device.name,
        trustLevel: data.trustLevel ?? device.trustLevel,
        trustedAt: data.trustLevel === 'TRUSTED' ? new Date() : device.trustedAt,
      },
    });
  }

  /**
   * Revoke a device and all its linked passkeys.
   */
  async revokeDevice(deviceId: string, userId: string) {
    const device = await this.prisma.trustedDevice.findFirst({
      where: { id: deviceId, userId, revokedAt: null },
    });

    if (!device) return null;

    const now = new Date();

    await this.prisma.$transaction([
      this.prisma.trustedDevice.update({
        where: { id: deviceId },
        data: { revokedAt: now, trustLevel: 'REVOKED' },
      }),
      this.prisma.passkey.updateMany({
        where: { deviceId, revokedAt: null },
        data: { revokedAt: now },
      }),
    ]);

    return { revoked: true };
  }

  /**
   * Transition a device from SUSPICIOUS back to TRUSTED after re-verification.
   */
  async reverifyDevice(deviceId: string, userId: string) {
    const { count } = await this.prisma.trustedDevice.updateMany({
      where: { id: deviceId, userId, trustLevel: 'SUSPICIOUS' },
      data: { trustLevel: 'TRUSTED', trustedAt: new Date() },
    });

    if (count === 0) return null;
    return { reverified: true };
  }

  /**
   * Check whether a fingerprint is currently revoked for a given user.
   */
  async isDeviceRevoked(userId: string, fingerprint: string): Promise<boolean> {
    const device = await this.prisma.trustedDevice.findUnique({
      where: { userId_fingerprint: { userId, fingerprint } },
      select: { trustLevel: true },
    });
    return device?.trustLevel === 'REVOKED';
  }

  /**
   * Get the current device for a request, if it can be identified.
   */
  async getCurrentDevice(userId: string, meta: RequestMetadata) {
    const fingerprint = meta.fingerprint
      || this.buildFallbackFingerprint(meta);

    if (!fingerprint) return null;

    return this.prisma.trustedDevice.findUnique({
      where: { userId_fingerprint: { userId, fingerprint } },
      include: { _count: { select: { passkeys: true } } },
    });
  }

  /**
   * Build a fallback fingerprint from user-agent + device type when no
   * explicit fingerprint header is provided.
   */
  private buildFallbackFingerprint(meta: RequestMetadata): string | null {
    if (!meta.userAgent) return null;

    // Simple hash of UA string components — not cryptographically strong,
    // but sufficient for "same browser on same device" heuristics.
    const parts = [meta.browser, meta.os, meta.deviceType].filter(Boolean).join('|');
    return parts || null;
  }
}
