import { createHash } from 'node:crypto';
import type { Prisma, PrismaClient } from '@prisma/client';
import type { RequestMetadata } from '../lib/metadata.js';
import { revokeOidcAccessForUser } from '../lib/oidc-revocation.js';

/**
 * Runs inside the transaction that changes a device, after the change (an
 * audit-log entry), so the record and the change commit together.
 */
export type DeviceAuditHook = (tx: Prisma.TransactionClient, metadata: Record<string, unknown>) => Promise<void>;

type DeviceUpdate = { name?: string; trustLevel?: 'TRUSTED' | 'SUSPICIOUS' };

/** The fields an update changed, before and after; empty when none did. */
function changedDeviceFields(
  device: { name: string | null; trustLevel: string },
  data: DeviceUpdate,
): Record<string, { from: unknown; to: unknown }> {
  const entries = (['name', 'trustLevel'] as const)
    .filter((field) => data[field] !== undefined && data[field] !== device[field])
    .map((field) => [field, { from: device[field], to: data[field] }] as const);
  return Object.fromEntries(entries);
}

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
   * Update a device's name or trust level. `audit` runs in the update's
   * transaction when a field changed.
   */
  async updateDevice(deviceId: string, userId: string, data: DeviceUpdate, audit?: DeviceAuditHook) {
    return this.prisma.$transaction(async (tx) => {
      const device = await tx.trustedDevice.findFirst({
        where: { id: deviceId, userId, revokedAt: null },
      });

      if (!device) return null;

      const updated = await tx.trustedDevice.update({
        where: { id: deviceId },
        data: {
          name: data.name ?? device.name,
          trustLevel: data.trustLevel ?? device.trustLevel,
          trustedAt: data.trustLevel === 'TRUSTED' ? new Date() : device.trustedAt,
        },
      });

      const changes = changedDeviceFields(device, data);
      if (audit && Object.keys(changes).length > 0) await audit(tx, { changes });
      return updated;
    });
  }

  /**
   * Revoke a device and all its linked passkeys. `audit` runs in the same
   * transaction.
   */
  async revokeDevice(deviceId: string, userId: string, audit?: DeviceAuditHook) {
    return this.prisma.$transaction(async (tx) => {
      const device = await tx.trustedDevice.findFirst({
        where: { id: deviceId, userId, revokedAt: null },
      });

      if (!device) return null;

      // The conditional update claims the revocation: of two concurrent
      // revokes, only one changes the row, and only that one goes on to end
      // sessions and write the audit entry.
      const now = new Date();
      const claim = await tx.trustedDevice.updateMany({
        where: { id: deviceId, userId, revokedAt: null },
        data: { revokedAt: now, trustLevel: 'REVOKED' },
      });
      if (claim.count === 0) return null;

      // A revoked device may be the one an OP session or a relying-party
      // token was obtained on, and the OP does not track which, so all of the
      // user's are ended (audit 2026-10 FINDING-011). One transaction, so a
      // failure leaves everything untouched and the request retryable.
      const oidc = await revokeOidcAccessForUser(tx, userId);

      const passkeys = await tx.passkey.updateMany({
        where: { deviceId, revokedAt: null },
        data: { revokedAt: now },
      });

      if (audit) {
        await audit(tx, { name: device.name, trustLevel: device.trustLevel, revokedPasskeys: passkeys.count, oidc });
      }
      return { revoked: true };
    });
  }

  /**
   * Transition a device from SUSPICIOUS back to TRUSTED after
   * re-verification. `audit` runs in the same transaction.
   */
  async reverifyDevice(deviceId: string, userId: string, audit?: DeviceAuditHook) {
    return this.prisma.$transaction(async (tx) => {
      const { count } = await tx.trustedDevice.updateMany({
        where: { id: deviceId, userId, trustLevel: 'SUSPICIOUS' },
        data: { trustLevel: 'TRUSTED', trustedAt: new Date() },
      });

      if (count === 0) return null;
      if (audit) await audit(tx, { trustLevel: { from: 'SUSPICIOUS', to: 'TRUSTED' } });
      return { reverified: true };
    });
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
   *
   * F-011 (audit 2026-05-17): the joined string is SHA-256-hashed before
   * use so the stored value is opaque to DB-read attackers and matches the
   * "composite SHA-256 hash" behaviour documented in CLAUDE.md.
   */
  private buildFallbackFingerprint(meta: RequestMetadata): string | null {
    if (!meta.userAgent) return null;

    const parts = [meta.browser, meta.os, meta.deviceType].filter(Boolean).join('|');
    if (!parts) return null;
    return createHash('sha256').update(parts).digest('hex');
  }
}
