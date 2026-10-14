import type { PrismaClient } from '@prisma/client';
import { checkAlgVersion, type AlgVersionStatus } from '@qrauth/shared';
import { ALGORITHM_VERSION_PENDING } from './hybrid-signing.js';

/**
 * Operational visibility into the PQC migration state for an organization.
 *
 * The point of this service is to give operators a single endpoint that
 * answers "where am I in the post-quantum migration, and what's broken
 * right now". We've shipped seven crypto layers and the only way to see
 * the running state today is to grep logs — that doesn't scale past
 * the first integration partner.
 *
 * Three signals matter:
 *
 *   1. **Algorithm distribution** — how many QR codes are on which
 *      algorithm version. ALGORITHM.md §11.3 specifically calls out
 *      surfacing "tokens using deprecated cryptography" as a
 *      compliance metric. We extend that to count every state.
 *
 *   2. **Stuck rows** — QRs in `ecdsa-pending-slhdsa-v1` for longer
 *      than the reconciler grace window. A stuck row means the
 *      reconciler is failing or the BatchSigner is wedged; either way
 *      the operator needs to know within minutes, not hours.
 *
 *   3. **Bridge coverage** — passkeys missing the PQC bridge half.
 *      Either they were registered before the bridge layer landed
 *      (legacy) or the user lost their IndexedDB entry. Under the
 *      `optional` tenant policy these still verify, but they're a
 *      migration target.
 *
 * Plus rotation watchdogs (MAC key age) and aggregate batch counts so
 * the dashboard has something to chart over time.
 *
 * Status colors are deliberately opinionated:
 *   - **red**: something is actively broken — stuck rows older than the
 *     fail threshold, or rejected algVersions in flight (Phase 3+).
 *   - **yellow**: degraded but not broken — deprecated algorithms,
 *     unbridged passkeys under non-disabled policy, MAC keys past their
 *     rotation due date.
 *   - **green**: every measurable axis is on the recommended path.
 */

export interface PqcHealthReport {
  organizationId: string;
  generatedAt: string;
  status: 'green' | 'yellow' | 'red';
  warnings: string[];

  qrCodes: {
    total: number;
    byAlgVersion: Record<string, number>;
    byStatus: Record<AlgVersionStatus, number>;
    pendingStuck: number; // pending older than the stuck threshold
  };

  passkeys: {
    total: number;
    withBridge: number;
    withoutBridge: number;
  };

  macKeys: {
    activeVersion: number | null;
    activeAgeDays: number | null;
    rotatedCount: number;
    retiredCount: number;
    daysUntilRotation: number | null; // negative when overdue
  };

  signedBatches: {
    total: number;
    lastBatchAt: string | null;
  };
}

/** Pending rows older than this are considered stuck. The reconciler
 *  runs every 60s and should drain pending rows within minutes. An hour
 *  is a comfortable upper bound — anything past that is genuinely broken. */
const STUCK_PENDING_HOURS = 1;

/** MAC keys rotate every 90 days (ALGORITHM.md §10.3). The "yellow"
 *  threshold fires once we're within 7 days of the rotation due date. */
const MAC_KEY_ROTATION_DAYS = 90;
const MAC_KEY_ROTATION_WARNING_DAYS = 7;

export class PqcHealthService {
  constructor(private prisma: PrismaClient) {}

  async getOrgHealth(organizationId: string): Promise<PqcHealthReport> {
    const generatedAt = new Date();
    const stuckCutoff = new Date(generatedAt.getTime() - STUCK_PENDING_HOURS * 60 * 60 * 1000);

    // ---- QR code aggregation ------------------------------------------------
    const qrAggregation = await this.prisma.qRCode.groupBy({
      by: ['algVersion'],
      where: { organizationId },
      _count: { _all: true },
    });

    const byAlgVersion: Record<string, number> = {};
    const byStatus: Record<AlgVersionStatus, number> = {
      accepted: 0,
      deprecated: 0,
      rejected: 0,
      unknown: 0,
    };
    let totalQrs = 0;
    for (const row of qrAggregation) {
      const version = row.algVersion ?? 'null';
      byAlgVersion[version] = row._count._all;
      byStatus[checkAlgVersion(row.algVersion)] += row._count._all;
      totalQrs += row._count._all;
    }

    const pendingStuck = await this.prisma.qRCode.count({
      where: {
        organizationId,
        algVersion: ALGORITHM_VERSION_PENDING,
        createdAt: { lt: stuckCutoff },
      },
    });

    // ---- Passkey bridge coverage -------------------------------------------
    // Passkeys are user-scoped (no direct organizationId), so we walk via
    // the user's memberships in this org. A user who's a member of multiple
    // orgs has the same passkeys counted in each — that's the right answer
    // because the same key would unlock auth into either tenant.
    const passkeyCounts = await this.prisma.passkey.findMany({
      where: {
        revokedAt: null,
        user: {
          memberships: { some: { organizationId } },
        },
      },
      select: { bridgePublicKey: true },
    });
    const totalPasskeys = passkeyCounts.length;
    const withBridge = passkeyCounts.filter((p) => p.bridgePublicKey !== null).length;
    const withoutBridge = totalPasskeys - withBridge;

    // ---- MAC key lifecycle -------------------------------------------------
    const activeMacKey = await this.prisma.orgMacKey.findFirst({
      where: { organizationId, status: 'ACTIVE' },
      orderBy: { version: 'desc' },
    });
    const rotatedMacKeyCount = await this.prisma.orgMacKey.count({
      where: { organizationId, status: 'ROTATED' },
    });
    const retiredMacKeyCount = await this.prisma.orgMacKey.count({
      where: { organizationId, status: 'RETIRED' },
    });

    let activeAgeDays: number | null = null;
    let daysUntilRotation: number | null = null;
    if (activeMacKey) {
      const ageMs = generatedAt.getTime() - activeMacKey.createdAt.getTime();
      activeAgeDays = Math.floor(ageMs / (24 * 60 * 60 * 1000));
      daysUntilRotation = MAC_KEY_ROTATION_DAYS - activeAgeDays;
    }

    // ---- Signed batches ----------------------------------------------------
    const signedBatchCount = await this.prisma.signedBatch.count({
      where: { organizationId },
    });
    const lastBatch = await this.prisma.signedBatch.findFirst({
      where: { organizationId },
      orderBy: { issuedAt: 'desc' },
      select: { issuedAt: true },
    });

    // ---- Status synthesis --------------------------------------------------
    const warnings: string[] = [];
    let status: PqcHealthReport['status'] = 'green';

    if (pendingStuck > 0) {
      status = 'red';
      warnings.push(
        `${pendingStuck} QR code(s) stuck in ecdsa-pending state for >${STUCK_PENDING_HOURS}h — check reconciler worker`,
      );
    }
    if (byStatus.rejected > 0) {
      status = 'red';
      warnings.push(`${byStatus.rejected} QR code(s) using rejected algorithm versions`);
    }
    if (byStatus.unknown > 0) {
      // Unknown is a schema violation — fail closed at the verifier, but
      // still report at the operator dashboard so they can investigate.
      status = 'red';
      warnings.push(`${byStatus.unknown} QR code(s) using unrecognized algorithm versions`);
    }

    if (status !== 'red') {
      if (byStatus.deprecated > 0) {
        status = 'yellow';
        warnings.push(
          `${byStatus.deprecated} QR code(s) using deprecated cryptography — schedule re-issuance`,
        );
      }
      if (withoutBridge > 0) {
        status = 'yellow';
        warnings.push(
          `${withoutBridge} passkey(s) missing PQC bridge — affected users should re-register on this device`,
        );
      }
      if (daysUntilRotation !== null && daysUntilRotation < 0) {
        status = 'yellow';
        warnings.push(
          `MAC key v${activeMacKey?.version} is overdue for rotation by ${-daysUntilRotation} day(s)`,
        );
      } else if (
        daysUntilRotation !== null &&
        daysUntilRotation <= MAC_KEY_ROTATION_WARNING_DAYS
      ) {
        if (status === 'green') status = 'yellow';
        warnings.push(
          `MAC key v${activeMacKey?.version} rotates in ${daysUntilRotation} day(s)`,
        );
      }
    }

    return {
      organizationId,
      generatedAt: generatedAt.toISOString(),
      status,
      warnings,
      qrCodes: {
        total: totalQrs,
        byAlgVersion,
        byStatus,
        pendingStuck,
      },
      passkeys: {
        total: totalPasskeys,
        withBridge,
        withoutBridge,
      },
      macKeys: {
        activeVersion: activeMacKey?.version ?? null,
        activeAgeDays,
        rotatedCount: rotatedMacKeyCount,
        retiredCount: retiredMacKeyCount,
        daysUntilRotation,
      },
      signedBatches: {
        total: signedBatchCount,
        lastBatchAt: lastBatch?.issuedAt.toISOString() ?? null,
      },
    };
  }
}

export {
  STUCK_PENDING_HOURS,
  MAC_KEY_ROTATION_DAYS,
  MAC_KEY_ROTATION_WARNING_DAYS,
};
