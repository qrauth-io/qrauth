import type { PrismaClient } from '@prisma/client';

/**
 * Per-org WebAuthn PQC bridge enforcement modes (ALGORITHM.md §9).
 * Strictness order is `required > optional > disabled` — see
 * `resolveBridgePolicyForUser` for cross-org resolution.
 */
export type BridgePolicy = 'required' | 'optional' | 'disabled';

export const BRIDGE_POLICY_VALUES: readonly BridgePolicy[] = [
  'required',
  'optional',
  'disabled',
] as const;

/**
 * Default policy for users with no DevicePolicy row in any of their orgs.
 * `required` is the safest default — operators have to explicitly opt out.
 */
export const DEFAULT_BRIDGE_POLICY: BridgePolicy = 'required';

const BRIDGE_POLICY_STRICTNESS: Record<BridgePolicy, number> = {
  required: 2,
  optional: 1,
  disabled: 0,
};

export class DevicePolicyService {
  constructor(private prisma: PrismaClient) {}

  async getPolicy(organizationId: string) {
    return this.prisma.devicePolicy.findUnique({
      where: { organizationId },
    });
  }

  async upsertPolicy(
    organizationId: string,
    data: {
      maxDevices?: number;
      requireBiometric?: boolean;
      geoFenceLat?: number | null;
      geoFenceLng?: number | null;
      geoFenceRadiusKm?: number | null;
      autoRevokeAfterDays?: number | null;
      bridgePolicy?: BridgePolicy;
    },
  ) {
    return this.prisma.devicePolicy.upsert({
      where: { organizationId },
      create: { organizationId, ...data },
      update: data,
    });
  }

  /**
   * Resolve the effective bridge policy for a user across all of their
   * organization memberships. Returns the **strictest** policy in force.
   *
   * Strictness order: `required > optional > disabled`. So a user who
   * belongs to both a government tenant (`required`) and a personal
   * tenant (`disabled`) is held to `required` — the toughest constraint
   * always wins.
   *
   * Falls back to `DEFAULT_BRIDGE_POLICY` (`required`) when the user
   * has no membership policies set, so the safe default is in force
   * even on a fresh deployment with no policy rows.
   */
  async resolveBridgePolicyForUser(userId: string): Promise<BridgePolicy> {
    const memberships = await this.prisma.membership.findMany({
      where: { userId },
      select: {
        organization: {
          select: {
            devicePolicy: { select: { bridgePolicy: true } },
          },
        },
      },
    });

    let strongest: BridgePolicy = DEFAULT_BRIDGE_POLICY;
    let strongestRank = -1;
    let sawAny = false;

    for (const m of memberships) {
      const policyValue = m.organization.devicePolicy?.bridgePolicy;
      if (!policyValue) continue;
      sawAny = true;
      const candidate = (
        (BRIDGE_POLICY_VALUES as readonly string[]).includes(policyValue)
          ? policyValue
          : DEFAULT_BRIDGE_POLICY
      ) as BridgePolicy;
      const rank = BRIDGE_POLICY_STRICTNESS[candidate];
      if (rank > strongestRank) {
        strongest = candidate;
        strongestRank = rank;
      }
    }

    return sawAny ? strongest : DEFAULT_BRIDGE_POLICY;
  }

  /**
   * Check if a user's active device count has reached the org policy limit.
   * Returns an error message string if the limit is reached, or null if ok.
   */
  async checkDeviceLimit(userId: string, organizationId: string): Promise<string | null> {
    const policy = await this.getPolicy(organizationId);
    if (!policy) return null;

    const deviceCount = await this.prisma.trustedDevice.count({
      where: { userId, trustLevel: { not: 'REVOKED' } },
    });

    if (deviceCount >= policy.maxDevices) {
      return `Device limit reached (${policy.maxDevices}). Revoke an existing device before adding a new one.`;
    }

    return null;
  }
}
