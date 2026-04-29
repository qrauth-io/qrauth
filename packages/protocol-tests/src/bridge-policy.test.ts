import { describe, it, expect } from "vitest";
import {
  DevicePolicyService,
  DEFAULT_BRIDGE_POLICY,
  BRIDGE_POLICY_VALUES,
  type BridgePolicy,
} from "../../api/src/services/device-policy.js";

/**
 * In-memory fake of the slice of Prisma the resolver touches:
 *   prisma.membership.findMany({ where: { userId }, select: {...} })
 *
 * Each test feeds a list of memberships with their devicePolicy values
 * and asserts the resolved policy. Avoids spinning Postgres for a pure
 * branching test.
 */
class FakeMembershipPrisma {
  private rows: Array<{ userId: string; bridgePolicy: BridgePolicy | null }> = [];

  addMembership(userId: string, bridgePolicy: BridgePolicy | null) {
    this.rows.push({ userId, bridgePolicy });
  }

  membership = {
    findMany: async ({ where }: { where: { userId: string } }) => {
      return this.rows
        .filter((r) => r.userId === where.userId)
        .map((r) => ({
          organization: {
            devicePolicy: r.bridgePolicy === null ? null : { bridgePolicy: r.bridgePolicy },
          },
        }));
    },
  };
}

function makeService() {
  const fake = new FakeMembershipPrisma();
  const svc = new DevicePolicyService(fake as unknown as never);
  return { fake, svc };
}

describe("DevicePolicyService.resolveBridgePolicyForUser", () => {
  it("returns the default (required) when the user has no memberships at all", async () => {
    const { svc } = makeService();
    expect(await svc.resolveBridgePolicyForUser("ghost")).toBe(DEFAULT_BRIDGE_POLICY);
  });

  it("returns the default when memberships exist but none have a policy row", async () => {
    const { fake, svc } = makeService();
    fake.addMembership("u1", null);
    fake.addMembership("u1", null);
    expect(await svc.resolveBridgePolicyForUser("u1")).toBe(DEFAULT_BRIDGE_POLICY);
  });

  it("returns 'required' for a single-org user whose org requires it", async () => {
    const { fake, svc } = makeService();
    fake.addMembership("u1", "required");
    expect(await svc.resolveBridgePolicyForUser("u1")).toBe("required");
  });

  it("returns 'optional' for a single-org user whose org is optional", async () => {
    const { fake, svc } = makeService();
    fake.addMembership("u1", "optional");
    expect(await svc.resolveBridgePolicyForUser("u1")).toBe("optional");
  });

  it("returns 'disabled' for a single-org user whose org has it disabled", async () => {
    const { fake, svc } = makeService();
    fake.addMembership("u1", "disabled");
    expect(await svc.resolveBridgePolicyForUser("u1")).toBe("disabled");
  });

  it("strictest wins: required + disabled → required", async () => {
    const { fake, svc } = makeService();
    fake.addMembership("u1", "disabled");
    fake.addMembership("u1", "required");
    expect(await svc.resolveBridgePolicyForUser("u1")).toBe("required");
  });

  it("strictest wins: required + optional → required", async () => {
    const { fake, svc } = makeService();
    fake.addMembership("u1", "optional");
    fake.addMembership("u1", "required");
    expect(await svc.resolveBridgePolicyForUser("u1")).toBe("required");
  });

  it("strictest wins: optional + disabled → optional", async () => {
    const { fake, svc } = makeService();
    fake.addMembership("u1", "disabled");
    fake.addMembership("u1", "optional");
    expect(await svc.resolveBridgePolicyForUser("u1")).toBe("optional");
  });

  it("ignores memberships belonging to other users", async () => {
    const { fake, svc } = makeService();
    fake.addMembership("u1", "disabled");
    fake.addMembership("u2", "required");
    expect(await svc.resolveBridgePolicyForUser("u1")).toBe("disabled");
    expect(await svc.resolveBridgePolicyForUser("u2")).toBe("required");
  });

  it("treats a malformed policy string as the default required", async () => {
    // Defensive: if the DB column is somehow corrupted or set to a value
    // outside the enum (manual SQL), the resolver must fail closed.
    const { fake, svc } = makeService();
    fake.addMembership("u1", "garbage" as BridgePolicy);
    expect(await svc.resolveBridgePolicyForUser("u1")).toBe(DEFAULT_BRIDGE_POLICY);
  });

  it("BRIDGE_POLICY_VALUES is exhaustive", () => {
    expect(BRIDGE_POLICY_VALUES).toEqual(["required", "optional", "disabled"]);
  });
});
