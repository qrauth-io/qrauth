import { describe, it, expect } from "vitest";
import { PqcHealthService } from "../../api/src/services/pqc-health.js";

/**
 * In-memory fake covering the slice of Prisma the health service touches.
 * Each test seeds the rows it cares about and asserts the resulting
 * report. Avoids spinning Postgres for a pure aggregation/branching test.
 */
interface FakeQR {
  organizationId: string;
  algVersion: string | null;
  createdAt: Date;
}

interface FakePasskey {
  organizationId: string;
  bridgePublicKey: Buffer | null;
  revokedAt: Date | null;
}

interface FakeMacKey {
  organizationId: string;
  version: number;
  status: "ACTIVE" | "ROTATED" | "RETIRED";
  createdAt: Date;
}

interface FakeBatch {
  organizationId: string;
  issuedAt: Date;
}

class FakePrisma {
  qrCodes: FakeQR[] = [];
  passkeys: FakePasskey[] = [];
  macKeys: FakeMacKey[] = [];
  batches: FakeBatch[] = [];

  qRCode = {
    groupBy: async ({ where }: { where: { organizationId: string } }) => {
      const rows = this.qrCodes.filter((q) => q.organizationId === where.organizationId);
      const byAlg = new Map<string | null, number>();
      for (const r of rows) {
        byAlg.set(r.algVersion, (byAlg.get(r.algVersion) ?? 0) + 1);
      }
      return Array.from(byAlg.entries()).map(([algVersion, count]) => ({
        algVersion,
        _count: { _all: count },
      }));
    },
    count: async ({
      where,
    }: {
      where: { organizationId: string; algVersion?: string; createdAt?: { lt: Date } };
    }) =>
      this.qrCodes.filter((q) => {
        if (q.organizationId !== where.organizationId) return false;
        if (where.algVersion !== undefined && q.algVersion !== where.algVersion) return false;
        if (where.createdAt && q.createdAt >= where.createdAt.lt) return false;
        return true;
      }).length,
  };

  passkey = {
    findMany: async ({ where }: any) => {
      const orgId = where.user.memberships.some.organizationId;
      return this.passkeys
        .filter((p) => p.organizationId === orgId && p.revokedAt === null)
        .map((p) => ({ bridgePublicKey: p.bridgePublicKey }));
    },
  };

  orgMacKey = {
    findFirst: async ({
      where,
      orderBy,
    }: {
      where: { organizationId: string; status: "ACTIVE" };
      orderBy: { version: "desc" };
    }) => {
      void orderBy;
      const matches = this.macKeys
        .filter((m) => m.organizationId === where.organizationId && m.status === where.status)
        .sort((a, b) => b.version - a.version);
      return matches[0] ?? null;
    },
    count: async ({
      where,
    }: {
      where: { organizationId: string; status: "ROTATED" | "RETIRED" };
    }) =>
      this.macKeys.filter(
        (m) => m.organizationId === where.organizationId && m.status === where.status,
      ).length,
  };

  signedBatch = {
    count: async ({ where }: { where: { organizationId: string } }) =>
      this.batches.filter((b) => b.organizationId === where.organizationId).length,
    findFirst: async ({ where }: { where: { organizationId: string } }) => {
      const matches = this.batches
        .filter((b) => b.organizationId === where.organizationId)
        .sort((a, b) => b.issuedAt.getTime() - a.issuedAt.getTime());
      return matches[0] ? { issuedAt: matches[0].issuedAt } : null;
    },
  };
}

const ORG = "org_test";
const recently = (msAgo: number) => new Date(Date.now() - msAgo);
const daysAgo = (d: number) => recently(d * 24 * 60 * 60 * 1000);
const hoursAgo = (h: number) => recently(h * 60 * 60 * 1000);

function makeService() {
  const prisma = new FakePrisma();
  const svc = new PqcHealthService(prisma as unknown as never);
  return { prisma, svc };
}

describe("PqcHealthService.getOrgHealth", () => {
  it("returns green for an org with only hybrid QRs and a fresh MAC key", async () => {
    const { prisma, svc } = makeService();
    prisma.qrCodes.push(
      { organizationId: ORG, algVersion: "hybrid-ecdsa-slhdsa-v1", createdAt: hoursAgo(1) },
      { organizationId: ORG, algVersion: "hybrid-ecdsa-slhdsa-v1", createdAt: hoursAgo(2) },
    );
    prisma.macKeys.push({
      organizationId: ORG,
      version: 1,
      status: "ACTIVE",
      createdAt: daysAgo(1),
    });

    const report = await svc.getOrgHealth(ORG);
    expect(report.status).toBe("green");
    expect(report.warnings).toEqual([]);
    expect(report.qrCodes.byStatus.accepted).toBe(2);
    expect(report.qrCodes.byStatus.deprecated).toBe(0);
  });

  it("returns red when legacy ecdsa-p256-sha256-v1 rows appear (dropped alg version)", async () => {
    // `ecdsa-p256-sha256-v1` is in REJECTED_ALG_VERSIONS (alg-versions.ts),
    // so these rows count toward `byStatus.rejected` and trigger the
    // "rejected algorithm versions" warning — either path drives `red`.
    const { prisma, svc } = makeService();
    prisma.qrCodes.push(
      { organizationId: ORG, algVersion: "hybrid-ecdsa-slhdsa-v1", createdAt: hoursAgo(1) },
      { organizationId: ORG, algVersion: "ecdsa-p256-sha256-v1", createdAt: hoursAgo(2) },
      { organizationId: ORG, algVersion: "ecdsa-p256-sha256-v1", createdAt: hoursAgo(3) },
    );
    prisma.macKeys.push({
      organizationId: ORG,
      version: 1,
      status: "ACTIVE",
      createdAt: daysAgo(1),
    });

    const report = await svc.getOrgHealth(ORG);
    expect(report.status).toBe("red");
    expect(report.qrCodes.byStatus.rejected).toBe(2);
    expect(report.warnings.some((w) => w.includes("rejected"))).toBe(true);
  });

  it("returns red when pending rows are stuck past the threshold", async () => {
    const { prisma, svc } = makeService();
    prisma.qrCodes.push(
      { organizationId: ORG, algVersion: "ecdsa-pending-slhdsa-v1", createdAt: hoursAgo(2) }, // stuck (>1h)
      { organizationId: ORG, algVersion: "hybrid-ecdsa-slhdsa-v1", createdAt: hoursAgo(1) },
    );
    prisma.macKeys.push({
      organizationId: ORG,
      version: 1,
      status: "ACTIVE",
      createdAt: daysAgo(1),
    });

    const report = await svc.getOrgHealth(ORG);
    expect(report.status).toBe("red");
    expect(report.qrCodes.pendingStuck).toBe(1);
    expect(report.warnings.some((w) => w.includes("stuck"))).toBe(true);
  });

  it("does not flag fresh pending rows as stuck", async () => {
    const { prisma, svc } = makeService();
    prisma.qrCodes.push({
      organizationId: ORG,
      algVersion: "ecdsa-pending-slhdsa-v1",
      createdAt: hoursAgo(0.1), // 6 minutes — well under the 1h threshold
    });
    prisma.macKeys.push({
      organizationId: ORG,
      version: 1,
      status: "ACTIVE",
      createdAt: daysAgo(1),
    });

    const report = await svc.getOrgHealth(ORG);
    expect(report.status).toBe("green");
    expect(report.qrCodes.pendingStuck).toBe(0);
  });

  it("returns red for unknown algorithm versions in the wild", async () => {
    const { prisma, svc } = makeService();
    prisma.qrCodes.push(
      { organizationId: ORG, algVersion: "future-algo-v99", createdAt: hoursAgo(1) },
    );
    prisma.macKeys.push({
      organizationId: ORG,
      version: 1,
      status: "ACTIVE",
      createdAt: daysAgo(1),
    });

    const report = await svc.getOrgHealth(ORG);
    expect(report.status).toBe("red");
    expect(report.qrCodes.byStatus.unknown).toBe(1);
  });

  it("counts passkeys with and without bridge", async () => {
    const { prisma, svc } = makeService();
    prisma.passkeys.push(
      { organizationId: ORG, bridgePublicKey: Buffer.from("pub1"), revokedAt: null },
      { organizationId: ORG, bridgePublicKey: Buffer.from("pub2"), revokedAt: null },
      { organizationId: ORG, bridgePublicKey: null, revokedAt: null },
    );
    prisma.macKeys.push({
      organizationId: ORG,
      version: 1,
      status: "ACTIVE",
      createdAt: daysAgo(1),
    });

    const report = await svc.getOrgHealth(ORG);
    expect(report.passkeys.total).toBe(3);
    expect(report.passkeys.withBridge).toBe(2);
    expect(report.passkeys.withoutBridge).toBe(1);
    expect(report.status).toBe("yellow"); // missing bridge → yellow
  });

  it("warns when MAC key is overdue for rotation", async () => {
    const { prisma, svc } = makeService();
    prisma.macKeys.push({
      organizationId: ORG,
      version: 1,
      status: "ACTIVE",
      createdAt: daysAgo(95), // 5 days past the 90-day rotation window
    });

    const report = await svc.getOrgHealth(ORG);
    expect(report.status).toBe("yellow");
    expect(report.macKeys.daysUntilRotation).toBe(-5);
    expect(report.warnings.some((w) => w.includes("overdue"))).toBe(true);
  });

  it("warns when MAC key is in the rotation warning window (within 7 days)", async () => {
    const { prisma, svc } = makeService();
    prisma.macKeys.push({
      organizationId: ORG,
      version: 1,
      status: "ACTIVE",
      createdAt: daysAgo(85), // 5 days until rotation
    });

    const report = await svc.getOrgHealth(ORG);
    expect(report.status).toBe("yellow");
    expect(report.macKeys.daysUntilRotation).toBe(5);
  });

  it("does NOT warn when MAC key is well within the rotation window", async () => {
    const { prisma, svc } = makeService();
    prisma.macKeys.push({
      organizationId: ORG,
      version: 1,
      status: "ACTIVE",
      createdAt: daysAgo(30),
    });

    const report = await svc.getOrgHealth(ORG);
    expect(report.status).toBe("green");
    expect(report.macKeys.daysUntilRotation).toBe(60);
  });

  it("returns null mac fields when no key exists", async () => {
    const { svc } = makeService();
    const report = await svc.getOrgHealth(ORG);
    expect(report.macKeys.activeVersion).toBeNull();
    expect(report.macKeys.activeAgeDays).toBeNull();
    expect(report.macKeys.daysUntilRotation).toBeNull();
  });

  it("aggregates signed batch counts", async () => {
    const { prisma, svc } = makeService();
    prisma.batches.push(
      { organizationId: ORG, issuedAt: hoursAgo(1) },
      { organizationId: ORG, issuedAt: hoursAgo(3) },
      { organizationId: ORG, issuedAt: hoursAgo(5) },
    );
    prisma.macKeys.push({
      organizationId: ORG,
      version: 1,
      status: "ACTIVE",
      createdAt: daysAgo(1),
    });

    const report = await svc.getOrgHealth(ORG);
    expect(report.signedBatches.total).toBe(3);
    expect(report.signedBatches.lastBatchAt).not.toBeNull();
  });

  it("red overrides yellow when both conditions are present", async () => {
    const { prisma, svc } = makeService();
    prisma.qrCodes.push(
      { organizationId: ORG, algVersion: "ecdsa-pending-slhdsa-v1", createdAt: hoursAgo(2) }, // stuck → red
      { organizationId: ORG, algVersion: "ecdsa-p256-sha256-v1", createdAt: hoursAgo(1) }, // deprecated → yellow
    );
    prisma.macKeys.push({
      organizationId: ORG,
      version: 1,
      status: "ACTIVE",
      createdAt: daysAgo(95), // overdue → yellow
    });

    const report = await svc.getOrgHealth(ORG);
    expect(report.status).toBe("red");
  });

  it("scopes counts to the requested organization", async () => {
    const { prisma, svc } = makeService();
    prisma.qrCodes.push(
      { organizationId: ORG, algVersion: "hybrid-ecdsa-slhdsa-v1", createdAt: hoursAgo(1) },
      { organizationId: "other_org", algVersion: "ecdsa-p256-sha256-v1", createdAt: hoursAgo(1) },
    );
    prisma.macKeys.push({
      organizationId: ORG,
      version: 1,
      status: "ACTIVE",
      createdAt: daysAgo(1),
    });

    const report = await svc.getOrgHealth(ORG);
    expect(report.qrCodes.total).toBe(1);
    expect(report.status).toBe("green");
  });
});
