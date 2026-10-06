import { describe, it, expect, vi } from 'vitest';

// The service touches Redis via lib/cache; stub it so these stay hermetic.
vi.mock('../../lib/cache.js', () => ({
  cacheGet: vi.fn(async () => null),
  cacheSet: vi.fn(async () => undefined),
  cacheDel: vi.fn(async () => undefined),
}));

import { EphemeralSessionService } from '../ephemeral.js';

interface Row {
  id: string;
  organizationId: string;
  appId: string | null;
  token: string;
  status: string;
  scopes: string[];
  ttlSeconds: number;
  maxUses: number;
  useCount: number;
  deviceBinding: boolean;
  boundDeviceHash: string | null;
  metadata: unknown;
  claimUrl: string | null;
  expiresAt: Date;
  revokedAt: Date | null;
  claimedAt: Date | null;
  createdAt: Date;
}

/** In-memory fake of the prisma methods the ephemeral service uses. */
function makeFakePrisma(seed: Row[] = []) {
  const rows: Row[] = [...seed];
  let seq = seed.length;
  const prisma = {
    ephemeralSession: {
      create: async ({ data }: any) => {
        const row: Row = {
          id: `e${++seq}`,
          organizationId: data.organizationId,
          appId: data.appId ?? null,
          token: data.token,
          status: data.status ?? 'PENDING',
          scopes: data.scopes ?? [],
          ttlSeconds: data.ttlSeconds,
          maxUses: data.maxUses ?? 1,
          useCount: 0,
          deviceBinding: data.deviceBinding ?? false,
          boundDeviceHash: null,
          metadata: data.metadata ?? null,
          claimUrl: data.claimUrl ?? null,
          expiresAt: data.expiresAt,
          revokedAt: null,
          claimedAt: null,
          createdAt: new Date(),
        };
        rows.push(row);
        return { ...row };
      },
      findUnique: async ({ where }: any) => {
        const r = rows.find((x) => (where.id ? x.id === where.id : x.token === where.token));
        return r ? { ...r } : null;
      },
      findMany: async ({ where }: any) => {
        return rows
          .filter((r) => (where.organizationId ? r.organizationId === where.organizationId : true))
          .filter((r) => (where.status ? r.status === where.status : true))
          .map((r) => ({ ...r }));
      },
      count: async ({ where }: any) =>
        rows.filter((r) => (where.organizationId ? r.organizationId === where.organizationId : true)).length,
      updateMany: async ({ where, data }: any) => {
        let count = 0;
        for (const r of rows) {
          if (where.id && r.id !== where.id) continue;
          if (where.organizationId && r.organizationId !== where.organizationId) continue;
          if (where.status?.not && r.status === where.status.not) continue;
          Object.assign(r, data);
          count++;
        }
        return { count };
      },
    },
  };
  return { prisma, rows };
}

const svc = (prisma: unknown) => new EphemeralSessionService(prisma as any);

describe('EphemeralSessionService — org scoping (ADR-0002 step 8)', () => {
  it('stores organizationId and a null appId for org-credential creates', async () => {
    const { prisma, rows } = makeFakePrisma();
    const session = await svc(prisma).createSession({ organizationId: 'org1' }, { scopes: ['read'] });
    expect(session.organizationId).toBe('org1');
    expect(session.appId).toBeNull();
    expect(rows[0].organizationId).toBe('org1');
  });

  it('records appId as provenance when created via app credentials', async () => {
    const { prisma } = makeFakePrisma();
    const session = await svc(prisma).createSession({ organizationId: 'org1', appId: 'app1' }, { scopes: ['read'] });
    expect(session.organizationId).toBe('org1');
    expect(session.appId).toBe('app1');
  });

  it('lists only the calling org sessions', async () => {
    const { prisma } = makeFakePrisma();
    const s = svc(prisma);
    await s.createSession({ organizationId: 'orgA' }, { scopes: ['a'] });
    await s.createSession({ organizationId: 'orgA' }, { scopes: ['a'] });
    await s.createSession({ organizationId: 'orgB' }, { scopes: ['b'] });

    const a = await s.listSessions('orgA', {});
    const b = await s.listSessions('orgB', {});
    expect(a.total).toBe(2);
    expect(b.total).toBe(1);
    expect(a.sessions.every((x) => x.organizationId === 'orgA')).toBe(true);
  });

  it('revokes a session for its org', async () => {
    const { prisma, rows } = makeFakePrisma();
    const s = svc(prisma);
    const session = await s.createSession({ organizationId: 'orgA' }, { scopes: ['a'] });
    const res = await s.revokeSession(session.id, 'orgA');
    expect(res.status).toBe('REVOKED');
    expect(rows.find((r) => r.id === session.id)!.status).toBe('REVOKED');
  });

  it('refuses to reveal/revoke another org session (cross-tenant → 404)', async () => {
    const { prisma } = makeFakePrisma();
    const s = svc(prisma);
    const session = await s.createSession({ organizationId: 'orgA' }, { scopes: ['a'] });
    await expect(s.revokeSession(session.id, 'orgB')).rejects.toMatchObject({ statusCode: 404 });
  });
});
