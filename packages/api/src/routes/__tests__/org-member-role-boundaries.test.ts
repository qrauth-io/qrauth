import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * Audit 2026-10 FINDING-006 / FINDING-007 / FINDING-010 (role-change half).
 *
 * - An actor may remove or re-role only members with a strictly lower role,
 *   except an OWNER acting on another OWNER.
 * - The last-owner check and the change run in one serializable transaction.
 * - A role change revokes the member's CLI keys.
 * - Changing an organization's domain drops its verified state.
 *
 * Real routes, stubbed `authenticate` (x-test-role) and an in-memory prisma.
 */

process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

vi.mock('../../lib/email.js', () => ({
  sendInvitationEmail: vi.fn(async () => undefined),
  sendMemberRemovedEmail: vi.fn(async () => undefined),
  sendRoleChangedEmail: vi.fn(async () => undefined),
  sendSigningKeyRotatedEmail: vi.fn(async () => undefined),
  sendDomainVerifiedEmail: vi.fn(async () => undefined),
}));

const ORG = 'org_1';

interface Member {
  id: string;
  userId: string;
  organizationId: string;
  role: string;
  joinedAt: Date;
}

let members: Member[] = [];
let cliKeys: Array<{ createdByUserId: string; organizationId: string; source: string; revokedAt: Date | null }> = [];
let org: Record<string, unknown> = {};
let transactionOptions: Array<Record<string, unknown> | undefined> = [];

function seed(roles: Record<string, string>): void {
  members = Object.entries(roles).map(([userId, role], index) => ({
    id: `m_${index}`, userId, organizationId: ORG, role, joinedAt: new Date(),
  }));
}

const findMember = (where: any) =>
  members.find((m) => m.userId === where.userId_organizationId.userId
    && m.organizationId === where.userId_organizationId.organizationId);

const prisma: Record<string, any> = {
  membership: {
    findUnique: async ({ where }: any) => {
      const found = findMember(where);
      return found ? { ...found } : null;
    },
    count: async ({ where }: any) =>
      members.filter((m) => m.organizationId === where.organizationId && m.role === where.role).length,
    delete: async ({ where }: any) => {
      const found = findMember(where)!;
      members = members.filter((m) => m !== found);
      return found;
    },
    update: async ({ where, data }: any) => {
      const found = findMember(where)!;
      Object.assign(found, data);
      return { ...found };
    },
  },
  user: { findUnique: async () => ({ email: 'member@example.com', name: 'Member' }) },
  organization: {
    findUnique: async () => ({ ...org }),
    update: async ({ data }: any) => {
      Object.assign(org, data);
      return { ...org };
    },
  },
  apiKey: {
    updateMany: async ({ where, data }: any) => {
      const hit = cliKeys.filter((k) => k.createdByUserId === where.createdByUserId
        && k.organizationId === where.organizationId && k.source === where.source && k.revokedAt === null);
      hit.forEach((k) => { k.revokedAt = data.revokedAt; });
      return { count: hit.length };
    },
  },
  auditLog: { create: async () => ({}) },
  $transaction: async (fn: (tx: unknown) => Promise<unknown>, options?: Record<string, unknown>) => {
    transactionOptions.push(options);
    return fn(prisma);
  },
};

let app: FastifyInstance;

beforeAll(async () => {
  app = Fastify({ logger: false });
  app.decorate('prisma', prisma as never);
  app.decorate('signingService', {} as never);
  app.decorate('authenticate', async (req: never) => {
    const request = req as unknown as { headers: Record<string, string>; user?: unknown };
    request.user = { id: 'actor', orgId: ORG, role: request.headers['x-test-role'], email: 'actor@example.com' };
  });
  const { default: organizationRoutes } = await import('../organizations.js');
  await app.register(organizationRoutes, { prefix: '/api/v1/organizations' });
  await app.ready();
});

afterAll(async () => {
  await app?.close();
});

beforeEach(() => {
  cliKeys = [];
  transactionOptions = [];
  org = { id: ORG, name: 'Org', domain: 'verified.example', domainVerified: true, domainVerifyToken: 'tok' };
});

const remove = (actorRole: string, userId: string) => app.inject({
  method: 'DELETE',
  url: `/api/v1/organizations/${ORG}/members/${userId}`,
  headers: { 'x-test-role': actorRole },
});

const setRole = (actorRole: string, userId: string, role: string) => app.inject({
  method: 'PATCH',
  url: `/api/v1/organizations/${ORG}/members/${userId}`,
  headers: { 'x-test-role': actorRole },
  payload: { role },
});

const roleOf = (userId: string) => members.find((m) => m.userId === userId)?.role;

describe('member removal — role boundary (FINDING-006)', () => {
  it('an ADMIN cannot remove an OWNER', async () => {
    seed({ owner_a: 'OWNER', owner_b: 'OWNER', admin: 'ADMIN' });

    const res = await remove('ADMIN', 'owner_b');

    expect(res.statusCode).toBe(403);
    expect(roleOf('owner_b')).toBe('OWNER');
  });

  it('an ADMIN cannot remove another ADMIN', async () => {
    seed({ owner_a: 'OWNER', admin_b: 'ADMIN' });

    const res = await remove('ADMIN', 'admin_b');

    expect(res.statusCode).toBe(403);
    expect(roleOf('admin_b')).toBe('ADMIN');
  });

  it('an ADMIN can remove a MEMBER', async () => {
    seed({ owner_a: 'OWNER', member: 'MEMBER' });

    const res = await remove('ADMIN', 'member');

    expect(res.statusCode).toBe(204);
    expect(roleOf('member')).toBeUndefined();
  });

  it('an OWNER can remove another OWNER', async () => {
    seed({ owner_a: 'OWNER', owner_b: 'OWNER' });

    const res = await remove('OWNER', 'owner_b');

    expect(res.statusCode).toBe(204);
  });

  it('the last OWNER cannot be removed', async () => {
    seed({ owner_a: 'OWNER', admin: 'ADMIN' });

    const res = await remove('OWNER', 'owner_a');

    expect(res.statusCode).toBe(422);
    expect(roleOf('owner_a')).toBe('OWNER');
  });

  it('checks and removes inside one serializable transaction', async () => {
    seed({ owner_a: 'OWNER', member: 'MEMBER' });

    await remove('OWNER', 'member');

    expect(transactionOptions).toEqual([{ isolationLevel: 'Serializable' }]);
  });
});

describe('member role change — role boundary (FINDING-006)', () => {
  it('an ADMIN cannot demote an OWNER', async () => {
    seed({ owner_a: 'OWNER', owner_b: 'OWNER' });

    const res = await setRole('ADMIN', 'owner_b', 'VIEWER');

    expect(res.statusCode).toBe(403);
    expect(roleOf('owner_b')).toBe('OWNER');
  });

  it('an ADMIN cannot demote another ADMIN', async () => {
    seed({ owner_a: 'OWNER', admin_b: 'ADMIN' });

    const res = await setRole('ADMIN', 'admin_b', 'VIEWER');

    expect(res.statusCode).toBe(403);
    expect(roleOf('admin_b')).toBe('ADMIN');
  });

  it('an ADMIN can change a MEMBER to MANAGER', async () => {
    seed({ owner_a: 'OWNER', member: 'MEMBER' });

    const res = await setRole('ADMIN', 'member', 'MANAGER');

    expect(res.statusCode).toBe(200);
    expect(roleOf('member')).toBe('MANAGER');
  });

  it('an OWNER can demote another OWNER', async () => {
    seed({ owner_a: 'OWNER', owner_b: 'OWNER' });

    const res = await setRole('OWNER', 'owner_b', 'ADMIN');

    expect(res.statusCode).toBe(200);
    expect(roleOf('owner_b')).toBe('ADMIN');
  });

  it('the last OWNER cannot be demoted', async () => {
    seed({ owner_a: 'OWNER', admin: 'ADMIN' });

    const res = await setRole('OWNER', 'owner_a', 'ADMIN');

    expect(res.statusCode).toBe(422);
    expect(roleOf('owner_a')).toBe('OWNER');
  });

  it('checks and updates inside one serializable transaction', async () => {
    seed({ owner_a: 'OWNER', member: 'MEMBER' });

    await setRole('OWNER', 'member', 'VIEWER');

    expect(transactionOptions).toEqual([{ isolationLevel: 'Serializable' }]);
  });

  it("revokes the member's CLI keys for that organization (FINDING-010)", async () => {
    seed({ owner_a: 'OWNER', admin: 'ADMIN' });
    cliKeys = [
      { createdByUserId: 'admin', organizationId: ORG, source: 'cli', revokedAt: null },
      { createdByUserId: 'admin', organizationId: 'org_other', source: 'cli', revokedAt: null },
      { createdByUserId: 'owner_a', organizationId: ORG, source: 'cli', revokedAt: null },
    ];

    const res = await setRole('OWNER', 'admin', 'VIEWER');

    expect(res.statusCode).toBe(200);
    expect(cliKeys.map((k) => k.revokedAt !== null)).toEqual([true, false, false]);
  });
});

describe('organization domain change (FINDING-007)', () => {
  const patchOrg = (payload: Record<string, unknown>) => app.inject({
    method: 'PATCH',
    url: `/api/v1/organizations/${ORG}`,
    headers: { 'x-test-role': 'OWNER' },
    payload,
  });

  it('drops the verified state when the domain changes', async () => {
    const res = await patchOrg({ domain: 'unproven.example' });

    expect(res.statusCode).toBe(200);
    expect(org.domain).toBe('unproven.example');
    expect(org.domainVerified).toBe(false);
    expect(org.domainVerifyToken).toBeNull();
  });

  it('keeps the verified state when the same domain is sent again', async () => {
    await patchOrg({ domain: 'verified.example' });

    expect(org.domainVerified).toBe(true);
    expect(org.domainVerifyToken).toBe('tok');
  });

  it('keeps the verified state when only other fields change', async () => {
    await patchOrg({ name: 'Renamed Org' });

    expect(org.name).toBe('Renamed Org');
    expect(org.domainVerified).toBe(true);
  });
});
