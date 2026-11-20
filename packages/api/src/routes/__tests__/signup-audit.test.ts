import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * Audit log (ADR-0008): sign-up records organization.create in the new
 * organization, by the new user, in the sign-up transaction; switch-org
 * records user.org_switch with the refresh token it issues.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);
delete process.env.TURNSTILE_SECRET_KEY;
delete process.env.TURNSTILE_SITE_KEY;

vi.mock('../../lib/cache.js', () => ({
  redis: {},
  cacheGet: vi.fn(async () => null),
  cacheSet: vi.fn(async () => undefined),
  cacheDel: vi.fn(async () => undefined),
  disconnectCache: vi.fn(async () => undefined),
}));

vi.mock('../../lib/email.js', () => ({
  sendPasswordResetEmail: vi.fn(async () => undefined),
  sendWelcomeVerificationEmail: vi.fn(async () => undefined),
  sendPasswordChangedEmail: vi.fn(async () => undefined),
  sendSuspiciousLoginEmail: vi.fn(async () => undefined),
}));

let auditLogs: Array<Record<string, any>> = [];
let insideTransaction = false;
let auditWritesOutsideTransaction = 0;

const prisma: Record<string, any> = {
  user: {
    findMany: async () => [],
    create: async ({ data }: any) => ({ id: 'user_new', ...data }),
  },
  organization: {
    findUnique: async () => null,
    create: async ({ data }: any) => ({ id: 'org_new', ...data }),
  },
  membership: {
    create: async () => ({}),
    findUnique: async () => ({
      organizationId: 'org_b',
      role: 'ADMIN',
      organization: { id: 'org_b', name: 'B', slug: 'b' },
    }),
  },
  refreshToken: { create: async ({ data }: any) => data },
  auditLog: {
    create: async ({ data }: any) => {
      if (!insideTransaction) auditWritesOutsideTransaction += 1;
      auditLogs.push(data);
      return data;
    },
  },
  $transaction: async (fn: (tx: unknown) => Promise<unknown>) => {
    insideTransaction = true;
    try {
      return await fn(prisma);
    } finally {
      insideTransaction = false;
    }
  },
};

let app: FastifyInstance;

beforeAll(async () => {
  app = Fastify({ logger: false });
  await app.register((await import('@fastify/cookie')).default);
  await app.register((await import('@fastify/jwt')).default, { secret: 'b'.repeat(32) });
  app.decorate('prisma', prisma as never);
  app.decorate('signingService', { createKeyPair: async () => ({}) } as never);
  app.decorate('authenticate', async (req: never) => {
    (req as { user?: unknown }).user = { id: 'user_1', orgId: 'org_a', role: 'OWNER', email: 'a@example.com' };
  });
  const { default: authRoutes } = await import('../auth.js');
  await app.register(authRoutes, { prefix: '/api/v1/auth' });
  await app.ready();
});

afterAll(async () => {
  await app.close();
});

beforeEach(() => {
  auditLogs = [];
  auditWritesOutsideTransaction = 0;
});

describe('auth routes write audit entries', () => {
  it('signup records organization.create by the new user, in the transaction', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/signup',
      payload: { name: 'New', email: 'new@example.com', password: 'SecurePass123!', organizationName: 'New Org' },
    });

    expect(res.statusCode).toBe(202);
    expect(auditLogs).toEqual([
      expect.objectContaining({
        organizationId: 'org_new',
        action: 'organization.create',
        resource: 'Organization',
        resourceId: 'org_new',
        actorType: 'USER',
        actorId: 'user_new',
        metadata: { name: 'New Org', slug: 'new-org', via: 'signup' },
      }),
    ]);
    expect(auditLogs[0].metadata).not.toHaveProperty('passwordHash');
    expect(auditWritesOutsideTransaction).toBe(0);
  });

  it('switch-org records user.org_switch in the target organization, in the transaction', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/switch-org',
      payload: { organizationId: 'org_b' },
    });

    expect(res.statusCode).toBe(200);
    expect(auditLogs).toEqual([
      expect.objectContaining({
        organizationId: 'org_b',
        action: 'user.org_switch',
        actorType: 'USER',
        actorId: 'user_1',
        metadata: { fromOrgId: 'org_a', toOrgId: 'org_b' },
      }),
    ]);
    expect(auditWritesOutsideTransaction).toBe(0);
  });
});
