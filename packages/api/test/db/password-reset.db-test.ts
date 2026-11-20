/**
 * Password reset token consumption (ADR-0008 review): the token is spent by
 * a conditional update inside the reset transaction, so two concurrent
 * submissions of one token reset the password once, with one audit entry.
 * Real auth routes on a real Postgres; email and queues are stubbed. Run by
 * scripts/ci-verify.sh `db`.
 */
import { PrismaClient } from '@prisma/client';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

const url = process.env.TEST_DATABASE_URL;
if (!url) throw new Error('TEST_DATABASE_URL is not set');
if (!/test/i.test(new URL(url).pathname)) throw new Error('TEST_DATABASE_URL must name a test database (the suite truncates tables)');

process.env.DATABASE_URL ??= url;
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'db-test-only-throwaway-secret-0000000000';

const stubs = vi.hoisted(() => ({ noQueue: { add: async () => undefined } }));
vi.mock('../../src/lib/queue.js', () => ({
  scanQueue: stubs.noQueue, fraudQueue: stubs.noQueue, alertQueue: stubs.noQueue, webhookQueue: stubs.noQueue,
  cleanupQueue: stubs.noQueue, analyticsQueue: stubs.noQueue, webRiskQueue: stubs.noQueue,
  createQueueConnection: vi.fn(), closeQueues: vi.fn(async () => undefined),
}));
vi.mock('../../src/lib/cache.js', () => ({
  cacheGet: vi.fn(async () => null),
  cacheSet: vi.fn(async () => undefined),
  cacheDel: vi.fn(async () => undefined),
  cacheIncr: vi.fn(async () => 1),
}));
vi.mock('../../src/lib/email.js', async (importOriginal) => {
  const real = await importOriginal<Record<string, unknown>>();
  return Object.fromEntries(Object.entries(real).map(([k, v]) => [k, typeof v === 'function' && /^send/.test(k) ? vi.fn(async () => undefined) : v]));
});

const db = new PrismaClient({ datasources: { db: { url } } });
let app: FastifyInstance;

beforeAll(async () => {
  await db.$executeRawUnsafe('TRUNCATE "organizations", "users" CASCADE');
  app = Fastify();
  app.decorate('prisma', db as never);
  app.decorate('authenticate', async () => {});
  await app.register(import('@fastify/cookie'));
  await app.register(import('@fastify/jwt'), { secret: process.env.JWT_SECRET! });
  const { default: authRoutes } = await import('../../src/routes/auth.js');
  await app.register(authRoutes, { prefix: '/api/v1/auth' });
  await app.ready();
});

afterAll(async () => {
  await app.close();
  await db.$disconnect();
});

describe('POST /auth/reset-password', () => {
  it('two concurrent submissions of one token: one succeeds, one is refused, one audit entry', async () => {
    const { hashString } = await import('../../src/lib/crypto.js');
    const { hashPassword } = await import('../../src/lib/password.js');
    const org = await db.organization.create({ data: { name: 'Reset Org', slug: 'reset-org-test', email: 'reset@org.test' } });
    const user = await db.user.create({
      data: {
        name: 'Reset User', email: 'reset-user@org.test', emailVerified: true, passwordHash: await hashPassword('old-password-123'),
        passwordResetToken: hashString('reset-token-1'), passwordResetExpires: new Date(Date.now() + 60 * 60 * 1000),
      },
    });
    await db.membership.create({ data: { userId: user.id, organizationId: org.id, role: 'OWNER' } });

    const submit = (password: string) =>
      app.inject({ method: 'POST', url: '/api/v1/auth/reset-password', payload: { token: 'reset-token-1', password } });
    const results = await Promise.all([submit('first-new-password-1'), submit('second-new-password-2')]);

    expect(results.map((r) => r.statusCode).sort()).toEqual([200, 400]);
    expect(await db.auditLog.count({ where: { action: 'user.password_reset' } })).toBe(1);
    expect(await db.user.findUniqueOrThrow({ where: { id: user.id } })).toMatchObject({ passwordResetToken: null, passwordResetExpires: null });
    // A third try with the spent token is refused too.
    expect((await submit('third-new-password-3')).statusCode).toBe(400);
  });
});
