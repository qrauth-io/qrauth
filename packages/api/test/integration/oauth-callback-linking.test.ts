import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import { randomBytes } from 'node:crypto';
import Fastify, { type FastifyInstance } from 'fastify';
import { PrismaClient } from '@prisma/client';
import type { OAuthUser } from '../../src/lib/oauth.js';

/**
 * OAuth callback (routes/auth.ts GET /oauth/:provider/callback) against a REAL
 * migrated Postgres — the nOAuth takeover case end to end: the provider
 * identity is stubbed (exchangeCodeForUser), everything after it is the real
 * route + real DB. Skips cleanly when no migrated database is reachable (CI's
 * API unit-test job has no Postgres); the pure policy is covered in CI by
 * src/services/__tests__/oauth-account-link.test.ts.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

// Redis-backed cache stub: every OAuth state is "valid".
vi.mock('../../src/lib/cache.js', () => ({
  redis: {},
  cacheGet: vi.fn(async () => ({ valid: true })),
  cacheSet: vi.fn(async () => undefined),
  cacheDel: vi.fn(async () => undefined),
  disconnectCache: vi.fn(async () => undefined),
}));

// The provider identity each test asserts. A plain variable rather than a
// vi.fn: vitest's spy re-surfaces a rejected promise it returned as a test
// failure even when the route handles it.
let providerIdentity: () => Promise<OAuthUser> = async () => {
  throw new Error('providerIdentity not set');
};
const asserts = (identity: OAuthUser) => {
  providerIdentity = async () => identity;
};
vi.mock('../../src/lib/oauth.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../src/lib/oauth.js')>()),
  exchangeCodeForUser: () => providerIdentity(),
}));

const { OAUTH_SIGN_IN_PATH } = await import('../../src/routes/auth.js');

const nonce = randomBytes(4).toString('hex');
const mail = (local: string) => `${local}-${nonce}@corp.example`;
let prisma: PrismaClient | null = null;
let dbAvailable = false;
let app: FastifyInstance | null = null;

async function buildAuthApp(db: PrismaClient): Promise<FastifyInstance> {
  const instance = Fastify({ logger: false });
  await instance.register((await import('@fastify/cookie')).default);
  await instance.register((await import('@fastify/jwt')).default, { secret: 'b'.repeat(32) });
  instance.decorate('prisma', db);
  instance.decorate('signingService', { createKeyPair: async () => ({}) } as never);
  instance.decorate('authenticate', async () => undefined);
  const { default: authRoutes } = await import('../../src/routes/auth.js');
  await instance.register(authRoutes, { prefix: '/api/v1/auth' });
  await instance.ready();
  return instance;
}

function callback(provider: string) {
  return app!.inject({ method: 'GET', url: `/api/v1/auth/oauth/${provider}/callback?code=c&state=s` });
}

async function makeEmailUser(email: string, extra: Record<string, unknown> = {}) {
  const user = await prisma!.user.create({
    data: { name: 'Victim', email, passwordHash: 'N:salt:key', emailVerified: true, ...extra },
  });
  const org = await prisma!.organization.create({
    data: { name: `Org ${user.id}`, slug: `org-${user.id}`, email },
  });
  await prisma!.membership.create({ data: { userId: user.id, organizationId: org.id, role: 'OWNER' } });
  return user;
}

function expectGenericFailure(res: Awaited<ReturnType<typeof callback>>) {
  // Same redirect for every refusal: back to sign-in with oauth_error=failed, no JSON body.
  expect(res.statusCode).toBe(303);
  expect(String(res.headers.location)).toMatch(new RegExp(`${OAUTH_SIGN_IN_PATH}\\?oauth_error=failed$`));
  expect(res.headers['set-cookie']).toBeUndefined();
}

beforeAll(async () => {
  try {
    prisma = new PrismaClient();
    await prisma.$queryRaw`SELECT 1`;
    await prisma.user.count();
    dbAvailable = true;
  } catch {
    dbAvailable = false;
    return;
  }
  app = await buildAuthApp(prisma);
});

beforeEach(() => {
  providerIdentity = async () => {
    throw new Error('providerIdentity not set');
  };
});

afterAll(async () => {
  await app?.close();
  if (!prisma) return;
  if (dbAvailable) {
    const users = await prisma.user.findMany({ where: { email: { contains: nonce, mode: 'insensitive' } }, select: { id: true } });
    const ids = users.map((u) => u.id);
    const orgIds = (await prisma.membership.findMany({ where: { userId: { in: ids } }, select: { organizationId: true } }))
      .map((m) => m.organizationId);
    await prisma.user.deleteMany({ where: { id: { in: ids } } });
    await prisma.organization.deleteMany({ where: { id: { in: orgIds } } });
  }
  await prisma.$disconnect().catch(() => undefined);
});

describe('OAuth callback linking (real DB)', () => {
  it('TAKEOVER: Microsoft identity with a matching but unverified email is refused and not linked', async (ctx) => {
    if (!dbAvailable || !prisma) return ctx.skip();
    const victim = await makeEmailUser(mail('victim'));
    asserts({
      providerId: `attacker-oid-${nonce}`, email: victim.email.toUpperCase(), emailVerified: false, name: 'Mallory',
    });

    const res = await callback('microsoft');

    expectGenericFailure(res);
    const after = await prisma.user.findUniqueOrThrow({ where: { id: victim.id } });
    expect(after.provider).toBe('EMAIL');
    expect(after.providerId).toBeNull();
    expect(after.lastLoginAt).toBeNull();
    const events = await prisma.loginEvent.findMany({ where: { userId: victim.id } });
    expect(events).toEqual([expect.objectContaining({ success: false, provider: 'MICROSOFT' })]);
  });

  it('a personal Microsoft account matching an existing user gets the personal-account message and is not linked', async (ctx) => {
    if (!dbAvailable || !prisma) return ctx.skip();
    const existing = await makeEmailUser(mail('personal'));
    asserts({
      providerId: `msa-oid-${nonce}`, email: existing.email, emailVerified: false, name: 'P', personalMicrosoftAccount: true,
    });

    const res = await callback('microsoft');

    expect(res.statusCode).toBe(303);
    expect(String(res.headers.location)).toMatch(/oauth_error=microsoft_personal$/);
    const after = await prisma.user.findUniqueOrThrow({ where: { id: existing.id } });
    expect(after.provider).toBe('EMAIL');
    expect(after.providerId).toBeNull();
  });

  it('a verified email links the existing account, signs in, and records a success LoginEvent', async (ctx) => {
    if (!dbAvailable || !prisma) return ctx.skip();
    const user = await makeEmailUser(mail('linkme'));
    asserts({ providerId: `g-${nonce}`, email: user.email, emailVerified: true, name: 'Jane' });

    const res = await callback('google');

    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toMatch(/\/dashboard#jwt=/);
    const after = await prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    expect(after).toMatchObject({ provider: 'GOOGLE', providerId: `g-${nonce}` });
    const events = await prisma.loginEvent.findMany({ where: { userId: user.id } });
    expect(events).toEqual([expect.objectContaining({ success: true, provider: 'GOOGLE' })]);
  });

  it('(provider, providerId) wins over email for a returning Microsoft user', async (ctx) => {
    if (!dbAvailable || !prisma) return ctx.skip();
    const msUser = await makeEmailUser(mail('msuser'), { provider: 'MICROSOFT', providerId: `oid-${nonce}` });
    const other = await makeEmailUser(mail('other'));
    asserts({ providerId: `oid-${nonce}`, email: other.email, emailVerified: false, name: 'X' });

    const res = await callback('microsoft');

    expect(res.statusCode).toBe(302);
    expect(await prisma.loginEvent.count({ where: { userId: msUser.id, success: true, provider: 'MICROSOFT' } })).toBe(1);
    expect(await prisma.loginEvent.count({ where: { userId: other.id } })).toBe(0);
  });

  it('a verified email with LIKE wildcards cannot sign in to a different account', async (ctx) => {
    if (!dbAvailable || !prisma) return ctx.skip();
    const john = await makeEmailUser(mail('john'));
    const attackerEmail = john.email.replace('john', 'j_hn');
    asserts({ providerId: `gh-wild-${nonce}`, email: attackerEmail, emailVerified: true, name: 'Eve' });

    const res = await callback('github');

    // A brand-new account for the attacker's own address, never John's.
    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toMatch(/\/onboarding#jwt=/);
    expect(await prisma.loginEvent.count({ where: { userId: john.id } })).toBe(0);
    expect(await prisma.user.findUniqueOrThrow({ where: { id: john.id } })).toMatchObject({ provider: 'EMAIL', providerId: null });
    expect(await prisma.user.count({ where: { email: attackerEmail } })).toBe(1);
  });

  it('does not create an account for an unverified email', async (ctx) => {
    if (!dbAvailable || !prisma) return ctx.skip();
    const email = mail('newbie');
    asserts({ providerId: `gh-${nonce}`, email, emailVerified: false, name: 'New' });

    expectGenericFailure(await callback('github'));
    expect(await prisma.user.count({ where: { email } })).toBe(0);
  });

  it('creates an account for a verified email', async (ctx) => {
    if (!dbAvailable || !prisma) return ctx.skip();
    const email = mail('fresh');
    asserts({ providerId: `g2-${nonce}`, email, emailVerified: true, name: 'Fresh' });

    const res = await callback('google');

    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toMatch(/\/onboarding#jwt=/);
    const created = await prisma.user.findFirstOrThrow({ where: { email } });
    expect(created).toMatchObject({ provider: 'GOOGLE', providerId: `g2-${nonce}`, emailVerified: true });
  });

  it('keeps the lockout check, with the generic response and a failure LoginEvent', async (ctx) => {
    if (!dbAvailable || !prisma) return ctx.skip();
    const user = await makeEmailUser(mail('locked'), { lockedUntil: new Date(Date.now() + 15 * 60_000) });
    asserts({ providerId: `g3-${nonce}`, email: user.email, emailVerified: true, name: 'L' });

    expectGenericFailure(await callback('google'));
    expect(await prisma.loginEvent.count({ where: { userId: user.id, success: false, provider: 'GOOGLE' } })).toBe(1);
  });

  it('never echoes provider/token errors to the client', async (ctx) => {
    if (!dbAvailable || !prisma) return ctx.skip();
    providerIdentity = async () => {
      throw new Error('Microsoft ID token verification failed: secret-detail-xyz');
    };

    const res = await callback('microsoft');

    expectGenericFailure(res);
    expect(res.body).not.toContain('secret-detail-xyz');
  });
});
