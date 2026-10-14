import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { randomBytes } from 'node:crypto';
import Fastify, { type FastifyInstance } from 'fastify';
import { PrismaClient } from '@prisma/client';

/**
 * scripts/provision-managed-user.ts (PerforMax pilot managed users).
 *
 * The argument tests are pure and always run. The provisioning tests run
 * against a REAL migrated Postgres (DATABASE_URL) and wire the real
 * routes/auth.ts POST /login and POST /reset-password onto a minimal Fastify
 * app, so "cannot log in before set-password" and "the printed link works"
 * are proven end to end. They skip cleanly when no migrated database is
 * reachable (CI's API unit-test job has no Postgres), mirroring
 * src/services/__tests__/approve-signing.integration.test.ts.
 */

// Config validation runs at import time; give it what it needs without a .env.
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

// Keep the test hermetic to Postgres: stub the Redis-backed cache (imported by
// routes/auth.ts and middleware/rateLimit.ts).
vi.mock('../../src/lib/cache.js', () => ({
  redis: {},
  cacheGet: vi.fn(async () => null),
  cacheSet: vi.fn(async () => undefined),
  cacheDel: vi.fn(async () => undefined),
  disconnectCache: vi.fn(async () => undefined),
}));

import {
  parseCliArgs,
  provisionManagedUser,
  ProvisionError,
  DEFAULT_TTL_HOURS,
  MAX_TTL_HOURS,
  type ProvisionOptions,
} from '../../scripts/provision-managed-user.js';
import { hashString } from '../../src/lib/crypto.js';

const REQUIRED = ['--email', 'Jane.Doe@Example.com', '--name', 'Jane Doe', '--org-slug', 'pilot-org'];
const NEW_PASSWORD = 'Correct-Horse-Battery-9';

// ---------------------------------------------------------------------------
// Argument parsing (no DB)
// ---------------------------------------------------------------------------

describe('parseCliArgs', () => {
  it('normalizes the email and applies defaults', () => {
    const opts = parseCliArgs(REQUIRED);
    expect(opts).toEqual({
      email: 'jane.doe@example.com',
      name: 'Jane Doe',
      orgSlug: 'pilot-org',
      role: 'MEMBER',
      ttlHours: DEFAULT_TTL_HOURS,
      dryRun: false,
    });
  });

  it('accepts a non-owner role, ttl and --dry-run', () => {
    const opts = parseCliArgs([...REQUIRED, '--role', 'viewer', '--ttl-hours', '72', '--dry-run']);
    expect(opts.role).toBe('VIEWER');
    expect(opts.ttlHours).toBe(MAX_TTL_HOURS);
    expect(opts.dryRun).toBe(true);
  });

  it('rejects --role OWNER', () => {
    expect(() => parseCliArgs([...REQUIRED, '--role', 'OWNER'])).toThrow(/OWNER is not allowed/);
    expect(() => parseCliArgs([...REQUIRED, '--role', 'owner'])).toThrow(ProvisionError);
  });

  it('rejects unknown roles', () => {
    expect(() => parseCliArgs([...REQUIRED, '--role', 'SUPERUSER'])).toThrow(/--role must be one of/);
  });

  it.each(['0', '73', '1.5', 'abc'])('rejects --ttl-hours %s', (ttl) => {
    expect(() => parseCliArgs([...REQUIRED, '--ttl-hours', ttl])).toThrow(/--ttl-hours/);
  });

  it('rejects an invalid email and missing required flags', () => {
    expect(() => parseCliArgs(['--email', 'not-an-email', '--name', 'Jane', '--org-slug', 'x'])).toThrow(/valid email/);
    expect(() => parseCliArgs(['--email', 'a@b.co', '--name', 'Jane'])).toThrow(/required/);
  });

  it('rejects unknown flags', () => {
    expect(() => parseCliArgs([...REQUIRED, '--password', 'x'])).toThrow(ProvisionError);
  });
});

// ---------------------------------------------------------------------------
// Provisioning (real DB)
// ---------------------------------------------------------------------------

const nonce = randomBytes(4).toString('hex');
let prisma: PrismaClient | null = null;
let dbAvailable = false;
let app: FastifyInstance | null = null;
let orgId = '';
const orgSlug = `it-pilot-${nonce}`;

function options(overrides: Partial<ProvisionOptions> = {}): ProvisionOptions {
  return {
    email: `managed-${nonce}-${randomBytes(3).toString('hex')}@example.com`,
    name: 'Managed User',
    orgSlug,
    role: 'MEMBER',
    ttlHours: DEFAULT_TTL_HOURS,
    dryRun: false,
    ...overrides,
  };
}

function tokenFrom(url: string | null): string {
  const token = new URL(url!).searchParams.get('token');
  expect(token).toMatch(/^[0-9a-f]{64}$/);
  return token!;
}

async function buildAuthApp(db: PrismaClient): Promise<FastifyInstance> {
  const instance = Fastify({ logger: false });
  await instance.register((await import('@fastify/cookie')).default);
  await instance.register((await import('@fastify/jwt')).default, { secret: 'b'.repeat(32) });
  instance.decorate('prisma', db);
  instance.decorate('signingService', {} as never);
  instance.decorate('authenticate', async () => undefined);
  const { default: authRoutes } = await import('../../src/routes/auth.js');
  await instance.register(authRoutes, { prefix: '/api/v1/auth' });
  await instance.ready();
  return instance;
}

function login(email: string, password: string) {
  return app!.inject({ method: 'POST', url: '/api/v1/auth/login', payload: { email, password } });
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
  const org = await prisma.organization.create({
    data: { name: `IT Pilot ${nonce}`, slug: orgSlug, email: `pilot-${nonce}@example.com` },
  });
  orgId = org.id;
  app = await buildAuthApp(prisma);
});

afterAll(async () => {
  await app?.close();
  if (!prisma) return;
  if (dbAvailable) {
    // Users first (memberships cascade); audit rows reference the user.
    const users = await prisma.user.findMany({ where: { email: { contains: nonce } }, select: { id: true } });
    const ids = users.map((u) => u.id);
    await prisma.auditLog.deleteMany({ where: { userId: { in: ids } } });
    await prisma.user.deleteMany({ where: { id: { in: ids } } });
    await prisma.organization.deleteMany({ where: { slug: orgSlug } });
  }
  await prisma.$disconnect().catch(() => undefined);
});

describe('provisionManagedUser (real DB)', () => {
  it('creates a verified, password-less, onboarded member with a hashed set-password token and an audit row', async (ctx) => {
    if (!dbAvailable || !prisma) return ctx.skip();
    const opts = options({ ttlHours: 24 });
    const now = new Date();

    const result = await provisionManagedUser(prisma, opts, now);

    expect(result.dryRun).toBe(false);
    expect(result.auditError).toBeNull();
    expect(result.expiresAt.getTime()).toBe(now.getTime() + 24 * 60 * 60 * 1000);
    const rawToken = tokenFrom(result.setPasswordUrl);
    expect(result.setPasswordUrl).toContain('/auth/jwt/reset-password?token=');

    const user = await prisma.user.findUniqueOrThrow({
      where: { id: result.userId! },
      include: { memberships: true },
    });
    expect(user.email).toBe(opts.email);
    expect(user.emailVerified).toBe(true);
    expect(user.emailVerifyToken).toBeNull();
    expect(user.passwordHash).toBe('');
    expect(user.onboardedAt).not.toBeNull();
    expect(user.passwordResetToken).toBe(hashString(rawToken));
    expect(user.passwordResetToken).not.toBe(rawToken);
    expect(user.passwordResetExpires?.getTime()).toBe(result.expiresAt.getTime());
    expect(user.memberships).toHaveLength(1);
    expect(user.memberships[0]).toMatchObject({ organizationId: orgId, role: 'MEMBER' });

    const audit = await prisma.auditLog.findMany({ where: { userId: user.id } });
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({
      organizationId: orgId,
      action: 'user.provisioned_by_operator',
      resource: 'User',
      resourceId: user.id,
    });
    expect(JSON.stringify(audit[0].metadata)).not.toContain(rawToken);
  });

  it('aborts on an existing email (any case) without modifying that account', async (ctx) => {
    if (!dbAvailable || !prisma) return ctx.skip();
    const email = `Existing-${nonce}@Example.com`;
    const existing = await prisma.user.create({
      data: { name: 'Existing', email, passwordHash: 'keep-me', emailVerified: false },
    });

    await expect(
      provisionManagedUser(prisma, options({ email: email.toLowerCase() })),
    ).rejects.toThrow(/already exists/);

    const after = await prisma.user.findUniqueOrThrow({ where: { id: existing.id } });
    expect(after).toEqual(existing);
    expect(await prisma.membership.count({ where: { userId: existing.id } })).toBe(0);
  });

  it('rejects OWNER even when called programmatically', async (ctx) => {
    if (!dbAvailable || !prisma) return ctx.skip();
    const opts = options({ role: 'OWNER' });
    await expect(provisionManagedUser(prisma, opts)).rejects.toThrow(/OWNER is not allowed/);
    expect(await prisma.user.count({ where: { email: opts.email } })).toBe(0);
  });

  it('aborts when the org slug does not exist', async (ctx) => {
    if (!dbAvailable || !prisma) return ctx.skip();
    const opts = options({ orgSlug: `missing-${nonce}` });
    await expect(provisionManagedUser(prisma, opts)).rejects.toThrow(/not found/);
    expect(await prisma.user.count({ where: { email: opts.email } })).toBe(0);
  });

  it('--dry-run validates but writes nothing', async (ctx) => {
    if (!dbAvailable || !prisma) return ctx.skip();
    const opts = options({ dryRun: true });
    const auditBefore = await prisma.auditLog.count({ where: { organizationId: orgId } });

    const result = await provisionManagedUser(prisma, opts);

    expect(result).toMatchObject({ dryRun: true, userId: null, setPasswordUrl: null, orgSlug });
    expect(await prisma.user.count({ where: { email: opts.email } })).toBe(0);
    expect(await prisma.membership.count({ where: { organizationId: orgId, user: { email: opts.email } } })).toBe(0);
    expect(await prisma.auditLog.count({ where: { organizationId: orgId } })).toBe(auditBefore);
  });

  it('cannot log in before set-password; the printed link sets a password that then works', async (ctx) => {
    if (!dbAvailable || !prisma || !app) return ctx.skip();
    const opts = options();
    const result = await provisionManagedUser(prisma, opts);
    const rawToken = tokenFrom(result.setPasswordUrl);

    for (const password of ['', 'x', NEW_PASSWORD]) {
      const res = await login(opts.email, password);
      expect(res.statusCode).not.toBe(200);
      expect(res.json()).not.toHaveProperty('token');
    }

    const reset = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/reset-password',
      payload: { token: rawToken, password: NEW_PASSWORD },
    });
    expect(reset.statusCode).toBe(200);

    const ok = await login(opts.email, NEW_PASSWORD);
    expect(ok.statusCode).toBe(200);
    expect(ok.json()).toMatchObject({
      token: expect.any(String),
      user: { id: result.userId, email: opts.email },
      organization: { slug: orgSlug },
    });

    // One-time: the link cannot be replayed.
    const replay = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/reset-password',
      payload: { token: rawToken, password: 'Another-Password-42' },
    });
    expect(replay.statusCode).toBe(400);
  });
});
