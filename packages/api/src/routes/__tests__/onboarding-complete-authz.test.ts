import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * Audit 2026-10 FINDING-005: POST /onboarding/complete changes the
 * organization's public name and slug, so it is OWNER-only, refuses API-key
 * principals, applies once per ORGANIZATION, runs as one transaction, and
 * merges into kycData instead of replacing it.
 */

process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);
process.env.WEBAUTHN_ORIGIN ??= 'https://qrauth.test';

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

const ORG_ID = 'org_1';

let org: Record<string, any> = {};
let users: Record<string, { onboardedAt: Date | null }> = {};
let transactions = 0;
let insideTransaction = false;
let writesOutsideTransaction = 0;
let signingKeysCreated = 0;
let failSigningKeyOnce = false;

function write<T>(fn: () => T): T {
  if (!insideTransaction) writesOutsideTransaction += 1;
  return fn();
}

const prisma: Record<string, any> = {
  user: {
    findUnique: async ({ where }: any) => (users[where.id] ? { ...users[where.id] } : null),
    update: async ({ where, data }: any) => write(() => {
      if (!users[where.id]) throw new Error('Record to update not found.');
      Object.assign(users[where.id], data);
      return { ...users[where.id] };
    }),
  },
  organization: {
    findUnique: async () => ({ ...org }),
    findFirst: async () => null,
    update: async ({ data }: any) => write(() => {
      Object.assign(org, data);
      return { ...org };
    }),
    updateMany: async ({ where, data }: any) => write(() => {
      if (where.onboardedAt === null && org.onboardedAt !== null) return { count: 0 };
      Object.assign(org, data);
      return { count: 1 };
    }),
  },
  signingKey: { findFirst: async () => null },
  $transaction: async (fn: (tx: unknown) => Promise<unknown>) => {
    transactions += 1;
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
  app.decorate('signingService', {
    createKeyPair: async () => {
      if (failSigningKeyOnce) {
        failSigningKeyOnce = false;
        throw new Error('signer unavailable');
      }
      signingKeysCreated += 1;
      return {};
    },
  } as never);
  app.decorate('authenticate', async (req: never) => {
    const request = req as unknown as { headers: Record<string, string>; user?: unknown };
    request.user = {
      id: request.headers['x-test-user'],
      orgId: ORG_ID,
      role: request.headers['x-test-role'],
      email: 'someone@example.com',
    };
  });
  const { default: authRoutes } = await import('../auth.js');
  await app.register(authRoutes, { prefix: '/api/v1/auth' });
  await app.ready();
});

afterAll(async () => {
  await app?.close();
});

beforeEach(() => {
  org = {
    id: ORG_ID,
    name: 'Original Org',
    slug: 'original-org',
    onboardedAt: null,
    kycData: { domainVerification: { method: 'dns' } },
  };
  users = { user_1: { onboardedAt: null } };
  transactions = 0;
  writesOutsideTransaction = 0;
  signingKeysCreated = 0;
  failSigningKeyOnce = false;
});

const complete = (userId: string, role: string) => app.inject({
  method: 'POST',
  url: '/api/v1/auth/onboarding/complete',
  headers: { 'x-test-user': userId, 'x-test-role': role },
  payload: { organizationName: 'Renamed By Caller', useCase: 'MUNICIPALITY' },
});

describe('POST /onboarding/complete — authorization (FINDING-005)', () => {
  it('refuses an API-key principal and leaves the organization unchanged', async () => {
    const res = await complete('api-key', 'OWNER');

    expect(res.statusCode).toBe(403);
    expect(org.name).toBe('Original Org');
    expect(org.kycData).toEqual({ domainVerification: { method: 'dns' } });
  });

  it.each(['ADMIN', 'MANAGER', 'MEMBER', 'VIEWER'])(
    'a %s cannot rename the organization, but is no longer sent back to onboarding',
    async (role) => {
      const res = await complete('user_1', role);

      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ success: true, alreadyOnboarded: true });
      expect(org.name).toBe('Original Org');
      expect(org.slug).toBe('original-org');
      expect(org.kycData).toEqual({ domainVerification: { method: 'dns' } });
      expect(users.user_1.onboardedAt).toBeInstanceOf(Date);
      expect(signingKeysCreated).toBe(0);
    },
  );

  it('an OWNER completes onboarding once for the organization', async () => {
    const res = await complete('user_1', 'OWNER');

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ success: true, alreadyOnboarded: false });
    expect(org.name).toBe('Renamed By Caller');
    expect(org.slug).toBe('renamed-by-caller');
    expect(org.onboardedAt).toBeInstanceOf(Date);
    expect(users.user_1.onboardedAt).toBeInstanceOf(Date);
    expect(signingKeysCreated).toBe(1);
  });

  it('merges the use case into kycData instead of replacing it', async () => {
    await complete('user_1', 'OWNER');

    expect(org.kycData).toEqual({
      domainVerification: { method: 'dns' },
      onboardingUseCase: 'MUNICIPALITY',
    });
  });

  it('a second OWNER cannot re-run onboarding on an onboarded organization', async () => {
    org.onboardedAt = new Date('2026-01-01T00:00:00Z');
    users.user_2 = { onboardedAt: null };

    const res = await complete('user_2', 'OWNER');

    expect(res.json()).toEqual({ success: true, alreadyOnboarded: true });
    expect(org.name).toBe('Original Org');
    expect(users.user_2.onboardedAt).toBeInstanceOf(Date);
  });

  it('a failed signing-key creation leaves nothing onboarded, so a retry works', async () => {
    failSigningKeyOnce = true;

    const failed = await complete('user_1', 'OWNER');
    const retried = await complete('user_1', 'OWNER');

    expect(failed.statusCode).toBe(500);
    expect(retried.json()).toEqual({ success: true, alreadyOnboarded: false });
    expect(org.name).toBe('Renamed By Caller');
    expect(signingKeysCreated).toBe(1);
  });

  it('writes the organization and the user in one transaction', async () => {
    await complete('user_1', 'OWNER');

    expect(transactions).toBe(1);
    expect(writesOutsideTransaction).toBe(0);
  });
});
