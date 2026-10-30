import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * A linked Microsoft account remembers the tenant (`tid`) it was linked from.
 * The first sign-in records it, a sign-in from the same tenant succeeds, and
 * one from another tenant is refused with the generic failure. Other providers
 * never store a tenant. In-memory Prisma stand-in — no database.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);
process.env.WEBAUTHN_ORIGIN = 'https://qrauth.test';

vi.mock('../../lib/cache.js', () => ({
  redis: {},
  cacheGet: vi.fn(async () => ({ valid: true, codeVerifier: 'test-code-verifier' })),
  cacheSet: vi.fn(async () => undefined),
  cacheDel: vi.fn(async () => undefined),
  disconnectCache: vi.fn(async () => undefined),
}));

let providerIdentity: Record<string, unknown> = {};
vi.mock('../../lib/oauth.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../lib/oauth.js')>()),
  exchangeCodeForUser: async () => providerIdentity,
}));

vi.mock('../../lib/metadata.js', () => ({ collectRequestMetadata: async () => ({}) }));

const loginEvents: Array<{ userId: string; success: boolean }> = [];
vi.mock('../../services/login-event.js', () => ({
  LoginEventService: class {
    async record(userId: string, success: boolean) {
      loginEvents.push({ userId, success });
    }
  },
}));

vi.mock('../../services/device.js', () => ({ DeviceService: class {} }));

const { OAUTH_STATE_COOKIE, hashOAuthState } = await import('../../lib/oauth-state-binding.js');
const { OAUTH_SIGN_IN_PATH } = await import('../auth.js');

// ---------------------------------------------------------------------------
// In-memory Prisma stand-in: only the calls the OAuth callback makes.
// ---------------------------------------------------------------------------

interface UserRow {
  id: string;
  name: string;
  email: string;
  passwordHash: string;
  emailVerified: boolean;
  provider: string;
  providerId: string | null;
  providerTenantId: string | null;
  avatarUrl: string | null;
  lockedUntil: Date | null;
  createdAt: Date;
}

const ORG = { id: 'org_1', name: 'Org', slug: 'org' };
let users: UserRow[] = [];

function seedUser(overrides: Partial<UserRow> = {}): UserRow {
  const row: UserRow = {
    id: `user_${users.length + 1}`,
    name: 'Someone',
    email: 'person@contoso.example',
    passwordHash: '',
    emailVerified: true,
    provider: 'EMAIL',
    providerId: null,
    providerTenantId: null,
    avatarUrl: null,
    lockedUntil: null,
    createdAt: new Date(),
    ...overrides,
  };
  users.push(row);
  return row;
}

function matchesUserWhere(user: UserRow, where: Record<string, any>): boolean {
  for (const key of ['id', 'provider', 'providerId', 'providerTenantId'] as const) {
    if (key in where && user[key] !== where[key]) return false;
  }
  if (typeof where.email === 'string' && user.email !== where.email) return false;
  if (where.email && typeof where.email === 'object') {
    const wanted = String(where.email.equals).replace(/\\([\\%_])/g, '$1');
    if (user.email.toLowerCase() !== wanted.toLowerCase()) return false;
  }
  return true;
}

function applyData(user: UserRow, data: Record<string, unknown>) {
  for (const [key, value] of Object.entries(data)) {
    if (value !== undefined) (user as any)[key] = value;
  }
}

const prisma: Record<string, any> = {
  user: {
    findUnique: async ({ where, include }: any) => {
      const user = users.find((u) => matchesUserWhere(u, where));
      if (!user) return null;
      return include?.memberships
        ? { ...user, memberships: [{ userId: user.id, organizationId: ORG.id, role: 'OWNER', organization: ORG }] }
        : { ...user };
    },
    findFirst: async ({ where }: any) => users.find((u) => matchesUserWhere(u, where)) ?? null,
    findMany: async ({ where }: any) => users.filter((u) => matchesUserWhere(u, where)),
    update: async ({ where, data }: any) => {
      const user = users.find((u) => u.id === where.id)!;
      applyData(user, data);
      return { ...user };
    },
    updateMany: async ({ where, data }: any) => {
      const hit = users.filter((u) => matchesUserWhere(u, where));
      hit.forEach((u) => applyData(u, data));
      return { count: hit.length };
    },
    create: async ({ data }: any) => seedUser({ ...data, id: `user_new_${users.length + 1}` }),
  },
  organization: {
    findUnique: async () => null,
    create: async ({ data }: any) => ({ id: 'org_new', ...data }),
  },
  membership: { create: async () => ({}) },
  refreshToken: { create: async ({ data }: any) => data },
  // The claim path of an already-verified account is a no-op here.
  apiKey: { updateMany: async () => ({ count: 0 }) },
  $transaction: async (fn: (tx: unknown) => Promise<unknown>) => fn(prisma),
};

// ---------------------------------------------------------------------------

const BASE = 'https://qrauth.test';
const OID = 'oid-1';
const TENANT = '11111111-2222-3333-4444-555555555555';
const OTHER_TENANT = '99999999-8888-7777-6666-555555555555';

let app: FastifyInstance;
const logLines: string[] = [];

function microsoftIdentity(overrides: Record<string, unknown> = {}) {
  return {
    providerId: OID,
    email: 'person@contoso.example',
    emailVerified: true,
    name: 'Person',
    personalMicrosoftAccount: false,
    tenantId: TENANT,
    ...overrides,
  };
}

async function callback(provider = 'microsoft') {
  const state = Buffer.from(JSON.stringify({ csrf: 'x', returnTo: '', authSessionToken: '' })).toString('base64url');
  return app.inject({
    method: 'GET',
    url: `/api/v1/auth/oauth/${provider}/callback?code=abc&state=${state}`,
    cookies: { [OAUTH_STATE_COOKIE]: hashOAuthState(state) },
  });
}

beforeAll(async () => {
  app = Fastify({ logger: { level: 'info', stream: { write: (line: string) => { logLines.push(line); } } } });
  await app.register((await import('@fastify/cookie')).default);
  await app.register((await import('@fastify/jwt')).default, { secret: 'b'.repeat(32) });
  app.decorate('prisma', prisma as never);
  app.decorate('signingService', { createKeyPair: async () => ({}) } as never);
  app.decorate('authenticate', async () => undefined);
  const { default: authRoutes } = await import('../auth.js');
  await app.register(authRoutes, { prefix: '/api/v1/auth' });
  await app.ready();
});

afterAll(async () => {
  await app?.close();
});

beforeEach(() => {
  users = [];
  loginEvents.length = 0;
  logLines.length = 0;
  providerIdentity = microsoftIdentity();
});

describe('Microsoft sign-in records and checks the tenant of the linked account', () => {
  it('first sign-in on an existing link backfills the tenant', async () => {
    const account = seedUser({ provider: 'MICROSOFT', providerId: OID });

    const res = await callback();

    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toContain(`${BASE}/dashboard#jwt=`);
    expect(account.providerTenantId).toBe(TENANT);
  });

  it('a sign-in from the stored tenant succeeds and leaves it unchanged', async () => {
    const account = seedUser({ provider: 'MICROSOFT', providerId: OID, providerTenantId: TENANT });

    const res = await callback();

    expect(res.headers.location).toContain(`${BASE}/dashboard#jwt=`);
    expect(account.providerTenantId).toBe(TENANT);
  });

  it('a sign-in from another tenant with the same oid is refused as failed', async () => {
    const account = seedUser({ provider: 'MICROSOFT', providerId: OID, providerTenantId: TENANT });
    providerIdentity = microsoftIdentity({ tenantId: OTHER_TENANT });

    const res = await callback();

    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe(`${BASE}${OAUTH_SIGN_IN_PATH}?oauth_error=failed`);
    expect(res.headers['set-cookie']?.toString() ?? '').not.toContain('refresh');
    expect(account.providerTenantId).toBe(TENANT);
    expect(loginEvents).toEqual([{ userId: account.id, success: false }]);
  });

  it('logs the refusal at warn with no identifiers', async () => {
    const account = seedUser({ provider: 'MICROSOFT', providerId: OID, providerTenantId: TENANT });
    providerIdentity = microsoftIdentity({ tenantId: OTHER_TENANT });

    await callback();

    const event = logLines.map((l) => JSON.parse(l)).find((l) => l.event === 'oauth.refused_tenant_mismatch');
    expect(event).toMatchObject({ level: 40, provider: 'microsoft', mismatch: true });
    const all = logLines.join('\n');
    for (const identifier of [account.id, OID, TENANT, OTHER_TENANT, 'person@contoso.example']) {
      expect(all).not.toContain(identifier);
    }
  });

  it('a new Microsoft account stores oid and tid', async () => {
    const res = await callback();

    expect(res.headers.location).toContain(`${BASE}/onboarding#jwt=`);
    expect(users).toHaveLength(1);
    expect(users[0]).toMatchObject({ provider: 'MICROSOFT', providerId: OID, providerTenantId: TENANT });
  });

  it('linking Microsoft to an existing account by verified email stores oid and tid', async () => {
    const account = seedUser();

    await callback();

    expect(account).toMatchObject({ provider: 'MICROSOFT', providerId: OID, providerTenantId: TENANT });
  });
});

describe('Other providers never store a tenant', () => {
  it('a Google sign-in on an existing link writes no tenant', async () => {
    const account = seedUser({ provider: 'GOOGLE', providerId: 'google-sub-1' });
    providerIdentity = { providerId: 'google-sub-1', email: 'person@contoso.example', emailVerified: true, name: 'Person' };

    const res = await callback('google');

    expect(res.headers.location).toContain(`${BASE}/dashboard#jwt=`);
    expect(account.providerTenantId).toBeNull();
  });

  it('a new Google account has no tenant', async () => {
    providerIdentity = { providerId: 'google-sub-2', email: 'new@example.com', emailVerified: true, name: 'New' };

    await callback('google');

    expect(users[0]).toMatchObject({ provider: 'GOOGLE', providerId: 'google-sub-2', providerTenantId: null });
  });
});
