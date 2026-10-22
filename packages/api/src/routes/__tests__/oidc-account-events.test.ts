import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHash } from 'node:crypto';

/**
 * Audit 2026-10 FINDING-011: a change in the account's standing ends what
 * the OP issued for it. Covers the report's test (after a password reset the
 * old OP cookie no longer authorizes and the refresh grant is dead), device
 * revocation, that a lockout does NOT revoke, and a refresh after the consent
 * was withdrawn.
 * Real routes and services, in-memory Prisma stand-in.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

vi.mock('../../lib/cache.js', () => ({
  redis: {},
  cacheGet: vi.fn(async () => null),
  cacheSet: vi.fn(async () => undefined),
  cacheDel: vi.fn(async () => undefined),
  cacheTake: vi.fn(async () => null),
  disconnectCache: vi.fn(async () => undefined),
}));
vi.mock('../../lib/email.js', () => ({
  sendPasswordResetEmail: vi.fn(async () => undefined),
  sendWelcomeVerificationEmail: vi.fn(async () => undefined),
  sendPasswordChangedEmail: vi.fn(async () => undefined),
  sendSuspiciousLoginEmail: vi.fn(async () => undefined),
}));

const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');

const USER = 'user_1';
const OTHER_USER = 'user_2';
const SESSION = 'op-session-token';
const RESET_TOKEN = 'reset-token';
const SECRET = 'client-secret';
const REDIRECT_URI = 'https://rp.example/callback';

interface Row { userId: string; revokedAt: Date | null; [key: string]: unknown }

const client = {
  id: 'client_db_1',
  clientId: 'qrauth_oidc_test',
  clientSecretHash: sha256(SECRET),
  tier: 'CUSTOMER',
  consentRequired: true,
  name: 'Example Shop',
  redirectUris: [REDIRECT_URI],
  postLogoutRedirectUris: [],
  allowedScopes: ['openid', 'offline_access'],
  sectorIdentifierUri: null,
  sectorHost: 'rp.example',
  organization: { name: 'Example Ltd' },
};

let sessions = new Map<string, Row>();
let refreshTokens = new Map<string, Row>();
let accessTokens: Row[] = [];
let authCodes: Array<{ userId: string; usedAt: Date | null }> = [];
let consent: { grantedScopes: string[]; revokedAt: Date | null } | null = null;
let failedLoginAttempts = 0;

function revokeForUser(rows: Iterable<Row>) {
  return async ({ where, data }: any) => {
    const hit = [...rows].filter((r) => r.userId === where.userId && r.revokedAt === null);
    hit.forEach((r) => { r.revokedAt = data.revokedAt; });
    return { count: hit.length };
  };
}

const prisma: Record<string, any> = {
  user: {
    findFirst: async ({ where }: any) =>
      where.passwordResetToken === sha256(RESET_TOKEN) ? { id: USER, email: 'person@example.com', name: 'Person' } : null,
    // A verified account: password reset is a plain reset, not a claim.
    findUnique: async () => ({ emailVerified: true }),
    update: async ({ data }: any) => {
      if (data.failedLoginAttempts?.increment) failedLoginAttempts += data.failedLoginAttempts.increment;
      return { failedLoginAttempts };
    },
  },
  refreshToken: { updateMany: async () => ({ count: 0 }) },
  membership: { findFirst: async () => null },
  oidcClient: { findUnique: async ({ where }: any) => (where.clientId === client.clientId || where.id === client.id ? client : null) },
  oidcSession: {
    findUnique: async ({ where }: any) => sessions.get(where.sessionTokenHash) ?? null,
    updateMany: (args: any) => revokeForUser(sessions.values())(args),
  },
  oidcRefreshToken: {
    findUnique: async ({ where }: any) => refreshTokens.get(where.tokenHash) ?? null,
    findFirst: async ({ where }: any) =>
      [...refreshTokens.values()].find((t) => t.familyId === where.familyId) ?? null,
    updateMany: async (args: any) => {
      if (args.where.familyId) {
        const hit = [...refreshTokens.values()].filter((t) => t.familyId === args.where.familyId && t.revokedAt === null);
        hit.forEach((t) => { t.revokedAt = args.data.revokedAt; });
        return { count: hit.length };
      }
      return revokeForUser(refreshTokens.values())(args);
    },
  },
  oidcAccessToken: { updateMany: (args: any) => revokeForUser(accessTokens)(args) },
  oidcAuthCode: {
    updateMany: async ({ where, data }: any) => {
      const hit = authCodes.filter((c) => c.userId === where.userId && c.usedAt === null);
      hit.forEach((c) => { c.usedAt = data.usedAt; });
      return { count: hit.length };
    },
  },
  oidcConsent: { findUnique: async () => consent },
  trustedDevice: {
    findFirst: async ({ where }: any) => (where.id === 'device_1' && where.userId === USER ? { id: 'device_1' } : null),
    update: async () => ({}),
  },
  passkey: { updateMany: async () => ({ count: 0 }) },
  $transaction: async (ops: unknown) => (Array.isArray(ops) ? Promise.all(ops) : (ops as any)(prisma)),
};

let app: FastifyInstance;

const refreshGrant = (token: string) =>
  app.inject({
    method: 'POST',
    url: '/token',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: token,
      client_id: client.clientId,
      client_secret: SECRET,
    }).toString(),
  });

const authorizeWithOldCookie = () =>
  app.inject({
    method: 'GET',
    url: `/authorize?${new URLSearchParams({
      response_type: 'code', client_id: client.clientId, redirect_uri: REDIRECT_URI, scope: 'openid', state: 's',
    }).toString()}`,
    cookies: { qrauth_op_session: SESSION },
  });

function expectEverythingRevokedFor(userId: string) {
  const mine = <T extends Row>(rows: Iterable<T>) => [...rows].filter((r) => r.userId === userId);
  expect(mine(sessions.values()).every((r) => r.revokedAt !== null)).toBe(true);
  expect(mine(refreshTokens.values()).every((r) => r.revokedAt !== null)).toBe(true);
  expect(mine(accessTokens).every((r) => r.revokedAt !== null)).toBe(true);
  expect(authCodes.filter((c) => c.userId === userId).every((c) => c.usedAt !== null)).toBe(true);
}

function expectUntouchedFor(userId: string) {
  expect([...sessions.values()].filter((r) => r.userId === userId).every((r) => r.revokedAt === null)).toBe(true);
  expect([...refreshTokens.values()].filter((r) => r.userId === userId).every((r) => r.revokedAt === null)).toBe(true);
  expect(accessTokens.filter((r) => r.userId === userId).every((r) => r.revokedAt === null)).toBe(true);
}

beforeAll(async () => {
  app = Fastify({ logger: false });
  await app.register((await import('@fastify/cookie')).default);
  await app.register((await import('@fastify/jwt')).default, { secret: 'b'.repeat(32) });
  app.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string' }, (_req, body, done) => {
    done(null, Object.fromEntries(new URLSearchParams(body as string)));
  });
  app.decorate('prisma', prisma as never);
  app.decorate('signingService', {} as never);
  app.decorate('authenticate', async () => undefined);
  const { default: authRoutes } = await import('../auth.js');
  await app.register(authRoutes, { prefix: '/api/v1/auth' });
  const { default: oidcFlowRoutes } = await import('../oidc-flow.js');
  await app.register(oidcFlowRoutes);
  await app.ready();
});

afterAll(async () => {
  await app?.close();
});

beforeEach(() => {
  const future = new Date(Date.now() + 3_600_000);
  sessions = new Map<string, Row>([
    [sha256(SESSION), { userId: USER, createdAt: new Date(), expiresAt: future, revokedAt: null }],
    [sha256('other-session'), { userId: OTHER_USER, createdAt: new Date(), expiresAt: future, revokedAt: null }],
  ]);
  refreshTokens = new Map<string, Row>([
    [sha256('rt-user'), { userId: USER, oidcClientId: client.id, familyId: 'fam_1', scope: 'openid offline_access', createdAt: new Date(), expiresAt: future, rotatedAt: null, revokedAt: null, authTime: new Date() }],
    [sha256('rt-other'), { userId: OTHER_USER, oidcClientId: client.id, familyId: 'fam_2', scope: 'openid offline_access', createdAt: new Date(), expiresAt: future, rotatedAt: null, revokedAt: null, authTime: new Date() }],
  ]);
  accessTokens = [
    { userId: USER, revokedAt: null },
    { userId: OTHER_USER, revokedAt: null },
  ];
  authCodes = [{ userId: USER, usedAt: null }];
  consent = { grantedScopes: ['openid', 'offline_access'], revokedAt: null };
  failedLoginAttempts = 0;
});

describe('password reset', () => {
  it('ends the OP session and the refresh grant (the audit report test)', async () => {
    const reset = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/reset-password',
      payload: { token: RESET_TOKEN, password: 'a-new-long-password-1' },
    });
    expect(reset.statusCode).toBe(200);

    const authorize = await authorizeWithOldCookie();
    expect(authorize.statusCode).toBe(302);
    expect(String(authorize.headers.location)).toMatch(/^\/login\?returnTo=/);

    const refresh = await refreshGrant('rt-user');
    expect(refresh.statusCode).toBe(400);
    expect(refresh.json().error).toBe('invalid_grant');

    expectEverythingRevokedFor(USER);
    expectUntouchedFor(OTHER_USER);
  });
});

describe('account lockout', () => {
  it('locks the account but leaves OP sessions and OIDC tokens alone', async () => {
    // Anyone who knows the address can cause a lockout, so it must not be a
    // way to sign the user out of every relying party.
    const { LoginEventService } = await import('../../services/login-event.js');
    const { MAX_FAILED_LOGIN_ATTEMPTS } = await import('@qrauth/shared');
    const service = new LoginEventService(prisma as never);

    let last = { locked: false };
    for (let attempt = 1; attempt <= MAX_FAILED_LOGIN_ATTEMPTS; attempt++) {
      last = await service.recordFailedAttempt(USER);
    }

    expect(last.locked).toBe(true);
    expectUntouchedFor(USER);
    expect(authCodes.every((code) => code.usedAt === null)).toBe(true);
    expectUntouchedFor(OTHER_USER);
  });
});

describe('device revocation', () => {
  it('ends everything the OP issued for the user', async () => {
    const { DeviceService } = await import('../../services/device.js');

    const result = await new DeviceService(prisma as never).revokeDevice('device_1', USER);

    expect(result).toEqual({ revoked: true });
    expectEverythingRevokedFor(USER);
    expectUntouchedFor(OTHER_USER);
  });

  it("does nothing for a device that is not the user's", async () => {
    const { DeviceService } = await import('../../services/device.js');

    const result = await new DeviceService(prisma as never).revokeDevice('device_1', OTHER_USER);

    expect(result).toBeNull();
    expectUntouchedFor(OTHER_USER);
  });
});

describe('refresh after the consent was withdrawn', () => {
  it('returns invalid_grant and kills the family', async () => {
    consent = { grantedScopes: ['openid', 'offline_access'], revokedAt: new Date() };

    const res = await refreshGrant('rt-user');

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_grant');
    expect(refreshTokens.get(sha256('rt-user'))!.revokedAt).toBeInstanceOf(Date);
    expect(refreshTokens.get(sha256('rt-other'))!.revokedAt).toBeNull();
  });

  it('a narrowing request without openid is invalid_scope and leaves the family alive', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/token',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams({
        grant_type: 'refresh_token', refresh_token: 'rt-user', scope: 'offline_access',
        client_id: client.clientId, client_secret: SECRET,
      }).toString(),
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_scope');
    expect(refreshTokens.get(sha256('rt-user'))!.revokedAt).toBeNull();
  });

  it('malformed Basic credentials are a 401, not a server error', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/token',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${Buffer.from('%E0%A4%A:secret').toString('base64')}`,
      },
      payload: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: 'rt-user' }).toString(),
    });

    expect(res.statusCode).toBe(401);
    expect(res.json().error).toBe('invalid_client');
  });

  it('returns invalid_grant when the client lost the openid scope', async () => {
    const original = client.allowedScopes;
    client.allowedScopes = ['offline_access'];
    try {
      const res = await refreshGrant('rt-user');
      expect(res.statusCode).toBe(400);
      expect(res.json().error).toBe('invalid_grant');
    } finally {
      client.allowedScopes = original;
    }
  });
});
