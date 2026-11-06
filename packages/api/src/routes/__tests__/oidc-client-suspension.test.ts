import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHash, randomBytes } from 'node:crypto';

/**
 * OIDC clients of a suspended organization: /authorize redirects
 * access_denied (error page when the redirect_uri is not registered),
 * /token refuses every grant with invalid_client before touching the code
 * or refresh token, and /userinfo rejects the client's access tokens.
 * Nothing is revoked, so lifting the suspension restores them.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);
process.env.OIDC_PAIRWISE_SECRET = randomBytes(32).toString('base64');

vi.mock('../../lib/cache.js', () => ({
  redis: {},
  cacheGet: vi.fn(async () => null),
  cacheSet: vi.fn(async () => undefined),
  cacheDel: vi.fn(async () => undefined),
  cacheTake: vi.fn(async () => null),
  disconnectCache: vi.fn(async () => undefined),
}));

const { constantTimeEqualString } = await import('../../lib/constant-time.js');
const sha256 = (v: string) => createHash('sha256').update(v).digest('hex');
const SECRET = 'client-secret';
const REDIRECT_URI = 'https://rp.example/callback';
const ACCESS_TOKEN = 'access-token-value';

const org = { suspendedAt: null as Date | null };
const client = {
  id: 'client_db_1',
  organizationId: 'org_1',
  clientId: 'qrauth_oidc_test',
  clientSecretHash: sha256(SECRET),
  tier: 'CUSTOMER',
  consentRequired: true,
  name: 'Example Shop',
  redirectUris: [REDIRECT_URI],
  postLogoutRedirectUris: [],
  allowedScopes: ['openid', 'offline_access', 'email'],
  sectorIdentifierUri: null,
  sectorHost: 'rp.example',
  get organization() {
    return { name: 'Example Ltd', suspendedAt: org.suspendedAt };
  },
};

const refreshLookup = vi.fn(async () => null);
const codeLookup = vi.fn(async () => null);
const prisma: Record<string, any> = {
  oidcClient: { findUnique: async ({ where }: any) => (where.clientId === client.clientId || where.id === client.id ? client : null) },
  organization: { findUnique: async () => ({ suspendedAt: org.suspendedAt }) },
  oidcRefreshToken: { findUnique: refreshLookup, findFirst: async () => null, updateMany: async () => ({ count: 0 }) },
  oidcAuthCode: { findUnique: codeLookup, updateMany: async () => ({ count: 0 }) },
  oidcAccessToken: {
    findUnique: async ({ where }: any) =>
      constantTimeEqualString(where.tokenHash, sha256(ACCESS_TOKEN))
        ? { oidcClientId: client.id, userId: 'user_1', scope: 'openid email', revokedAt: null, expiresAt: new Date(Date.now() + 600_000) }
        : null,
  },
  user: { findUnique: async () => ({ name: 'Person', email: 'p@example.com', emailVerified: true, avatarUrl: null }) },
  oidcSession: { findUnique: async () => null },
  $transaction: async (ops: unknown) => (Array.isArray(ops) ? Promise.all(ops) : (ops as any)(prisma)),
};

let app: FastifyInstance;

const authorize = (redirectUri = REDIRECT_URI) =>
  app.inject({
    method: 'GET',
    url: `/authorize?${new URLSearchParams({ response_type: 'code', client_id: client.clientId, redirect_uri: redirectUri, scope: 'openid', state: 'st8' })}`,
  });
const token = (params: Record<string, string>) =>
  app.inject({
    method: 'POST',
    url: '/token',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams({ client_id: client.clientId, client_secret: SECRET, ...params }).toString(),
  });
const userinfo = () => app.inject({ method: 'GET', url: '/userinfo', headers: { authorization: `Bearer ${ACCESS_TOKEN}` } });

beforeAll(async () => {
  app = Fastify({ logger: false });
  await app.register((await import('@fastify/cookie')).default);
  app.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string' }, (_req, body, done) => {
    done(null, Object.fromEntries(new URLSearchParams(body as string)));
  });
  app.decorate('prisma', prisma as never);
  app.decorate('signingService', {} as never);
  app.decorate('authenticate', async () => undefined);
  const { default: oidcFlowRoutes } = await import('../oidc-flow.js');
  await app.register(oidcFlowRoutes);
  await app.ready();
});

afterAll(async () => {
  await app?.close();
});

beforeEach(() => {
  org.suspendedAt = null;
  refreshLookup.mockClear();
  codeLookup.mockClear();
});

describe('client of a suspended organization', () => {
  beforeEach(() => {
    org.suspendedAt = new Date('2026-10-27T10:00:00Z');
  });

  it('/authorize redirects back with error=access_denied and the state', async () => {
    const res = await authorize();

    expect(res.statusCode).toBe(302);
    const location = new URL(String(res.headers.location));
    expect(location.origin + location.pathname).toBe(REDIRECT_URI);
    expect(location.searchParams.get('error')).toBe('access_denied');
    expect(location.searchParams.get('state')).toBe('st8');
  });

  it('/authorize with an unregistered redirect_uri shows the error page, no redirect', async () => {
    const res = await authorize('https://evil.example/cb');

    expect(res.statusCode).toBe(400);
    expect(res.headers.location).toBeUndefined();
  });

  it.each([
    ['refresh_token', { grant_type: 'refresh_token', refresh_token: 'rt-1' }],
    ['authorization_code', { grant_type: 'authorization_code', code: 'code-1', redirect_uri: REDIRECT_URI }],
  ])('/token %s grant → 401 invalid_client, nothing consumed', async (_label, params) => {
    const res = await token(params);

    expect(res.statusCode).toBe(401);
    expect(res.json()).toMatchObject({ error: 'invalid_client', error_description: 'the client is disabled' });
    expect(refreshLookup).not.toHaveBeenCalled();
    expect(codeLookup).not.toHaveBeenCalled();
  });

  it('/userinfo rejects the client\'s access token (401)', async () => {
    const res = await userinfo();

    expect(res.statusCode).toBe(401);
  });
});

describe('after the suspension is lifted', () => {
  it('/authorize no longer answers access_denied', async () => {
    const res = await authorize();

    expect(String(res.headers.location ?? '')).not.toContain('error=access_denied');
  });

  it('/token gets past client authentication to the grant itself', async () => {
    const res = await token({ grant_type: 'refresh_token', refresh_token: 'rt-1' });

    expect(res.json().error).not.toBe('invalid_client');
    expect(refreshLookup).toHaveBeenCalled();
  });

  it('/userinfo accepts the same, unrevoked access token', async () => {
    const res = await userinfo();

    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ email: 'p@example.com' });
  });
});
