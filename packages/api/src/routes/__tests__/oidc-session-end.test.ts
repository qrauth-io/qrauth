import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHash } from 'node:crypto';
import { SignJWT, exportSPKI, generateKeyPair } from 'jose';

/**
 * Audit 2026-10 FINDING-011: RP-initiated logout (/logout) and RFC 7009
 * token revocation (/revoke). Real route plugin, in-memory Prisma stand-in,
 * a real ES256 key for the id_token_hint.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);
process.env.OIDC_PAIRWISE_SECRET = Buffer.alloc(32, 7).toString('base64');

vi.mock('../../lib/cache.js', () => ({
  redis: {},
  cacheGet: vi.fn(async () => null),
  cacheSet: vi.fn(async () => undefined),
  cacheDel: vi.fn(async () => undefined),
  cacheIncr: vi.fn(async () => 1),
  cacheTake: vi.fn(async () => null),
  disconnectCache: vi.fn(async () => undefined),
}));

const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');

const POST_LOGOUT_URI = 'https://rp.example/signed-out';
const SESSION = 'op-session-token';
const KID = 'kid-1';
const SECRET = 'client-secret';

interface TokenRow { userId: string; oidcClientId: string; familyId?: string; revokedAt: Date | null }

const client = {
  id: 'client_db_1',
  clientId: 'qrauth_oidc_test',
  clientSecretHash: sha256(SECRET),
  tier: 'CUSTOMER',
  redirectUris: ['https://rp.example/callback'],
  postLogoutRedirectUris: [POST_LOGOUT_URI],
  sectorIdentifierUri: null,
  sectorHost: 'rp.example',
  allowedScopes: ['openid'],
};
const otherClient = { ...client, id: 'client_db_2', clientId: 'qrauth_oidc_other', clientSecretHash: sha256('other-secret') };

// Keyed by hash, like the unique indexes the real lookups use.
let sessions = new Map<string, { userId: string; createdAt: Date; expiresAt: Date; revokedAt: Date | null }>();
let refreshTokens = new Map<string, TokenRow>();
let accessTokens = new Map<string, TokenRow>();
let publicKeyPem = '';
let privateKey: CryptoKey;
let issuer = '';
let hintSub = '';

const prisma: Record<string, any> = {
  oidcClient: {
    findUnique: async ({ where }: any) => [client, otherClient].find((c) => c.clientId === where.clientId) ?? null,
  },
  signingKey: {
    findFirst: async ({ where }: any) =>
      where.AND[1].keyId === KID ? { publicKey: publicKeyPem, algorithm: 'ES256' } : null,
  },
  oidcSession: {
    findUnique: async ({ where }: any) => sessions.get(where.sessionTokenHash) ?? null,
    updateMany: async ({ where, data }: any) => {
      const row = sessions.get(where.sessionTokenHash);
      if (!row || row.revokedAt !== null) return { count: 0 };
      row.revokedAt = data.revokedAt;
      return { count: 1 };
    },
  },
  oidcRefreshToken: {
    findUnique: async ({ where }: any) => refreshTokens.get(where.tokenHash) ?? null,
    updateMany: async ({ where, data }: any) => {
      const hit = [...refreshTokens.values()].filter((t) => t.familyId === where.familyId && t.revokedAt === null);
      hit.forEach((t) => { t.revokedAt = data.revokedAt; });
      return { count: hit.length };
    },
  },
  oidcAccessToken: {
    findUnique: async ({ where }: any) => accessTokens.get(where.tokenHash) ?? null,
    update: async ({ where, data }: any) => Object.assign(accessTokens.get(where.tokenHash)!, data),
    updateMany: async ({ where, data }: any) => {
      const hit = [...accessTokens.values()].filter(
        (t) => t.userId === where.userId && t.oidcClientId === where.oidcClientId && t.revokedAt === null,
      );
      hit.forEach((t) => { t.revokedAt = data.revokedAt; });
      return { count: hit.length };
    },
  },
};

let app: FastifyInstance;

async function idToken(overrides: { sub?: string; aud?: string; iss?: string; kid?: string; expired?: boolean } = {}) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({})
    .setProtectedHeader({ alg: 'ES256', kid: overrides.kid ?? KID })
    .setIssuer(overrides.iss ?? issuer)
    .setAudience(overrides.aud ?? client.clientId)
    .setSubject(overrides.sub ?? hintSub)
    .setIssuedAt(now - 7200)
    .setExpirationTime(overrides.expired ? now - 3600 : now + 3600)
    .sign(privateKey);
}

const logout = (query: Record<string, string>, withSession = true) =>
  app.inject({
    method: 'GET',
    url: `/logout?${new URLSearchParams(query).toString()}`,
    cookies: withSession ? { qrauth_op_session: SESSION } : {},
  });

const sessionRow = () => sessions.get(sha256(SESSION))!;
const clearedCookie = (res: Awaited<ReturnType<typeof logout>>) =>
  res.cookies.find((c) => c.name === 'qrauth_op_session');

const revoke = (token: string, auth: { id: string; secret: string } = { id: client.clientId, secret: SECRET }) =>
  app.inject({
    method: 'POST',
    url: '/revoke',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams({ token, client_id: auth.id, client_secret: auth.secret }).toString(),
  });

beforeAll(async () => {
  const pair = await generateKeyPair('ES256', { extractable: true });
  privateKey = pair.privateKey as CryptoKey;
  publicKeyPem = await exportSPKI(pair.publicKey as CryptoKey);

  const { config } = await import('../../lib/config.js');
  const { computeSubForClient } = await import('../../lib/oidc-sub.js');
  issuer = config.oidc.issuer;
  hintSub = computeSubForClient({ userId: 'user_1', client: client as never, pairwiseSecret: config.oidc.pairwiseSecret });

  app = Fastify({ logger: false });
  await app.register((await import('@fastify/cookie')).default);
  const { parseFormBody } = await import('../../lib/form-body.js');
  app.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string' }, (_req, body, done) => {
    done(null, parseFormBody(body as string));
  });
  app.decorate('prisma', prisma as never);
  app.decorate('signingService', {} as never);
  const { default: oidcFlowRoutes } = await import('../oidc-flow.js');
  await app.register(oidcFlowRoutes);
  await app.ready();
});

afterAll(async () => {
  await app?.close();
});

beforeEach(() => {
  sessions = new Map([[sha256(SESSION), {
    userId: 'user_1',
    createdAt: new Date(),
    expiresAt: new Date(Date.now() + 3_600_000),
    revokedAt: null,
  }]]);
  refreshTokens = new Map([
    [sha256('rt-current'), { userId: 'user_1', oidcClientId: client.id, familyId: 'fam_1', revokedAt: null }],
    [sha256('rt-older'), { userId: 'user_1', oidcClientId: client.id, familyId: 'fam_1', revokedAt: null }],
    [sha256('rt-other-client'), { userId: 'user_1', oidcClientId: otherClient.id, familyId: 'fam_2', revokedAt: null }],
  ]);
  accessTokens = new Map([
    [sha256('at-1'), { userId: 'user_1', oidcClientId: client.id, revokedAt: null }],
    [sha256('at-2'), { userId: 'user_1', oidcClientId: client.id, revokedAt: null }],
    [sha256('at-other-client'), { userId: 'user_1', oidcClientId: otherClient.id, revokedAt: null }],
  ]);
});

describe('GET /logout with a valid id_token_hint', () => {
  it('ends the session and redirects to the registered post-logout URI with state', async () => {
    const res = await logout({ id_token_hint: await idToken(), post_logout_redirect_uri: POST_LOGOUT_URI, state: 's1' });

    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toBe(`${POST_LOGOUT_URI}?state=s1`);
    expect(sessionRow().revokedAt).toBeInstanceOf(Date);
    expect(clearedCookie(res)?.value).toBe('');
  });

  it('accepts an expired ID token as the hint', async () => {
    const res = await logout({ id_token_hint: await idToken({ expired: true }) });

    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('You are signed out');
    expect(sessionRow().revokedAt).toBeInstanceOf(Date);
  });

  it('never redirects to a URI that is not registered exactly', async () => {
    for (const uri of ['https://evil.example/', `${POST_LOGOUT_URI}/extra`, `${POST_LOGOUT_URI}?x=1`]) {
      const res = await logout({ id_token_hint: await idToken(), post_logout_redirect_uri: uri });
      expect(res.statusCode).toBe(200);
      expect(res.headers.location).toBeUndefined();
    }
  });
});

describe('GET /logout that does not prove which session it means', () => {
  it('asks first when there is no hint, and leaves the session alone', async () => {
    const res = await logout({ client_id: client.clientId, post_logout_redirect_uri: POST_LOGOUT_URI });

    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('Sign out of QRAuth?');
    expect(res.body).not.toContain('<script');
    expect(sessionRow().revokedAt).toBeNull();
    expect(String(res.headers['x-frame-options'])).toBe('DENY');
  });

  it("asks first when the hint is another user's token", async () => {
    const res = await logout({ id_token_hint: await idToken({ sub: 'someone-else' }) });

    expect(res.body).toContain('Sign out of QRAuth?');
    expect(sessionRow().revokedAt).toBeNull();
  });

  it('treats a hint with a bad issuer, unknown key or broken signature as no hint', async () => {
    const good = await idToken();
    const hints = [
      await idToken({ iss: 'https://evil.example' }),
      await idToken({ kid: 'unknown-kid' }),
      `${good.slice(0, -4)}AAAA`,
      'not-a-jwt',
    ];
    for (const hint of hints) {
      const res = await logout({ id_token_hint: hint, post_logout_redirect_uri: POST_LOGOUT_URI });
      expect(res.body).toContain('Sign out of QRAuth?');
      expect(sessionRow().revokedAt).toBeNull();
    }
  });

  it('does not trust a client_id that disagrees with the hint', async () => {
    const res = await logout({
      id_token_hint: await idToken(),
      client_id: otherClient.clientId,
      post_logout_redirect_uri: POST_LOGOUT_URI,
    });

    expect(res.headers.location).toBeUndefined();
    expect(sessionRow().revokedAt).toBeNull();
  });
});

describe('POST /logout', () => {
  const post = (fields: Record<string, string>, withSession = true) =>
    app.inject({
      method: 'POST',
      url: '/logout',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams(fields).toString(),
      cookies: withSession ? { qrauth_op_session: SESSION } : {},
    });

  it('the confirmation form ends the session and returns to the registered URI without a redirect', async () => {
    const res = await post({ confirm: 'yes', client_id: client.clientId, post_logout_redirect_uri: POST_LOGOUT_URI, state: 's2' });

    expect(res.statusCode).toBe(200);
    expect(res.headers.location).toBeUndefined();
    expect(res.body).toContain(`content="0;url=${POST_LOGOUT_URI}?state=s2"`);
    expect(sessionRow().revokedAt).toBeInstanceOf(Date);
  });

  it('a confirmation POST without the session cookie (cross-site) ends nothing', async () => {
    const res = await post({ confirm: 'yes' }, false);

    expect(res.statusCode).toBe(200);
    expect(sessionRow().revokedAt).toBeNull();
  });

  it("a relying party's POST is turned into the equivalent GET", async () => {
    const hint = await idToken();
    const res = await post({ id_token_hint: hint, state: 's3' }, false);

    expect(res.statusCode).toBe(303);
    const location = new URL(String(res.headers.location), 'https://id.example');
    expect(location.pathname).toBe('/logout');
    expect(location.searchParams.get('id_token_hint')).toBe(hint);
    expect(location.searchParams.get('confirm')).toBeNull();
  });
});

describe('GET /logout with no session', () => {
  it('still honours a registered post-logout URI', async () => {
    const res = await logout({ client_id: client.clientId, post_logout_redirect_uri: POST_LOGOUT_URI }, false);

    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toBe(POST_LOGOUT_URI);
  });
});

describe('POST /revoke (RFC 7009)', () => {
  it('revoking a refresh token ends its family and the access tokens of that client and user', async () => {
    const res = await revoke('rt-current');

    expect(res.statusCode).toBe(200);
    expect(res.body).toBe('');
    expect(refreshTokens.get(sha256('rt-current'))!.revokedAt).toBeInstanceOf(Date);
    expect(refreshTokens.get(sha256('rt-older'))!.revokedAt).toBeInstanceOf(Date);
    expect(refreshTokens.get(sha256('rt-other-client'))!.revokedAt).toBeNull();
    expect(accessTokens.get(sha256('at-1'))!.revokedAt).toBeInstanceOf(Date);
    expect(accessTokens.get(sha256('at-other-client'))!.revokedAt).toBeNull();
  });

  it('revoking an access token revokes only that token', async () => {
    const res = await revoke('at-1');

    expect(res.statusCode).toBe(200);
    expect(accessTokens.get(sha256('at-1'))!.revokedAt).toBeInstanceOf(Date);
    expect(accessTokens.get(sha256('at-2'))!.revokedAt).toBeNull();
    expect(refreshTokens.get(sha256('rt-current'))!.revokedAt).toBeNull();
  });

  it("answers 200 for another client's token and revokes nothing", async () => {
    const refresh = await revoke('rt-other-client');
    const access = await revoke('at-other-client');

    expect(refresh.statusCode).toBe(200);
    expect(access.statusCode).toBe(200);
    expect(refreshTokens.get(sha256('rt-other-client'))!.revokedAt).toBeNull();
    expect(accessTokens.get(sha256('at-other-client'))!.revokedAt).toBeNull();
  });

  it('answers 200 for an unknown token', async () => {
    expect((await revoke('never-issued')).statusCode).toBe(200);
  });

  it('requires client authentication', async () => {
    const wrongSecret = await revoke('rt-current', { id: client.clientId, secret: 'wrong' });
    const unknownClient = await revoke('rt-current', { id: 'nope', secret: 'x' });

    expect(wrongSecret.statusCode).toBe(401);
    expect(wrongSecret.json().error).toBe('invalid_client');
    expect(unknownClient.statusCode).toBe(401);
    expect(refreshTokens.get(sha256('rt-current'))!.revokedAt).toBeNull();
  });

  it('requires the token parameter', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/revoke',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: new URLSearchParams({ client_id: client.clientId, client_secret: SECRET }).toString(),
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_request');
  });
});

describe('POST /token with malformed input (FINDING-021)', () => {
  const token = (payload: string, headers: Record<string, string> = {}) =>
    app.inject({
      method: 'POST',
      url: '/token',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
      payload,
    });

  it('answers a malformed Basic header with 401 invalid_client', async () => {
    const res = await token('grant_type=authorization_code&code=x&redirect_uri=https%3A%2F%2Frp.example%2Fcb', {
      authorization: `Basic ${Buffer.from('%E0%A4%A:secret').toString('base64')}`,
    });

    expect(res.statusCode).toBe(401);
    expect(res.json().error).toBe('invalid_client');
  });

  it.each(['grant_type', 'code', 'client_id', 'refresh_token'])('answers a repeated %s with invalid_request', async (name) => {
    const res = await token(`grant_type=authorization_code&code=x&${name}=a&${name}=b`);

    expect(res.statusCode).toBe(400);
    expect(res.json()).toMatchObject({ error: 'invalid_request', error_description: `${name} must not be repeated` });
  });

  it('answers a JSON body with non-string values with invalid_request', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/token',
      headers: { 'content-type': 'application/json' },
      payload: JSON.stringify({ grant_type: 'authorization_code', code: { $ne: null }, client_id: 'x' }),
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_request');
  });
});
