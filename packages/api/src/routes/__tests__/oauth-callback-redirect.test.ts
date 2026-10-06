import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * OAuth callback failures redirect the browser back to where sign-in started
 * (with ?oauth_error=<code>) instead of returning a JSON body. No database:
 * every case here fails before the account lookup.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);
process.env.WEBAUTHN_ORIGIN = 'https://qrauth.test';

let stateIsValid = true;
vi.mock('../../lib/cache.js', () => ({
  redis: {},
  cacheGet: vi.fn(async () => (stateIsValid ? { valid: true } : null)),
  cacheSet: vi.fn(async () => undefined),
  cacheDel: vi.fn(async () => undefined),
  disconnectCache: vi.fn(async () => undefined),
}));

// null = the provider exchange fails; otherwise the identity it returns.
let providerIdentity: Record<string, unknown> | null = null;
vi.mock('../../lib/oauth.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../lib/oauth.js')>()),
  exchangeCodeForUser: async () => {
    if (!providerIdentity) throw new Error('token verification failed: secret-detail-xyz');
    return providerIdentity;
  },
}));

// Every identity that gets this far is refused as unverified (no database here).
vi.mock('../../services/oauth-account-link.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../services/oauth-account-link.js')>()),
  resolveOAuthAccount: async () => ({ kind: 'refuse', reason: 'unverified_email_new_account' }),
}));

const { oauthFailureUrl, OAUTH_SIGN_IN_PATH } = await import('../auth.js');

const BASE = 'https://qrauth.test';
const SESSION_TOKEN = `as_${'A'.repeat(32)}`;
let app: FastifyInstance;

function state(payload: Record<string, string> = {}): string {
  return Buffer.from(JSON.stringify({ csrf: 'x', returnTo: '', authSessionToken: '', ...payload })).toString('base64url');
}

function get(query: string) {
  return app.inject({ method: 'GET', url: `/api/v1/auth/oauth/microsoft/callback?${query}` });
}

beforeAll(async () => {
  app = Fastify({ logger: false });
  await app.register((await import('@fastify/cookie')).default);
  await app.register((await import('@fastify/jwt')).default, { secret: 'b'.repeat(32) });
  app.decorate('prisma', {} as never);
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
  stateIsValid = true;
  providerIdentity = null;
});

describe('oauthFailureUrl', () => {
  it('points at the web sign-in page by default', () => {
    expect(oauthFailureUrl(BASE, 'failed')).toBe(`${BASE}${OAUTH_SIGN_IN_PATH}?oauth_error=failed`);
  });

  it('points at the hosted approval page for a well-formed auth session token', () => {
    expect(oauthFailureUrl(BASE, 'cancelled', SESSION_TOKEN)).toBe(`${BASE}/a/${SESSION_TOKEN}?oauth_error=cancelled`);
  });

  it.each(['../evil', 'as_short', `as_${'A'.repeat(31)}/x`, `https://evil.example/${SESSION_TOKEN}`])(
    'falls back to the sign-in page for a malformed token (%s)',
    (token) => {
      expect(oauthFailureUrl(BASE, 'failed', token)).toBe(`${BASE}${OAUTH_SIGN_IN_PATH}?oauth_error=failed`);
    },
  );
});

describe('Microsoft callback opened directly (no code, state or error) restarts sign-in', () => {
  const START = `${BASE}/api/v1/auth/oauth/microsoft`;

  it('a bare GET is sent to the start of a fresh Microsoft sign-in', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/v1/auth/oauth/microsoft/callback' });

    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toBe(START);
    expect(res.headers['set-cookie']).toBeUndefined();
  });

  it('unrelated query parameters still count as a bare visit', async () => {
    const res = await get('utm_source=myapps');

    expect(res.statusCode).toBe(302);
    expect(res.headers.location).toBe(START);
  });

  it('logs the restart with no personal data', async () => {
    const lines: string[] = [];
    const logged = Fastify({ logger: { level: 'info', stream: { write: (line: string) => { lines.push(line); } } } });
    await logged.register((await import('@fastify/cookie')).default);
    await logged.register((await import('@fastify/jwt')).default, { secret: 'b'.repeat(32) });
    logged.decorate('prisma', {} as never);
    logged.decorate('signingService', { createKeyPair: async () => ({}) } as never);
    logged.decorate('authenticate', async () => undefined);
    const { default: authRoutes } = await import('../auth.js');
    await logged.register(authRoutes, { prefix: '/api/v1/auth' });

    await logged.inject({ method: 'GET', url: '/api/v1/auth/oauth/microsoft/callback' });
    await logged.close();

    const event = lines.map((l) => JSON.parse(l)).find((l) => l.event === 'oauth.microsoft.callback_bare_restart');
    expect(event).toBeDefined();
    expect(Object.keys(event).filter((k) => !['level', 'time', 'pid', 'hostname', 'reqId', 'msg'].includes(k))).toEqual(['event']);
  });

  it('code without state is still refused as expired, never restarted', async () => {
    const res = await get('code=c');

    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe(`${BASE}${OAUTH_SIGN_IN_PATH}?oauth_error=expired`);
  });

  it('an empty code or state parameter is not a bare visit', async () => {
    for (const query of ['code=', 'state=', 'error=']) {
      const res = await get(query);

      expect(res.statusCode).toBe(303);
      expect(res.headers.location).toBe(`${BASE}${OAUTH_SIGN_IN_PATH}?oauth_error=expired`);
    }
  });

  it('an invalid state is still refused as expired', async () => {
    stateIsValid = false;

    for (const query of [`code=c&state=${state()}`, `state=${state()}`, 'state=not-a-real-state']) {
      const res = await get(query);

      expect(res.statusCode).toBe(303);
      expect(res.headers.location).toBe(`${BASE}${OAUTH_SIGN_IN_PATH}?oauth_error=expired`);
    }
  });

  it('error=access_denied is handled as before', async () => {
    const withState = await get(`error=access_denied&state=${state()}`);
    expect(withState.statusCode).toBe(303);
    expect(withState.headers.location).toBe(`${BASE}${OAUTH_SIGN_IN_PATH}?oauth_error=cancelled`);

    const withoutState = await get('error=access_denied');
    expect(withoutState.statusCode).toBe(303);
    expect(withoutState.headers.location).toBe(`${BASE}${OAUTH_SIGN_IN_PATH}?oauth_error=expired`);
  });

  it('only Microsoft restarts: a bare callback for another provider is refused as before', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/v1/auth/oauth/google/callback' });

    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe(`${BASE}${OAUTH_SIGN_IN_PATH}?oauth_error=expired`);
  });

  it('a bare POST is refused as before', async () => {
    const res = await app.inject({ method: 'POST', url: '/api/v1/auth/oauth/microsoft/callback' });

    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe(`${BASE}${OAUTH_SIGN_IN_PATH}?oauth_error=expired`);
  });
});

describe('OAuth callback failures redirect instead of returning JSON', () => {
  it('sends a callback without state back to sign-in as expired', async () => {
    const res = await get('code=c');

    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe(`${BASE}${OAUTH_SIGN_IN_PATH}?oauth_error=expired`);
  });

  it('sends an unknown or used state back to sign-in as expired', async () => {
    stateIsValid = false;

    const res = await get(`code=c&state=${state()}`);

    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe(`${BASE}${OAUTH_SIGN_IN_PATH}?oauth_error=expired`);
  });

  it('maps a provider access_denied (user cancelled) to cancelled', async () => {
    const res = await get(`error=access_denied&state=${state()}`);

    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe(`${BASE}${OAUTH_SIGN_IN_PATH}?oauth_error=cancelled`);
  });

  it('maps any other provider error without a code to failed', async () => {
    const res = await get(`error=server_error&state=${state()}`);

    expect(res.headers.location).toBe(`${BASE}${OAUTH_SIGN_IN_PATH}?oauth_error=failed`);
  });

  it('sends a failed exchange back to sign-in as failed, with no error detail in the response', async () => {
    const res = await get(`code=c&state=${state()}`);

    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe(`${BASE}${OAUTH_SIGN_IN_PATH}?oauth_error=failed`);
    expect(res.body).not.toContain('secret-detail-xyz');
    expect(res.headers['content-type'] ?? '').not.toContain('application/json');
  });

  it('returns a failure from the hosted approval flow to that approval page', async () => {
    const res = await get(`code=c&state=${state({ authSessionToken: SESSION_TOKEN })}`);

    expect(res.headers.location).toBe(`${BASE}/a/${SESSION_TOKEN}?oauth_error=failed`);
  });

  it('answers Apple form_post (POST) failures with 303 so the browser follows with GET', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/oauth/apple/callback',
      payload: { code: 'c', state: state() },
    });

    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe(`${BASE}${OAUTH_SIGN_IN_PATH}?oauth_error=failed`);
  });

  it('tells a refused personal Microsoft account so, instead of the generic message', async () => {
    providerIdentity = { providerId: 'oid-1', email: 'jane@outlook.example', emailVerified: false, name: 'Jane', personalMicrosoftAccount: true };

    const res = await get(`code=c&state=${state()}`);

    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe(`${BASE}${OAUTH_SIGN_IN_PATH}?oauth_error=microsoft_personal`);
  });

  it('keeps the generic failure for a refused work or school account', async () => {
    providerIdentity = { providerId: 'oid-2', email: 'jane@contoso.example', emailVerified: false, name: 'Jane', personalMicrosoftAccount: false };

    const res = await get(`code=c&state=${state({ authSessionToken: SESSION_TOKEN })}`);

    expect(res.headers.location).toBe(`${BASE}/a/${SESSION_TOKEN}?oauth_error=failed`);
  });
});
