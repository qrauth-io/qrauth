import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance, type LightMyRequestResponse } from 'fastify';
import { createHash } from 'node:crypto';

/**
 * OAuth state is bound to the browser that started sign-in (login CSRF) and
 * the code exchange uses PKCE. The Redis state store is an in-memory map, so
 * start -> callback runs end to end; the provider exchange is stubbed.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);
process.env.WEBAUTHN_ORIGIN = 'https://qrauth.test';
process.env.GOOGLE_CLIENT_ID = 'google-client';
process.env.GOOGLE_CLIENT_SECRET = 'google-secret';
process.env.GITHUB_CLIENT_ID = 'github-client';
process.env.GITHUB_CLIENT_SECRET = 'github-secret';
process.env.MICROSOFT_CLIENT_ID = 'microsoft-client';
process.env.MICROSOFT_CLIENT_SECRET = 'microsoft-secret';
process.env.APPLE_CLIENT_ID = 'apple-client';
process.env.APPLE_CLIENT_SECRET = 'apple-secret';

const store = new Map<string, unknown>();
vi.mock('../../lib/cache.js', () => ({
  redis: {},
  cacheGet: vi.fn(async (key: string) => store.get(key) ?? null),
  cacheSet: vi.fn(async (key: string, value: unknown) => {
    store.set(key, value);
  }),
  cacheDel: vi.fn(async (key: string) => {
    store.delete(key);
  }),
  disconnectCache: vi.fn(async () => undefined),
}));

// Reaching the exchange means the state was accepted; it then fails, so no database is needed.
const exchangeCalls: Array<{ provider: string; codeVerifier: string | undefined }> = [];
vi.mock('../../lib/oauth.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../lib/oauth.js')>()),
  exchangeCodeForUser: async (provider: string, _code: string, _callbackUrl: string, codeVerifier?: string) => {
    exchangeCalls.push({ provider, codeVerifier });
    throw new Error('stubbed exchange');
  },
}));

const { OAUTH_SIGN_IN_PATH } = await import('../auth.js');
const { OAUTH_STATE_COOKIE } = await import('../../lib/oauth-state-binding.js');

const BASE = 'https://qrauth.test';
const EXPIRED = `${BASE}${OAUTH_SIGN_IN_PATH}?oauth_error=expired`;
const ACCEPTED = `${BASE}${OAUTH_SIGN_IN_PATH}?oauth_error=failed`; // past the state checks, stubbed exchange failed
let app: FastifyInstance;

async function buildApp(logStream?: { write: (line: string) => void }): Promise<FastifyInstance> {
  const instance = Fastify({ logger: logStream ? { level: 'info', stream: logStream } : false });
  await instance.register((await import('@fastify/cookie')).default);
  await instance.register((await import('@fastify/jwt')).default, { secret: 'b'.repeat(32) });
  instance.decorate('prisma', {} as never);
  instance.decorate('signingService', { createKeyPair: async () => ({}) } as never);
  instance.decorate('authenticate', async () => undefined);
  const { default: authRoutes } = await import('../auth.js');
  await instance.register(authRoutes, { prefix: '/api/v1/auth' });
  await instance.ready();
  return instance;
}

interface Started {
  state: string;
  cookie: LightMyRequestResponse['cookies'][number];
  authorizeParams: URLSearchParams;
}

async function start(provider: string, on: FastifyInstance = app): Promise<Started> {
  const res = await on.inject({ method: 'GET', url: `/api/v1/auth/oauth/${provider}` });
  const authorizeParams = new URL(String(res.headers.location)).searchParams;
  const cookie = res.cookies.find((c) => c.name === OAUTH_STATE_COOKIE);
  if (!cookie) throw new Error('start route set no state cookie');
  return { state: String(authorizeParams.get('state')), cookie, authorizeParams };
}

function callback(provider: string, state: string, cookieValue?: string, on: FastifyInstance = app) {
  return on.inject({
    method: 'GET',
    url: `/api/v1/auth/oauth/${provider}/callback?code=c&state=${state}`,
    ...(cookieValue ? { cookies: { [OAUTH_STATE_COOKIE]: cookieValue } } : {}),
  });
}

function storedVerifier(state: string): unknown {
  return (store.get(`oauth_state:${state}`) as { codeVerifier?: unknown } | undefined)?.codeVerifier;
}

beforeAll(async () => {
  app = await buildApp();
});

afterAll(async () => {
  await app?.close();
});

beforeEach(() => {
  store.clear();
  exchangeCalls.length = 0;
});

describe('start route binds the state to the browser', () => {
  it.each(['google', 'github', 'microsoft'])('%s: sets a __Host- cookie with SameSite=Lax holding SHA-256(state)', async (provider) => {
    const { state, cookie } = await start(provider);

    expect(cookie.value).toBe(createHash('sha256').update(state).digest('base64url'));
    expect(cookie).toMatchObject({ path: '/', secure: true, httpOnly: true, sameSite: 'Lax', maxAge: 300 });
    expect(cookie.domain).toBeUndefined();
  });

  it('apple (form_post): the cookie is SameSite=None so the cross-site POST carries it', async () => {
    const { cookie } = await start('apple');

    expect(cookie).toMatchObject({ path: '/', secure: true, httpOnly: true, sameSite: 'None', maxAge: 300 });
  });

  it('the PKCE verifier stays server-side; only its S256 challenge goes to the provider', async () => {
    const { state, cookie, authorizeParams } = await start('google');
    const verifier = String(storedVerifier(state));

    expect(verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(authorizeParams.get('code_challenge')).toBe(createHash('sha256').update(verifier).digest('base64url'));
    expect(authorizeParams.get('code_challenge_method')).toBe('S256');
    expect(cookie.value).not.toContain(verifier);
    expect(authorizeParams.toString()).not.toContain(verifier);
  });
});

describe('callback requires the browser that started the flow', () => {
  it.each(['google', 'github', 'microsoft'])('%s: matching cookie is accepted and the exchange gets the stored verifier', async (provider) => {
    const { state, cookie } = await start(provider);
    const verifier = storedVerifier(state);

    const res = await callback(provider, state, cookie.value);

    expect(res.headers.location).toBe(ACCEPTED);
    expect(exchangeCalls).toEqual([{ provider, codeVerifier: verifier }]);
    expect(store.has(`oauth_state:${state}`)).toBe(false);
    expect(res.cookies.find((c) => c.name === OAUTH_STATE_COOKIE)).toMatchObject({ value: '', path: '/', secure: true });
  });

  it('valid Redis state but NO cookie is refused (the login CSRF case)', async () => {
    const { state } = await start('google');

    const res = await callback('google', state);

    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe(EXPIRED);
    expect(exchangeCalls).toHaveLength(0);
  });

  it('a cookie for a different state is refused', async () => {
    const victim = await start('google');
    const attacker = await start('google');

    const res = await callback('google', attacker.state, victim.cookie.value);

    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe(EXPIRED);
    expect(exchangeCalls).toHaveLength(0);
  });

  it('replaying a consumed state is refused, even with its cookie', async () => {
    const { state, cookie } = await start('google');
    await callback('google', state, cookie.value);

    const replay = await callback('google', state, cookie.value);

    expect(replay.statusCode).toBe(303);
    expect(replay.headers.location).toBe(EXPIRED);
    expect(exchangeCalls).toHaveLength(1);
  });

  it.each(['google', 'github', 'microsoft'])('%s: a state record without a codeVerifier is refused before the exchange', async (provider) => {
    const { state, cookie } = await start(provider);
    store.set(`oauth_state:${state}`, { valid: true });

    const res = await callback(provider, state, cookie.value);

    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe(EXPIRED);
    expect(exchangeCalls).toHaveLength(0);
  });

  it('Apple form_post callback with its SameSite=None cookie is accepted, with no code_verifier', async () => {
    const { state, cookie } = await start('apple');

    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/auth/oauth/apple/callback',
      payload: { code: 'c', state },
      cookies: { [OAUTH_STATE_COOKIE]: cookie.value },
    });

    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe(ACCEPTED);
    expect(exchangeCalls).toEqual([{ provider: 'apple', codeVerifier: undefined }]);
  });
});

describe('Microsoft bare-visit restart goes through the start route, so it gets the cookie', () => {
  it.each(['GET', 'HEAD'] as const)('%s bare callback -> start route -> state cookie set', async (method) => {
    const bare = await app.inject({ method, url: '/api/v1/auth/oauth/microsoft/callback' });
    expect(bare.statusCode).toBe(302);
    expect(bare.headers.location).toBe(`${BASE}/api/v1/auth/oauth/microsoft`);

    const res = await app.inject({ method: 'GET', url: new URL(String(bare.headers.location)).pathname });
    const cookie = res.cookies.find((c) => c.name === OAUTH_STATE_COOKIE);
    const state = String(new URL(String(res.headers.location)).searchParams.get('state'));

    expect(cookie).toMatchObject({ path: '/', secure: true, httpOnly: true, sameSite: 'Lax', maxAge: 300 });
    expect(cookie?.value).toBe(createHash('sha256').update(state).digest('base64url'));
  });
});

describe('refusal logging', () => {
  const STANDARD_KEYS = ['level', 'time', 'pid', 'hostname', 'reqId', 'msg'];

  /** Runs a refused callback on a logging app; returns the state-cookie events and the values that must not leak. */
  async function refusedCallbackEvents(withCookie: 'none' | 'other-flow') {
    const lines: string[] = [];
    const logged = await buildApp({ write: (line) => { lines.push(line); } });
    const victim = await start('microsoft', logged);
    const attacker = await start('microsoft', logged);

    const res = await callback('microsoft', attacker.state, withCookie === 'none' ? undefined : victim.cookie.value, logged);
    await logged.close();

    const events = lines.map((l) => JSON.parse(l)).filter((l) => String(l.event ?? '').startsWith('oauth.state_cookie_'));
    return { res, events, secrets: [attacker.state, victim.state, victim.cookie.value, attacker.cookie.value] };
  }

  it('no cookie: logs oauth.state_cookie_missing with the provider name only', async () => {
    const { res, events, secrets } = await refusedCallbackEvents('none');

    expect(res.headers.location).toBe(EXPIRED);
    expect(events.map((e) => e.event)).toEqual(['oauth.state_cookie_missing']);
    expect(events[0].provider).toBe('microsoft');
    expect(Object.keys(events[0]).filter((k) => !STANDARD_KEYS.includes(k))).toEqual(['event', 'provider']);
    for (const secret of secrets) expect(JSON.stringify(events[0])).not.toContain(secret);
  });

  it('cookie for another flow: logs oauth.state_cookie_mismatch with the provider name only', async () => {
    const { res, events, secrets } = await refusedCallbackEvents('other-flow');

    expect(res.headers.location).toBe(EXPIRED);
    expect(events.map((e) => e.event)).toEqual(['oauth.state_cookie_mismatch']);
    expect(events[0].provider).toBe('microsoft');
    expect(Object.keys(events[0]).filter((k) => !STANDARD_KEYS.includes(k))).toEqual(['event', 'provider']);
    // (Request URLs are redacted by the server.ts serializers, not under test here.)
    for (const secret of secrets) expect(JSON.stringify(events[0])).not.toContain(secret);
  });
});
