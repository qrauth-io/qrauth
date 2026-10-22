import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHash } from 'node:crypto';

/**
 * "Sign in with QRAuth" always starts a QR scan. An existing OP session is
 * reused only when the relying party asks for that explicitly (`prompt=none`,
 * or a `max_age` the session satisfies); the one other use is the single
 * return to /authorize right after the scan that created the session.
 * Real /authorize and /login routes; Prisma, Redis and the auth-session
 * service are in-memory stand-ins.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

const cache = new Map<string, unknown>();
vi.mock('../../lib/cache.js', () => ({
  redis: {},
  cacheGet: vi.fn(async (key: string) => cache.get(key) ?? null),
  cacheSet: vi.fn(async (key: string, value: unknown) => { cache.set(key, value); }),
  cacheDel: vi.fn(async (key: string) => { cache.delete(key); }),
  cacheTake: vi.fn(async (key: string) => {
    const value = cache.get(key) ?? null;
    cache.delete(key);
    return value;
  }),
  disconnectCache: vi.fn(async () => undefined),
}));

vi.mock('../../lib/oidc-op-app.js', () => ({ getOpAppId: async () => 'op_app' }));

let authSession: { id: string; status: string; userId: string | null };
vi.mock('../../services/auth-session.js', () => ({
  AuthSessionService: class {
    async createSession() {
      return { id: authSession.id, token: 'as_token' };
    }
    async getSession() {
      return authSession;
    }
  },
}));

const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');

const REDIRECT_URI = 'https://rp.example/callback';
const OTHER_REDIRECT_URI = 'https://other.example/callback';
const USER_ID = 'user_1';
const SESSION_COOKIE = 'qrauth_op_session';

interface SessionRow { userId: string; createdAt: Date; expiresAt: Date; revokedAt: Date | null }
let sessions = new Map<string, SessionRow>();
let authCodes: Array<Record<string, unknown>> = [];

const clientRow = (clientId: string, name: string, redirectUri: string) => ({
  id: `db_${clientId}`,
  clientId,
  name,
  tier: 'FIRST_PARTY',
  clientSecretHash: 'confidential',
  redirectUris: [redirectUri],
  allowedScopes: ['openid', 'email'],
  consentRequired: true,
  organizationId: 'org_client',
  organization: { name: 'Example Ltd' },
});
const clients = [
  clientRow('shop', 'Example <Shop>', REDIRECT_URI),
  clientRow('other', 'Other App', OTHER_REDIRECT_URI),
  // Self-serve client: the user has to consent before it gets a code.
  { ...clientRow('selfserve', 'Self Serve', REDIRECT_URI), tier: 'CUSTOMER' },
];

const prisma = {
  oidcClient: {
    findUnique: async ({ where }: { where: { clientId: string } }) =>
      clients.find((c) => c.clientId === where.clientId) ?? null,
  },
  oidcSession: {
    create: async ({ data }: { data: { sessionTokenHash: string; userId: string; expiresAt: Date } }) => {
      sessions.set(data.sessionTokenHash, {
        userId: data.userId,
        createdAt: new Date(),
        expiresAt: data.expiresAt,
        revokedAt: null,
      });
      return data;
    },
    findUnique: async ({ where }: { where: { sessionTokenHash: string } }) =>
      sessions.get(where.sessionTokenHash) ?? null,
  },
  oidcConsent: {
    findUnique: async () => null,
  },
  user: {
    findUnique: async () => ({ email: 'person@example.com' }),
  },
  oidcAuthCode: {
    create: async ({ data }: { data: Record<string, unknown> }) => {
      authCodes.push(data);
      return data;
    },
  },
};

let app: FastifyInstance;

type Injected = Awaited<ReturnType<FastifyInstance['inject']>>;

const authorizeUrl = (params: Record<string, string> = {}) =>
  `/authorize?${new URLSearchParams({
    response_type: 'code',
    client_id: 'shop',
    redirect_uri: REDIRECT_URI,
    scope: 'openid email',
    state: 'state-1',
    ...params,
  }).toString()}`;

const get = (url: string, cookies: Record<string, string> = {}) =>
  app.inject({ method: 'GET', url, headers: { accept: 'text/html' }, cookies });

const goesToLogin = (res: Injected) =>
  res.statusCode === 302 && String(res.headers.location).startsWith('/login?returnTo=');

function issuedCode(res: Injected): string | null {
  if (res.statusCode !== 302) return null;
  const location = String(res.headers.location);
  if (!location.startsWith(REDIRECT_URI) && !location.startsWith(OTHER_REDIRECT_URI)) return null;
  return new URL(location).searchParams.get('code');
}

/** A session that exists already, as if the person signed in a minute ago. */
function seedSession(token = 'older-session', ageSeconds = 60): string {
  sessions.set(sha256(token), {
    userId: USER_ID,
    createdAt: new Date(Date.now() - ageSeconds * 1000),
    expiresAt: new Date(Date.now() + 600_000),
    revokedAt: null,
  });
  return token;
}

/**
 * Walk the browser through the QR sign-in that `first` (an /authorize
 * response that redirected to /login) started: open /login, approve the scan,
 * poll. Returns the new session cookie and where the page then navigates.
 */
async function scanAndApprove(first: Injected): Promise<{ sessionToken: string; returnUrl: string; statusRes: Injected }> {
  const loginRes = await get(String(first.headers.location));
  const id = loginRes.body.match(/var id = "([A-Za-z0-9_-]+)"/)![1];
  const pre = loginRes.cookies.find((c) => c.name === 'qrauth_op_pre')!.value;
  authSession = { ...authSession, status: 'APPROVED', userId: USER_ID };
  const statusRes = await app.inject({ method: 'GET', url: `/login/status?id=${id}`, cookies: { qrauth_op_pre: pre } });
  const sessionToken = statusRes.cookies.find((c) => c.name === SESSION_COOKIE)!.value;
  return { sessionToken, returnUrl: statusRes.json().redirectUrl as string, statusRes };
}

beforeAll(async () => {
  app = Fastify({ logger: false });
  await app.register((await import('@fastify/cookie')).default);
  // The parser server.ts installs.
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
  cache.clear();
  sessions = new Map();
  authCodes = [];
  authSession = { id: 'auth_session_1', status: 'PENDING', userId: null };
});

describe('/authorize with an existing OP session', () => {
  it('starts a new QR sign-in for an ordinary request', async () => {
    const token = seedSession();

    const res = await get(authorizeUrl(), { [SESSION_COOKIE]: token });

    expect(goesToLogin(res)).toBe(true);
    expect(authCodes).toHaveLength(0);
  });

  it('starts a new QR sign-in for a POST request too', async () => {
    const token = seedSession();

    const res = await app.inject({
      method: 'POST',
      url: '/authorize',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: authorizeUrl().split('?')[1],
      cookies: { [SESSION_COOKIE]: token },
    });

    expect(goesToLogin(res)).toBe(true);
    expect(authCodes).toHaveLength(0);
  });

  it('prompt=none reuses the session silently', async () => {
    const token = seedSession();

    const res = await get(authorizeUrl({ prompt: 'none' }), { [SESSION_COOKIE]: token });

    expect(issuedCode(res)).toBeTruthy();
  });

  it('prompt=none without a session still returns login_required', async () => {
    const res = await get(authorizeUrl({ prompt: 'none' }));

    expect(new URL(String(res.headers.location)).searchParams.get('error')).toBe('login_required');
  });

  it('a max_age the session satisfies reuses the session', async () => {
    const token = seedSession('older-session', 60);

    const res = await get(authorizeUrl({ max_age: '10000' }), { [SESSION_COOKIE]: token });

    expect(issuedCode(res)).toBeTruthy();
    expect(authCodes[0].authTime).toEqual(sessions.get(sha256(token))!.createdAt);
  });

  it('a max_age the session is too old for starts a new QR sign-in', async () => {
    const token = seedSession('older-session', 60);

    const res = await get(authorizeUrl({ max_age: '1' }), { [SESSION_COOKIE]: token });

    expect(goesToLogin(res)).toBe(true);
  });

  it('a max_age that is not a number does not unlock the session', async () => {
    const token = seedSession();

    const res = await get(authorizeUrl({ max_age: 'abc' }), { [SESSION_COOKIE]: token });

    expect(goesToLogin(res)).toBe(true);
    expect(authCodes).toHaveLength(0);
  });

  it('max_age=0 starts a new QR sign-in', async () => {
    const token = seedSession('older-session', 1);

    const res = await get(authorizeUrl({ max_age: '0' }), { [SESSION_COOKIE]: token });

    expect(goesToLogin(res)).toBe(true);
  });

  it('a session older than 15 minutes is not used, whatever expiry it was stored with', async () => {
    // Sessions created before the lifetime was shortened carry a 24-hour expiry.
    const token = seedSession('old-long-session', 16 * 60);
    sessions.get(sha256(token))!.expiresAt = new Date(Date.now() + 23 * 3_600_000);

    const silent = await get(authorizeUrl({ prompt: 'none' }), { [SESSION_COOKIE]: token });
    const withMaxAge = await get(authorizeUrl({ max_age: '86400' }), { [SESSION_COOKIE]: token });

    expect(new URL(String(silent.headers.location)).searchParams.get('error')).toBe('login_required');
    expect(goesToLogin(withMaxAge)).toBe(true);
    expect(authCodes).toHaveLength(0);
  });

  it('prompt=login starts a new QR sign-in even with a max_age the session satisfies', async () => {
    const token = seedSession();

    const res = await get(authorizeUrl({ prompt: 'login', max_age: '10000' }), { [SESSION_COOKIE]: token });

    expect(goesToLogin(res)).toBe(true);
  });
});

describe('the return to /authorize after a QR sign-in', () => {
  it('issues the code for the request that started the sign-in', async () => {
    const first = await get(authorizeUrl());
    const { sessionToken, returnUrl } = await scanAndApprove(first);

    const res = await get(returnUrl, { [SESSION_COOKIE]: sessionToken });

    expect(issuedCode(res)).toBeTruthy();
    expect(new URL(String(res.headers.location)).searchParams.get('state')).toBe('state-1');
  });

  it('works once: the same request again starts a new QR sign-in', async () => {
    const first = await get(authorizeUrl());
    const { sessionToken, returnUrl } = await scanAndApprove(first);
    await get(returnUrl, { [SESSION_COOKIE]: sessionToken });

    const again = await get(returnUrl, { [SESSION_COOKIE]: sessionToken });

    expect(goesToLogin(again)).toBe(true);
    expect(authCodes).toHaveLength(1);
  });

  it('does not cover a request from another application', async () => {
    const first = await get(authorizeUrl());
    const { sessionToken } = await scanAndApprove(first);

    const res = await get(
      authorizeUrl({ client_id: 'other', redirect_uri: OTHER_REDIRECT_URI }),
      { [SESSION_COOKIE]: sessionToken },
    );

    expect(goesToLogin(res)).toBe(true);
    expect(authCodes).toHaveLength(0);
  });

  it('does not cover the same application asking for more', async () => {
    const first = await get(authorizeUrl({ scope: 'openid' }));
    const { sessionToken } = await scanAndApprove(first);

    const res = await get(authorizeUrl({ scope: 'openid email' }), { [SESSION_COOKIE]: sessionToken });

    expect(goesToLogin(res)).toBe(true);
    expect(authCodes).toHaveLength(0);
  });

  it('covers the same request sent with its parameters in another order', async () => {
    const first = await get(authorizeUrl());
    const { sessionToken } = await scanAndApprove(first);
    const reordered = `/authorize?${new URLSearchParams(
      [...new URLSearchParams(authorizeUrl().split('?')[1]).entries()].reverse(),
    ).toString()}`;

    const res = await get(reordered, { [SESSION_COOKIE]: sessionToken });

    expect(issuedCode(res)).toBeTruthy();
  });

  it('does not cover a request that repeats a parameter', async () => {
    const first = await get(authorizeUrl());
    const { sessionToken, returnUrl } = await scanAndApprove(first);

    const res = await get(`${returnUrl}&scope=openid`, { [SESSION_COOKIE]: sessionToken });

    expect(issuedCode(res)).toBeNull();
    expect(authCodes).toHaveLength(0);
  });

  it('starts a new QR sign-in when the record of the scan cannot be read', async () => {
    const first = await get(authorizeUrl());
    const { sessionToken, returnUrl } = await scanAndApprove(first);
    const { cacheTake } = await import('../../lib/cache.js');
    vi.mocked(cacheTake).mockRejectedValueOnce(new Error('redis down'));

    const res = await get(returnUrl, { [SESSION_COOKIE]: sessionToken });

    expect(goesToLogin(res)).toBe(true);
    expect(authCodes).toHaveLength(0);
  });

  it('leads a self-serve client to the consent page, not to a code', async () => {
    const first = await get(authorizeUrl({ client_id: 'selfserve' }));
    const { sessionToken, returnUrl } = await scanAndApprove(first);

    const res = await get(returnUrl, { [SESSION_COOKIE]: sessionToken });

    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('name="consent_token"');
    expect(authCodes).toHaveLength(0);
  });

  it('carries prompt=consent through the sign-in', async () => {
    const first = await get(authorizeUrl({ client_id: 'selfserve', prompt: 'consent' }));
    const { sessionToken, returnUrl } = await scanAndApprove(first);

    const res = await get(returnUrl, { [SESSION_COOKIE]: sessionToken });

    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('name="consent_token"');
  });

  it('completes a request that asked for prompt=login', async () => {
    const token = seedSession();
    const first = await get(authorizeUrl({ prompt: 'login' }), { [SESSION_COOKIE]: token });
    const { sessionToken, returnUrl } = await scanAndApprove(first);

    const res = await get(returnUrl, { [SESSION_COOKIE]: sessionToken });

    expect(issuedCode(res)).toBeTruthy();
  });

  it('completes a request whose max_age forced the sign-in', async () => {
    const token = seedSession('older-session', 60);
    const first = await get(authorizeUrl({ max_age: '1' }), { [SESSION_COOKIE]: token });
    const { sessionToken, returnUrl } = await scanAndApprove(first);

    const res = await get(returnUrl, { [SESSION_COOKIE]: sessionToken });

    expect(issuedCode(res)).toBeTruthy();
  });

  it('keeps nothing in Redis that could be replayed as the session cookie', async () => {
    const first = await get(authorizeUrl());
    const { sessionToken } = await scanAndApprove(first);

    expect(JSON.stringify([...cache.entries()])).not.toContain(sessionToken);
  });
});

describe('malformed /authorize parameters (FINDING-021)', () => {
  const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

  it('a repeated scope is answered with invalid_request, not a 500', async () => {
    const res = await get(`${authorizeUrl()}&scope=email`);

    expect(res.statusCode).toBe(302);
    const back = new URL(String(res.headers.location));
    expect(back.origin + back.pathname).toBe(REDIRECT_URI);
    expect(back.searchParams.get('error')).toBe('invalid_request');
    expect(back.searchParams.get('error_description')).toBe('scope must not be repeated');
    expect(back.searchParams.get('state')).toBe('state-1');
  });

  it('a repeated state is refused without echoing it', async () => {
    const res = await get(`${authorizeUrl()}&state=other`);

    const back = new URL(String(res.headers.location));
    expect(back.searchParams.get('error')).toBe('invalid_request');
    expect(back.searchParams.has('state')).toBe(false);
  });

  it.each(['client_id', 'redirect_uri'])('a repeated %s is shown as an error and never redirected', async (name) => {
    const res = await get(`${authorizeUrl()}&${name}=x`);

    expect(res.statusCode).toBe(400);
    expect(res.headers.location).toBeUndefined();
  });

  it('a code_challenge of the wrong length is refused', async () => {
    const res = await get(authorizeUrl({ code_challenge: CHALLENGE.slice(2), code_challenge_method: 'S256' }));

    expect(new URL(String(res.headers.location)).searchParams.get('error')).toBe('invalid_request');
  });

  it('a well-formed code_challenge still goes to sign-in', async () => {
    const res = await get(authorizeUrl({ code_challenge: CHALLENGE, code_challenge_method: 'S256' }));

    expect(goesToLogin(res)).toBe(true);
  });

  it('a repeated parameter in a POST body is refused the same way', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/authorize',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: `${authorizeUrl().split('?')[1]}&scope=email`,
    });

    expect(new URL(String(res.headers.location)).searchParams.get('error')).toBe('invalid_request');
  });
});

describe('OP session lifetime', () => {
  it('is 15 minutes, for the cookie and for the stored session', async () => {
    const first = await get(authorizeUrl());
    const before = Date.now();
    const { sessionToken, statusRes } = await scanAndApprove(first);

    const cookie = statusRes.cookies.find((c) => c.name === SESSION_COOKIE)!;
    expect(cookie.maxAge).toBe(900);
    const lifetimeMs = sessions.get(sha256(sessionToken))!.expiresAt.getTime() - before;
    expect(lifetimeMs).toBeGreaterThanOrEqual(900_000);
    expect(lifetimeMs).toBeLessThan(905_000);
  });
});

describe('GET /login copy', () => {
  it('names the application the person is signing in to, escaped', async () => {
    const first = await get(authorizeUrl());

    const page = await get(String(first.headers.location));

    expect(page.body).toContain('Scan to sign in to');
    expect(page.body).toContain('Example &lt;Shop&gt;');
    expect(page.body).not.toContain('Example <Shop>');
  });

  it('shows the host the person will be sent back to, under the name', async () => {
    const first = await get(authorizeUrl());

    const page = await get(String(first.headers.location));

    expect(page.body).toMatch(/<\/h1>\s*<p class="rp-host">rp\.example<\/p>/);
  });

  it('shows the host for an operator-vetted client too', async () => {
    const vetted = clients.find((c) => c.clientId === 'selfserve')!;
    vetted.consentRequired = false;
    try {
      const first = await get(authorizeUrl({ client_id: 'selfserve' }));

      const page = await get(String(first.headers.location));

      expect(page.body).toContain('<p class="rp-host">rp.example</p>');
    } finally {
      vetted.consentRequired = true;
    }
  });

  it('keeps a non-default port in the host', async () => {
    const withPort = clients.find((c) => c.clientId === 'other')!;
    const original = withPort.redirectUris;
    withPort.redirectUris = ['http://localhost:8082/callback'];
    try {
      const returnTo = authorizeUrl({ client_id: 'other', redirect_uri: 'http://localhost:8082/callback' });

      const page = await get(`/login?returnTo=${encodeURIComponent(returnTo)}`);

      expect(page.body).toContain('<p class="rp-host">localhost:8082</p>');
    } finally {
      withPort.redirectUris = original;
    }
  });

  it('does not name an application for a redirect URI it has not registered', async () => {
    const returnTo = authorizeUrl({ redirect_uri: 'https://evil.example/callback' });

    const page = await get(`/login?returnTo=${encodeURIComponent(returnTo)}`);

    expect(page.statusCode).toBe(200);
    expect(page.body).not.toContain('Scan to sign in to');
    expect(page.body).not.toContain('class="rp-host"');
    expect(page.body).not.toContain('evil.example');
  });

  it('does not name an application when client_id is given twice', async () => {
    const page = await get(`/login?returnTo=${encodeURIComponent(`${authorizeUrl()}&client_id=other`)}`);

    expect(page.body).not.toContain('Scan to sign in to');
  });

  it('falls back to the generic heading when the application is unknown', async () => {
    const page = await get(`/login?returnTo=${encodeURIComponent('/authorize?client_id=nope')}`);

    expect(page.statusCode).toBe(200);
    expect(page.body).not.toContain('Scan to sign in to');
    expect(page.body).toContain('Sign in with');
  });
});
