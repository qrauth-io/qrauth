import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * Audit 2026-10 FINDING-003: an OP login attempt belongs to the browser that
 * opened /login. /login/status hands out the OP session only to the browser
 * holding the matching pre-login cookie. Real route plugin; the auth-session
 * service, Redis and Prisma are in-memory stand-ins.
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
const createdWith: Array<Record<string, unknown>> = [];
vi.mock('../../services/auth-session.js', () => ({
  AuthSessionService: class {
    async createSession(_appId: string, data: Record<string, unknown>) {
      createdWith.push(data);
      return { id: authSession.id, token: 'as_token' };
    }
    async getSession() {
      return authSession;
    }
  },
}));

const opSessions: Array<{ userId: string }> = [];
const prisma = {
  oidcSession: {
    create: async ({ data }: { data: { userId: string } }) => {
      opSessions.push({ userId: data.userId });
      return data;
    },
  },
};

const warnings: Array<Record<string, unknown>> = [];
let app: FastifyInstance;

type Injected = Awaited<ReturnType<FastifyInstance['inject']>>;
const cookieOf = (res: Injected, name: string) => res.cookies.find((c) => c.name === name);

async function openLogin(headers: Record<string, string> = {}) {
  const res = await app.inject({ method: 'GET', url: '/login?returnTo=%2Fauthorize%3Fx%3D1', headers });
  const id = res.body.match(/var id = "([A-Za-z0-9_-]+)"/)![1];
  return { res, id, pre: cookieOf(res, 'qrauth_op_pre') };
}

const pollStatus = (id: string, cookies: Record<string, string> = {}) =>
  app.inject({ method: 'GET', url: `/login/status?id=${id}`, cookies });

beforeAll(async () => {
  app = Fastify({
    logger: {
      level: 'warn',
      stream: { write: (line: string) => { warnings.push(JSON.parse(line)); } },
    },
  });
  await app.register((await import('@fastify/cookie')).default);
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
  createdWith.length = 0;
  opSessions.length = 0;
  warnings.length = 0;
  authSession = { id: 'auth_session_1', status: 'PENDING', userId: null };
});

describe('GET /login', () => {
  it('sets an HttpOnly pre-login cookie scoped to the whole host', async () => {
    const { pre } = await openLogin();

    expect(pre).toBeDefined();
    expect(pre!.value.length).toBeGreaterThanOrEqual(43);
    expect(pre).toMatchObject({ httpOnly: true, sameSite: 'Lax', path: '/', maxAge: 600 });
    expect(pre!.domain).toBeUndefined();
  });

  it('stores only a hash of the cookie with the attempt', async () => {
    const { pre } = await openLogin();

    expect(JSON.stringify([...cache.values()])).not.toContain(pre!.value);
  });

  it('records what the approver should see about the requesting browser', async () => {
    await openLogin({
      'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36',
      'cf-ipcountry': 'GR',
      'cf-ipcity': 'Athens',
    });

    // The city header is ignored unless Cloudflare is declared to set it
    // (CF_VISITOR_LOCATION_HEADERS); by default it could be the visitor's own.
    expect(createdWith[0].metadata).toEqual({
      requester: { deviceType: 'desktop', browser: 'Chrome 130', os: 'macOS', country: 'GR' },
    });
  });

  it('drops location headers that are not plain place names', async () => {
    await openLogin({ 'cf-ipcountry': '<b>', 'cf-ipcity': '<script>alert(1)</script>' });

    const requester = (createdWith[0].metadata as { requester: Record<string, unknown> }).requester;
    expect(requester.country).toBeUndefined();
    expect(requester.city).toBeUndefined();
  });
});

describe('GET /login/status once the scan is approved', () => {
  beforeEach(() => {
    authSession = { id: 'auth_session_1', status: 'APPROVED', userId: 'user_1' };
  });

  it('issues the OP session to the browser that opened /login', async () => {
    const { id, pre } = await openLogin();

    const res = await pollStatus(id, { qrauth_op_pre: pre!.value });

    expect(res.json()).toEqual({ status: 'approved', redirectUrl: '/authorize?x=1' });
    expect(cookieOf(res, 'qrauth_op_session')?.value).toBeTruthy();
    expect(cookieOf(res, 'qrauth_op_pre')?.value).toBe('');
    expect(opSessions).toEqual([{ userId: 'user_1' }]);
  });

  it('does not issue a session to a browser without the pre-login cookie', async () => {
    const { id } = await openLogin();

    const res = await pollStatus(id);

    expect(res.json()).toEqual({ status: 'pending' });
    expect(cookieOf(res, 'qrauth_op_session')).toBeUndefined();
    expect(opSessions).toHaveLength(0);
    expect(warnings.some((w) => w.event === 'oidc.login.prelogin_mismatch')).toBe(true);
  });

  it('does not issue a session to a browser with a different pre-login cookie', async () => {
    const { id } = await openLogin();
    const other = await openLogin();

    const res = await pollStatus(id, { qrauth_op_pre: other.pre!.value });

    expect(res.json()).toEqual({ status: 'pending' });
    expect(cookieOf(res, 'qrauth_op_session')).toBeUndefined();
    expect(opSessions).toHaveLength(0);
  });

  it('a refused poll does not burn the attempt for the right browser', async () => {
    const { id, pre } = await openLogin();
    await pollStatus(id);

    const res = await pollStatus(id, { qrauth_op_pre: pre!.value });

    expect(res.json().status).toBe('approved');
    expect(opSessions).toHaveLength(1);
  });

  it('is single-use for the right browser too', async () => {
    const { id, pre } = await openLogin();
    await pollStatus(id, { qrauth_op_pre: pre!.value });

    const again = await pollStatus(id, { qrauth_op_pre: pre!.value });

    expect(again.statusCode).toBe(404);
    expect(opSessions).toHaveLength(1);
  });
});

const resume = (id: string, cookies: Record<string, string> = {}) =>
  app.inject({ method: 'GET', url: `/login/resume?id=${id}`, cookies });

describe('same-device sign-in (/login/resume)', () => {
  it('registers /login/resume for this attempt as the approval page return address', async () => {
    const { id } = await openLogin();

    // The issuer in production, the local API in dev (routes/oidc-login.ts opOrigin).
    expect(createdWith[0].redirectUrl).toMatch(/^(https:\/\/id\.qrauth\.io|http:\/\/localhost:\d+)\/login\/resume\?id=/);
    expect(createdWith[0].redirectUrl).toContain(`/login/resume?id=${id}`);
  });

  it('offers an "Approve on this device" button that opens the approval page with dr=1', async () => {
    const { res } = await openLogin();

    expect(res.body).toMatch(/id="same-device" href="[^"]+\/a\/as_token\?dr=1"/);
    expect(res.body).toContain('Approve on this device');
  });

  it('finishes the sign-in in the browser that opened /login and continues to /authorize', async () => {
    authSession = { id: 'auth_session_1', status: 'APPROVED', userId: 'user_1' };
    const { id, pre } = await openLogin();

    const res = await resume(id, { qrauth_op_pre: pre!.value });

    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe('/authorize?x=1');
    expect(cookieOf(res, 'qrauth_op_session')?.value).toBeTruthy();
    expect(cookieOf(res, 'qrauth_op_pre')?.value).toBe('');
    expect(opSessions).toEqual([{ userId: 'user_1' }]);
  });

  it('issues nothing in another browser and keeps the attempt for the original window', async () => {
    authSession = { id: 'auth_session_1', status: 'APPROVED', userId: 'user_1' };
    const { id, pre } = await openLogin();

    const elsewhere = await resume(id);

    expect(elsewhere.statusCode).toBe(200);
    expect(elsewhere.body).toContain('data-state="other_browser"');
    expect(cookieOf(elsewhere, 'qrauth_op_session')).toBeUndefined();
    expect(opSessions).toHaveLength(0);
    expect(warnings.some((w) => w.event === 'oidc.login.resume_other_browser')).toBe(true);

    // The original window's poller still collects it.
    const original = await pollStatus(id, { qrauth_op_pre: pre!.value });
    expect(original.json().status).toBe('approved');
  });

  it('is single-use: a second resume after success finds nothing', async () => {
    authSession = { id: 'auth_session_1', status: 'APPROVED', userId: 'user_1' };
    const { id, pre } = await openLogin();
    await resume(id, { qrauth_op_pre: pre!.value });

    const again = await resume(id, { qrauth_op_pre: pre!.value });

    expect(again.body).toContain('data-state="expired"');
    expect(opSessions).toHaveLength(1);
  });

  it('waits with a meta refresh and no script while the approval is still pending', async () => {
    const { id, pre } = await openLogin();

    const res = await resume(id, { qrauth_op_pre: pre!.value });

    expect(res.body).toContain('data-state="waiting"');
    expect(res.body).toContain('<meta http-equiv="refresh" content="2">');
    expect(res.body).not.toContain('<script');
    expect(opSessions).toHaveLength(0);
  });

  it('reports a declined approval', async () => {
    authSession = { id: 'auth_session_1', status: 'DENIED', userId: null };
    const { id, pre } = await openLogin();

    const res = await resume(id, { qrauth_op_pre: pre!.value });

    expect(res.body).toContain('data-state="denied"');
  });

  it('rejects a malformed or unknown attempt id without touching the cache', async () => {
    const bad = await resume('..%2F..%2Fx');
    expect(bad.statusCode).toBe(400);
    expect(bad.body).toContain('data-state="expired"');

    const unknown = await resume('A'.repeat(22));
    expect(unknown.statusCode).toBe(200);
    expect(unknown.body).toContain('data-state="expired"');
  });

  it('a poll and a resume racing for the same attempt mint one session', async () => {
    authSession = { id: 'auth_session_1', status: 'APPROVED', userId: 'user_1' };
    const { id, pre } = await openLogin();

    const [polled, resumed] = await Promise.all([
      pollStatus(id, { qrauth_op_pre: pre!.value }),
      resume(id, { qrauth_op_pre: pre!.value }),
    ]);

    expect(opSessions).toHaveLength(1);
    const winners = [polled.json().status === 'approved', resumed.statusCode === 303].filter(Boolean);
    expect(winners).toHaveLength(1);
  });
});
