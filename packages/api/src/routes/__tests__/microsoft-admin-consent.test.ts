import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * Microsoft sends a tenant admin back to this page after an admin-consent
 * grant. It is a static page: no login, no session, no database, and nothing
 * from the query string is trusted beyond being shown (escaped).
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);
process.env.WEBAUTHN_ORIGIN = 'https://qrauth.test';

const cacheCalls = vi.fn();
vi.mock('../../lib/cache.js', () => ({
  redis: {},
  cacheGet: vi.fn(async () => { cacheCalls(); return null; }),
  cacheSet: vi.fn(async () => { cacheCalls(); }),
  cacheDel: vi.fn(async () => { cacheCalls(); }),
  disconnectCache: vi.fn(async () => undefined),
}));

const TENANT = '00000000-0000-0000-0000-000000000000';
const SUCCESS_TEXT = 'QRAuth is now approved for your organisation. Your users can sign in with Microsoft.';
let app: FastifyInstance;

function get(query = '') {
  return app.inject({ method: 'GET', url: `/api/v1/auth/oauth/microsoft/admin-consent${query ? `?${query}` : ''}` });
}

beforeAll(async () => {
  app = Fastify({ logger: false });
  await app.register((await import('@fastify/cookie')).default);
  await app.register((await import('@fastify/jwt')).default, { secret: 'b'.repeat(32) });
  // No models on the client: any database access would throw.
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

describe('GET /oauth/microsoft/admin-consent', () => {
  it('shows the approved page when Microsoft reports admin consent was granted', async () => {
    const res = await get(`admin_consent=True&tenant=${TENANT}`);

    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/html');
    expect(res.body).toContain(SUCCESS_TEXT);
    expect(res.body).toContain(TENANT);
  });

  it('shows a friendly error with the error code when the admin declined', async () => {
    const res = await get('error=access_denied&error_description=AADSTS65004%3A+User+declined+to+consent');

    expect(res.statusCode).toBe(200);
    expect(res.body).not.toContain(SUCCESS_TEXT);
    expect(res.body).toContain('access_denied');
    expect(res.body).toContain('AADSTS65004: User declined to consent');
  });

  it('treats an error as an error even if admin_consent=True is also present', async () => {
    const res = await get(`admin_consent=True&tenant=${TENANT}&error=server_error`);

    expect(res.body).not.toContain(SUCCESS_TEXT);
    expect(res.body).toContain('server_error');
  });

  it('answers 400 with the error page when called without a Microsoft result', async () => {
    const res = await get();

    expect(res.statusCode).toBe(400);
    expect(res.body).not.toContain(SUCCESS_TEXT);
  });

  it('escapes everything taken from the query string', async () => {
    const xss = encodeURIComponent('"><script>alert(1)</script>');
    const res = await get(`error=${xss}&error_description=${xss}&tenant=${xss}`);

    expect(res.body).not.toContain('<script');
    expect(res.body).toContain('&lt;script&gt;');
  });

  it('never shows a tenant value that is not a GUID', async () => {
    const res = await get('admin_consent=True&tenant=evil.example');

    expect(res.statusCode).toBe(200);
    expect(res.body).toContain(SUCCESS_TEXT);
    expect(res.body).not.toContain('evil.example');
  });

  it('truncates an oversized error description', async () => {
    const res = await get(`error=server_error&error_description=${'A'.repeat(5000)}`);

    expect(res.body).not.toContain('A'.repeat(301));
  });

  it('sets no cookie, runs no script, is not cached and touches neither cache nor database', async () => {
    const res = await get(`admin_consent=True&tenant=${TENANT}`);

    expect(res.headers['set-cookie']).toBeUndefined();
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.body).not.toContain('<script');
    expect(cacheCalls).not.toHaveBeenCalled();
  });

  it('does not shadow the Microsoft sign-in callback', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/v1/auth/oauth/microsoft/callback?code=c' });

    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toContain('oauth_error=expired');
  });
});
