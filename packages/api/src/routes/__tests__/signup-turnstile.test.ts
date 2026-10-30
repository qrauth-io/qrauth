import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * Email/password signup with Cloudflare Turnstile configured. The siteverify
 * call is mocked. A request that passes the check reaches the account lookup,
 * where the mocked database reports the email as taken (generic 400), so no
 * account is created here.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);
process.env.TURNSTILE_SECRET_KEY = 'test-secret';
process.env.TURNSTILE_SITE_KEY = 'test-site-key';

vi.mock('../../lib/cache.js', () => ({
  redis: {},
  cacheGet: vi.fn(async () => null),
  cacheSet: vi.fn(async () => undefined),
  cacheDel: vi.fn(async () => undefined),
  disconnectCache: vi.fn(async () => undefined),
}));

const verify = vi.hoisted(() => vi.fn());
vi.mock('../../lib/turnstile.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../lib/turnstile.js')>();
  return {
    ...actual,
    verifyTurnstileToken: verify,
    checkTurnstile: (...args: Parameters<typeof actual.checkTurnstile>) =>
      actual.checkTurnstile(args[0], args[1], args[2], args[3], verify),
  };
});

const findMany = vi.fn(async () => [{ id: 'u_existing', email: 'taken@example.com', emailVerified: true, providerId: null }]);

let app: FastifyInstance;

const SIGNUP = {
  name: 'Test User',
  email: 'taken@example.com',
  password: 'SecurePass123!',
  organizationName: 'Test Org',
};

const signup = (extra: Record<string, unknown> = {}) =>
  app.inject({
    method: 'POST',
    url: '/api/v1/auth/signup',
    headers: { 'content-type': 'application/json' },
    payload: JSON.stringify({ ...SIGNUP, ...extra }),
  });

beforeAll(async () => {
  app = Fastify({ logger: false });
  await app.register((await import('@fastify/cookie')).default);
  await app.register((await import('@fastify/jwt')).default, { secret: 'b'.repeat(32) });
  app.decorate('prisma', { user: { findMany } } as never);
  app.decorate('signingService', {} as never);
  app.decorate('authenticate', async () => undefined);
  const { default: authRoutes } = await import('../auth.js');
  await app.register(authRoutes, { prefix: '/api/v1/auth' });
  await app.ready();
});

afterAll(async () => {
  await app.close();
});

beforeEach(() => {
  verify.mockReset();
  findMany.mockClear();
});

describe('signup with Turnstile configured', () => {
  it('refuses a request without a token, before any database work', async () => {
    const res = await signup();

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('CaptchaFailed');
    expect(verify).not.toHaveBeenCalled();
    expect(findMany).not.toHaveBeenCalled();
  });

  it('refuses a token Cloudflare rejects', async () => {
    verify.mockResolvedValue({ outcome: 'failed', errorCodes: ['invalid-input-response'] });

    const res = await signup({ turnstileToken: 'bad' });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('CaptchaFailed');
    expect(findMany).not.toHaveBeenCalled();
  });

  it('fails closed (503) when siteverify is unreachable', async () => {
    verify.mockResolvedValue({ outcome: 'unavailable', detail: 'timeout' });

    const res = await signup({ turnstileToken: 'tok' });

    expect(res.statusCode).toBe(503);
    expect(findMany).not.toHaveBeenCalled();
  });

  it('passes a valid token through to the account lookup', async () => {
    verify.mockResolvedValue({ outcome: 'passed' });

    const res = await signup({ turnstileToken: 'good' });

    expect(verify).toHaveBeenCalledWith('test-secret', 'good', expect.any(String));
    expect(findMany).toHaveBeenCalled();
    expect(res.json().error).not.toBe('CaptchaFailed');
  });

  it('GET /providers exposes the site key for the widget', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/v1/auth/providers' });

    expect(res.json().turnstileSiteKey).toBe('test-site-key');
  });
});
