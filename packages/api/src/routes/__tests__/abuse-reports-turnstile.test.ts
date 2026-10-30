import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * "Report this code" with Turnstile configured (siteverify mocked).
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);
process.env.ABUSE_NOTIFY_EMAIL = 'abuse@qrauth.test';
process.env.TURNSTILE_SECRET_KEY = 'test-secret';
process.env.TURNSTILE_SITE_KEY = 'test-site-key';

const verify = vi.hoisted(() => vi.fn());
vi.mock('../../lib/turnstile.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../lib/turnstile.js')>();
  return {
    ...actual,
    checkTurnstile: (...args: Parameters<typeof actual.checkTurnstile>) =>
      actual.checkTurnstile(args[0], args[1], args[2], args[3], verify),
  };
});

const throttle = vi.hoisted(() => new Set<string>());
vi.mock('../../lib/cache.js', () => ({
  redis: {
    set: vi.fn(async (key: string) => {
      if (throttle.has(key)) return null;
      throttle.add(key);
      return 'OK';
    }),
  },
}));
const sendEmail = vi.hoisted(() => vi.fn(async () => undefined));
vi.mock('../../lib/email.js', () => ({ sendAbuseReportEmail: sendEmail }));

const QR = {
  token: 'tok_1',
  organizationId: 'org_1',
  destinationUrl: 'https://pay.example.com',
  organization: { name: 'Acme' },
};
const created: Array<Record<string, unknown>> = [];
const prisma = {
  qRCode: { findUnique: vi.fn(async ({ where }: { where: { token: string } }) => (where.token === QR.token ? QR : null)) },
  abuseReport: {
    create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => {
      created.push(data);
      return { id: `rep_${created.length}`, ...data };
    }),
  },
};

let app: FastifyInstance;

const postJson = (token: string, body: unknown) =>
  app.inject({
    method: 'POST',
    url: `/v/${token}/report`,
    headers: { 'content-type': 'application/json' },
    payload: JSON.stringify(body),
  });
const postForm = (token: string, body: Record<string, string>) =>
  app.inject({
    method: 'POST',
    url: `/v/${token}/report`,
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams(body).toString(),
  });

beforeAll(async () => {
  app = Fastify();
  app.decorate('prisma', prisma as never);
  app.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string' }, (_req, body, done) => {
    done(null, Object.fromEntries(new URLSearchParams(body as string)));
  });
  const { default: abuseReportRoutes } = await import('../abuse-reports.js');
  await app.register(abuseReportRoutes, { prefix: '/v' });
  await app.ready();
});

afterAll(async () => {
  await app.close();
});

beforeEach(() => {
  created.length = 0;
  throttle.clear();
  sendEmail.mockClear();
  verify.mockReset();
});

const flush = () => new Promise((r) => setTimeout(r, 0));

describe('report with Turnstile configured', () => {
  it('the form loads the widget with the site key and a CSP that allows Cloudflare', async () => {
    const res = await app.inject({ method: 'GET', url: '/v/tok_1/report' });

    expect(res.body).toContain('data-sitekey="test-site-key"');
    expect(res.body).toContain('https://challenges.cloudflare.com/turnstile/v0/api.js');
  });

  it('refuses a report without a token, storing nothing', async () => {
    const res = await postJson('tok_1', { reason: 'phishing' });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('CaptchaFailed');
    expect(verify).not.toHaveBeenCalled();
    expect(created).toHaveLength(0);
  });

  it('refuses a token Cloudflare rejects', async () => {
    verify.mockResolvedValue({ outcome: 'failed', errorCodes: ['invalid-input-response'] });

    const res = await postJson('tok_1', { reason: 'phishing', turnstileToken: 'bad' });

    expect(res.statusCode).toBe(400);
    expect(created).toHaveLength(0);
  });

  it('fails closed (503) when siteverify is unreachable', async () => {
    verify.mockResolvedValue({ outcome: 'unavailable', detail: 'timeout' });

    const res = await postJson('tok_1', { reason: 'phishing', turnstileToken: 'tok' });

    expect(res.statusCode).toBe(503);
    expect(created).toHaveLength(0);
  });

  it('accepts the widget field from a browser form post', async () => {
    verify.mockResolvedValue({ outcome: 'passed' });

    const res = await postForm('tok_1', { reason: 'phishing', 'cf-turnstile-response': 'widget-token' });

    expect(res.statusCode).toBe(202);
    expect(verify).toHaveBeenCalledWith('test-secret', 'widget-token', expect.any(String));
    expect(created).toHaveLength(1);
  });

  it('a refused browser post gets an HTML page', async () => {
    verify.mockResolvedValue({ outcome: 'failed', errorCodes: [] });

    const res = await postForm('tok_1', { reason: 'phishing', 'cf-turnstile-response': 'x' });

    expect(res.statusCode).toBe(400);
    expect(res.headers['content-type']).toContain('text/html');
    expect(res.body).toContain('Report not sent');
  });
});
