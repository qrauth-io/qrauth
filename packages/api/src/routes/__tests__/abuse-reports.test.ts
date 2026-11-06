import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * Public "Report this code" endpoint (Turnstile not configured here; see
 * abuse-reports-turnstile.test.ts). Stores reports for existing codes only,
 * answers 202 either way, emails the abuse inbox at most once per code per
 * hour, and is rate limited per network.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);
process.env.ABUSE_NOTIFY_EMAIL = 'abuse@qrauth.test';
delete process.env.TURNSTILE_SECRET_KEY;
delete process.env.TURNSTILE_SITE_KEY;

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
});

const flush = () => new Promise((r) => setTimeout(r, 0));

describe('GET /v/:token/report', () => {
  it('renders the form with every reason and no Turnstile script when it is off', async () => {
    const res = await app.inject({ method: 'GET', url: '/v/tok_1/report' });

    expect(res.statusCode).toBe(200);
    expect(res.body).toContain('action="/v/tok_1/report"');
    for (const r of ['phishing', 'malware', 'impersonation', 'spam', 'other']) {
      expect(res.body).toContain(`value="${r}"`);
    }
    expect(res.body).not.toContain('challenges.cloudflare.com');
  });

  it('escapes the token in the page', async () => {
    const res = await app.inject({ method: 'GET', url: `/v/${encodeURIComponent('<b>x</b>')}/report` });

    expect(res.body).not.toContain('<b>x</b>');
  });
});

describe('POST /v/:token/report', () => {
  it('stores a report for an existing code and answers 202', async () => {
    const res = await postJson('tok_1', { reason: 'phishing', comment: ' fake login ', reporterEmail: 'r@example.com' });

    expect(res.statusCode).toBe(202);
    expect(res.json()).toEqual({ status: 'received' });
    expect(created).toHaveLength(1);
    expect(created[0]).toMatchObject({
      token: 'tok_1',
      organizationId: 'org_1',
      reason: 'PHISHING',
      comment: 'fake login',
      reporterEmail: 'r@example.com',
      ipHash: expect.any(String),
    });
    expect(created[0].ipHash).not.toContain('127.0.0.1');
  });

  it('answers an unknown token exactly the same, without storing anything', async () => {
    const known = await postJson('tok_1', { reason: 'spam' });
    const unknown = await postJson('tok_nope', { reason: 'spam' });

    expect(unknown.statusCode).toBe(known.statusCode);
    expect(unknown.body).toBe(known.body);
    expect(created).toHaveLength(1);
  });

  it.each([
    ['no reason', {}],
    ['an unknown reason', { reason: 'boring' }],
    ['a comment over 500 characters', { reason: 'spam', comment: 'x'.repeat(501) }],
    ['a bad email', { reason: 'spam', reporterEmail: 'not-an-email' }],
  ])('400 for %s', async (_label, body) => {
    const res = await postJson('tok_1', body);

    expect(res.statusCode).toBe(400);
    expect(created).toHaveLength(0);
  });

  it('a browser form post gets HTML pages (thank-you, or the form again with an error)', async () => {
    const ok = await postForm('tok_1', { reason: 'malware', comment: '' });
    expect(ok.statusCode).toBe(202);
    expect(ok.headers['content-type']).toContain('text/html');
    expect(ok.body).toContain('Thank you');

    const bad = await postForm('tok_1', { comment: 'no reason chosen' });
    expect(bad.statusCode).toBe(400);
    expect(bad.headers['content-type']).toContain('text/html');
    expect(bad.body).toContain('no reason chosen');
    expect(bad.body).toContain('Choose a reason');
  });

  it('emails the abuse inbox at most once per code per hour', async () => {
    await postJson('tok_1', { reason: 'phishing' });
    await postJson('tok_1', { reason: 'phishing' });
    await flush();

    expect(created).toHaveLength(2);
    expect(sendEmail).toHaveBeenCalledTimes(1);
    expect(sendEmail).toHaveBeenCalledWith('abuse@qrauth.test', expect.objectContaining({ token: 'tok_1', reason: 'PHISHING' }));
  });
});

describe('rate limit', () => {
  it('uses the report tier: 10 per hour per network, fails closed', async () => {
    const { rateLimitReport } = await import('../../middleware/rateLimit.js');

    expect(rateLimitReport).toMatchObject({ max: 10, timeWindow: '1 hour', skipOnError: false });
  });

  it('the 11th report from one network in an hour is refused', async () => {
    const limited = Fastify();
    limited.decorate('prisma', prisma as never);
    await limited.register((await import('@fastify/rate-limit')).default, { global: false });
    const { default: abuseReportRoutes } = await import('../abuse-reports.js');
    await limited.register(abuseReportRoutes, { prefix: '/v' });
    await limited.ready();

    const codes: number[] = [];
    for (let i = 0; i < 11; i += 1) {
      const res = await limited.inject({
        method: 'POST',
        url: '/v/tok_1/report',
        headers: { 'content-type': 'application/json' },
        payload: JSON.stringify({ reason: 'spam' }),
      });
      codes.push(res.statusCode);
    }
    await limited.close();

    expect(codes.slice(0, 10).every((c) => c === 202)).toBe(true);
    expect(codes[10]).toBe(429);
  });
});
