import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * Audit 2026-10 FINDING-012 and the known "org tiers are IP-keyed" item.
 * Real @fastify/rate-limit plugin and real tier configs with production
 * limits; Redis is an in-memory stand-in that can be made to fail.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

const counters = new Map<string, number>();
let redisDown = false;
vi.mock('../../lib/cache.js', () => ({
  redis: {
    defineCommand: () => undefined,
    rateLimit: (
      key: string,
      timeWindow: number,
      _max: number,
      _continueExceeding: boolean,
      _exponentialBackoff: boolean,
      cb: (err: Error | null, result?: [number, number]) => void,
    ) => {
      if (redisDown) return cb(new Error('ECONNREFUSED'));
      const current = (counters.get(key) ?? 0) + 1;
      counters.set(key, current);
      cb(null, [current, timeWindow]);
    },
  },
}));

// Production limits: the dev/test headroom would hide the behaviour under test.
vi.mock('../../lib/config.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../lib/config.js')>();
  return { ...actual, config: { ...actual.config, server: { ...actual.config.server, isDev: false, isTest: false } } };
});

const apiKeys = new Map<string, { organizationId: string; revokedAt: Date | null }>();
let apiKeyLookups = 0;

const warnings: Array<Record<string, unknown>> = [];
let app: FastifyInstance;
let limits: typeof import('../rateLimit.js');

async function buildApp(): Promise<void> {
  limits = await import('../rateLimit.js');
  const { hashString } = await import('../../lib/crypto.js');
  app = Fastify({
    logger: { level: 'warn', stream: { write: (line: string) => { warnings.push(JSON.parse(line)); } } },
  });
  await app.register((await import('@fastify/jwt')).default, { secret: 'a'.repeat(32) });
  app.decorate('prisma', {
    apiKey: {
      findUnique: async ({ where }: { where: { keyHash: string } }) => {
        apiKeyLookups += 1;
        return apiKeys.get(where.keyHash) ?? null;
      },
    },
  } as never);
  apiKeys.set(hashString('qrauth_key_for_org_a'), { organizationId: 'org_a', revokedAt: null });
  apiKeys.set(hashString('qrauth_key_revoked_1'), { organizationId: 'org_a', revokedAt: new Date() });
  await app.register(limits.rateLimitMiddleware);

  const ok = async () => ({ ok: true });
  app.get('/org', { config: { rateLimit: limits.rateLimitConfig('auth', { max: 2 }) } }, ok);
  app.get('/default', ok);
  app.post('/sensitive', { config: { rateLimit: limits.rateLimitSensitive } }, ok);
  app.get('/login', { config: { rateLimit: limits.rateLimitOidcLogin } }, ok);
  app.get('/login/status', {
    onRequest: limits.loginStatusNetworkGuard(app),
    config: { rateLimit: limits.rateLimitOidcLoginStatus },
  }, ok);
  app.post('/token', { config: { rateLimit: limits.rateLimitOidcToken } }, ok);
  await app.ready();
}

const bearer = (orgId: string) => ({ authorization: `Bearer ${app.jwt.sign({ userId: 'u', orgId })}` });
const get = (url: string, headers: Record<string, string> = {}, remoteAddress = '203.0.113.7') =>
  app.inject({ method: 'GET', url, headers, remoteAddress });
async function hit(times: number, send: () => ReturnType<typeof get>): Promise<number[]> {
  const codes: number[] = [];
  for (let i = 0; i < times; i += 1) codes.push((await send()).statusCode);
  return codes;
}

beforeEach(async () => {
  counters.clear();
  apiKeys.clear();
  apiKeyLookups = 0;
  warnings.length = 0;
  redisDown = false;
  vi.resetModules();
  await buildApp();
});

afterEach(async () => {
  vi.useRealTimers();
  await app?.close();
});

describe('organization-keyed tiers', () => {
  it('give two organizations behind one IP their own buckets', async () => {
    const orgA = await hit(3, () => get('/org', bearer('org_a')));
    const orgB = await hit(2, () => get('/org', bearer('org_b')));

    expect(orgA).toEqual([200, 200, 429]);
    expect(orgB).toEqual([200, 200]);
  });

  it('count one organization across IPs and across JWT and API key', async () => {
    await get('/org', bearer('org_a'), '203.0.113.7');
    await get('/org', { 'x-api-key': 'qrauth_key_for_org_a' }, '198.51.100.9');

    const third = await get('/org', bearer('org_a'), '192.0.2.44');

    expect(third.statusCode).toBe(429);
  });

  it('do not look up a key that is not shaped like one', async () => {
    await get('/org', { 'x-api-key': 'short' });
    await get('/org', { 'x-api-key': 'has spaces and <tags> in it, definitely not a key' });

    expect(apiKeyLookups).toBe(0);
  });

  it('look an API key up once, not on every request', async () => {
    await hit(2, () => get('/org', { 'x-api-key': 'qrauth_key_for_org_a' }));

    expect(apiKeyLookups).toBe(1);
  });

  it('fall back to the IP for a forged token, an unknown key and a revoked key', async () => {
    await get('/org', { authorization: 'Bearer not.a.jwt' });
    await get('/org', { 'x-api-key': 'qrauth_no_such_key_x' });

    const third = await get('/org', { 'x-api-key': 'qrauth_key_revoked_1' });
    const otherIp = await get('/org', { authorization: 'Bearer not.a.jwt' }, '198.51.100.9');

    expect(third.statusCode).toBe(429);
    expect(otherIp.statusCode).toBe(200);
  });
});

describe('IP keys', () => {
  it('treat one IPv6 /64 as one client', async () => {
    await get('/org', {}, '2001:db8:1:2:aaaa::1');
    await get('/org', {}, '2001:db8:1:2:bbbb::2');

    const sameNetwork = await get('/org', {}, '2001:db8:1:2::3');
    const otherNetwork = await get('/org', {}, '2001:db8:1:3::1');

    expect(sameNetwork.statusCode).toBe(429);
    expect(otherNetwork.statusCode).toBe(200);
  });

  it('key an IPv4-mapped IPv6 address on the IPv4 address', async () => {
    await get('/org', {}, '::ffff:203.0.113.7');
    await get('/org', {}, '203.0.113.7');

    expect((await get('/org', {}, '::ffff:203.0.113.7')).statusCode).toBe(429);
    expect((await get('/org', {}, '::ffff:203.0.113.8')).statusCode).toBe(200);
  });
});

describe('OIDC tiers (FINDING-012)', () => {
  it('a polling browser keeps getting answers while /login from the same IP is limited', async () => {
    const logins = await hit(61, () => get('/login'));
    const polls = await hit(50, () => get('/login/status?id=AAAAAAAAAAAAAAAAAAAAAA'));

    expect(logins.slice(0, 60).every((code) => code === 200)).toBe(true);
    expect(logins[60]).toBe(429);
    expect(polls.every((code) => code === 200)).toBe(true);
  });

  it('limits /login/status per attempt, not per IP', async () => {
    const first = await hit(91, () => get('/login/status?id=AAAAAAAAAAAAAAAAAAAAAA'));
    const second = await get('/login/status?id=BBBBBBBBBBBBBBBBBBBBBB');

    expect(first[89]).toBe(200);
    expect(first[90]).toBe(429);
    expect(second.statusCode).toBe(200);
  });

  it('keys /login/status on the IP when the id is missing or malformed', async () => {
    const codes = [
      ...(await hit(45, () => get('/login/status'))),
      ...(await hit(46, () => get('/login/status?id=x&id=y'))),
    ];

    expect(codes[89]).toBe(200);
    expect(codes[90]).toBe(429);
  });

  it('caps a network that sends a new made-up id with every request', async () => {
    let n = 0;
    const freshId = () => `id${String((n += 1)).padStart(20, '0')}`;

    const codes = await hit(601, () => get(`/login/status?id=${freshId()}`));
    const otherNetwork = await get(`/login/status?id=${freshId()}`, {}, '198.51.100.9');

    expect(codes[599]).toBe(200);
    expect(codes[600]).toBe(429);
    expect(otherNetwork.statusCode).toBe(200);
  });

  it('gives /token its own bucket, separate from /login', async () => {
    await hit(61, () => get('/login'));

    const token = await app.inject({ method: 'POST', url: '/token', remoteAddress: '203.0.113.7' });

    expect(token.statusCode).toBe(200);
  });
});

describe('when Redis is unavailable', () => {
  it('lets ordinary and OIDC routes through', async () => {
    redisDown = true;

    expect((await get('/default')).statusCode).toBe(200);
    expect((await get('/org', bearer('org_a'))).statusCode).toBe(200);
    expect((await get('/login')).statusCode).toBe(200);
    expect((await app.inject({ method: 'POST', url: '/token' })).statusCode).toBe(200);
  });

  it('refuses sensitive authentication routes with 503', async () => {
    redisDown = true;

    const res = await app.inject({ method: 'POST', url: '/sensitive' });

    expect(res.statusCode).toBe(503);
  });

  it('logs one warning a minute, with a count, not one per request', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    redisDown = true;

    await hit(25, () => get('/default'));
    const firstMinute = warnings.filter((w) => w.event === 'rate_limit.store_unavailable');
    vi.setSystemTime(Date.now() + 61_000);
    await get('/default');
    const all = warnings.filter((w) => w.event === 'rate_limit.store_unavailable');

    expect(firstMinute).toHaveLength(1);
    expect(all).toHaveLength(2);
    expect(all[1].failuresSinceLastLog).toBe(24);
  });
});
