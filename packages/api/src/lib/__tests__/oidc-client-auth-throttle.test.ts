import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createHash } from 'node:crypto';

/**
 * Audit 2026-10 FINDING-012: failed client authentication at /token and
 * /revoke is limited per client and caller network. A wrong secret is never
 * answered more gently because Redis is down; a right one never depends on it.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

const counters = new Map<string, number>();
let redisDown = false;
vi.mock('../cache.js', () => ({
  redis: {},
  cacheGet: vi.fn(async (key: string) => {
    if (redisDown) throw new Error('ECONNREFUSED');
    return counters.get(key) ?? null;
  }),
  cacheIncr: vi.fn(async (key: string) => {
    if (redisDown) throw new Error('ECONNREFUSED');
    const next = (counters.get(key) ?? 0) + 1;
    counters.set(key, next);
    return next;
  }),
}));

const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');
const client = { id: 'db_1', clientId: 'shop', clientSecretHash: sha256('right-secret') };
const prisma = {
  oidcClient: {
    findUnique: async ({ where }: { where: { clientId: string } }) => (where.clientId === 'shop' ? client : null),
  },
} as never;

const { authenticateOidcClientThrottled, CLIENT_AUTH_MAX_FAILURES } = await import('../oidc-client-auth-throttle.js');

const attempt = (secret: string, ip = '203.0.113.7', clientId = 'shop') =>
  authenticateOidcClientThrottled(prisma, undefined, { client_id: clientId, client_secret: secret }, ip);

beforeEach(() => {
  counters.clear();
  redisDown = false;
});

describe('failed client authentication limit', () => {
  it('passes a correct secret through', async () => {
    expect(await attempt('right-secret')).toMatchObject({ ok: true });
  });

  it('refuses even the right secret after too many wrong ones from the same network', async () => {
    for (let i = 0; i < CLIENT_AUTH_MAX_FAILURES; i += 1) {
      expect(await attempt('wrong')).toMatchObject({ ok: false, throttled: false });
    }

    expect(await attempt('wrong')).toMatchObject({ ok: false, throttled: true });
    expect(await attempt('right-secret')).toMatchObject({ ok: false, throttled: true });
  });

  it('does not let one network lock the client out for everyone else', async () => {
    for (let i = 0; i <= CLIENT_AUTH_MAX_FAILURES; i += 1) await attempt('wrong', '203.0.113.7');

    expect(await attempt('right-secret', '198.51.100.9')).toMatchObject({ ok: true });
  });

  it('counts an IPv6 /64 as one network', async () => {
    for (let i = 0; i <= CLIENT_AUTH_MAX_FAILURES; i += 1) await attempt('wrong', `2001:db8:1:2::${i + 1}`);

    expect(await attempt('right-secret', '2001:db8:1:2:ffff::1')).toMatchObject({ ok: false, throttled: true });
  });

  it('counts unknown client ids too, without creating a key per guess of the secret', async () => {
    for (let i = 0; i <= CLIENT_AUTH_MAX_FAILURES; i += 1) await attempt('x', '203.0.113.7', 'nope');

    expect(await attempt('x', '203.0.113.7', 'nope')).toMatchObject({ ok: false, throttled: true });
    expect(counters.size).toBe(1);
  });

  it('does not count a request that names no client', async () => {
    await authenticateOidcClientThrottled(prisma, undefined, {}, '203.0.113.7');

    expect(counters.size).toBe(0);
  });
});

describe('when Redis is unavailable', () => {
  it('still accepts a correct secret', async () => {
    redisDown = true;

    expect(await attempt('right-secret')).toMatchObject({ ok: true });
  });

  it('answers a wrong secret as limited, since the failure cannot be counted', async () => {
    redisDown = true;

    expect(await attempt('wrong')).toMatchObject({ ok: false, throttled: true });
  });
});
