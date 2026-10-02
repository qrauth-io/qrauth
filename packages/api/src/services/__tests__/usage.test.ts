import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock the Redis client BEFORE importing UsageService — the service
// captures the export at import time, so the mock has to be in place
// by the time the module is evaluated.
vi.mock('../../lib/cache.js', () => {
  const store = new Map<string, string>();
  const ttls = new Map<string, number>();
  const failures = new Set<string>();
  const redis = {
    incr: vi.fn(async (key: string) => {
      if (failures.has('incr')) throw new Error('redis-down (incr)');
      const next = (parseInt(store.get(key) ?? '0', 10) || 0) + 1;
      store.set(key, String(next));
      return next;
    }),
    expire: vi.fn(async (key: string, seconds: number) => {
      if (failures.has('expire')) throw new Error('redis-down (expire)');
      ttls.set(key, seconds);
      return 1;
    }),
    get: vi.fn(async (key: string) => {
      if (failures.has('get')) throw new Error('redis-down (get)');
      return store.get(key) ?? null;
    }),
  };
  // Helpers exported on the same module for the tests to introspect.
  return {
    redis,
    __testStore: store,
    __testTtls: ttls,
    __testFailures: failures,
  };
});

import { UsageService, type UsageMetric } from '../usage.js';
// @ts-expect-error — test-only helpers attached to the mocked module
import { __testStore, __testTtls, __testFailures } from '../../lib/cache.js';

const makeFakeLogger = () => ({ warn: vi.fn() });

const ORG = 'org_abc';

function currentMonthKey(): string {
  const now = new Date();
  return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
}

function expectKey(orgId: string, metric: UsageMetric): string {
  return `qrauth:usage:${orgId}:${metric}:${currentMonthKey()}`;
}

describe('UsageService.increment', () => {
  let logger: ReturnType<typeof makeFakeLogger>;
  let prisma: { qRCode: { count: () => Promise<number> } };
  let svc: UsageService;

  beforeEach(async () => {
    __testStore.clear();
    __testTtls.clear();
    __testFailures.clear();
    // Reset spy call counts between tests so per-test assertions on
    // toHaveBeenCalledTimes don't bleed into each other.
    const { redis } = await import('../../lib/cache.js');
    (redis.incr as ReturnType<typeof vi.fn>).mockClear();
    (redis.expire as ReturnType<typeof vi.fn>).mockClear();
    (redis.get as ReturnType<typeof vi.fn>).mockClear();
    logger = makeFakeLogger();
    prisma = { qRCode: { count: vi.fn(async () => 0) } };
    // The cast keeps the test honest about touching only the surface
    // UsageService actually uses.
    svc = new UsageService(prisma as never, logger);
  });

  it('returns monotonically increasing values across sequential calls', async () => {
    const a = await svc.increment(ORG, 'verifications');
    const b = await svc.increment(ORG, 'verifications');
    const c = await svc.increment(ORG, 'verifications');
    expect([a, b, c]).toEqual([1, 2, 3]);
  });

  it('writes to the canonical Redis key shape', async () => {
    await svc.increment(ORG, 'verifications');
    expect([...__testStore.keys()]).toEqual([expectKey(ORG, 'verifications')]);
  });

  it('sets a 35-day TTL on first increment, no further TTL writes after', async () => {
    await svc.increment(ORG, 'authSessions');
    await svc.increment(ORG, 'authSessions');
    await svc.increment(ORG, 'authSessions');
    const key = expectKey(ORG, 'authSessions');
    expect(__testTtls.get(key)).toBe(35 * 24 * 60 * 60);
    // expire() should be called only on the first INCR (count === 1).
    const { redis } = await import('../../lib/cache.js');
    expect(redis.expire).toHaveBeenCalledTimes(1);
  });

  it('returns 0 and logs a warn when INCR throws (verify path must not fail)', async () => {
    __testFailures.add('incr');
    const result = await svc.increment(ORG, 'verifications');
    expect(result).toBe(0);
    expect(logger.warn).toHaveBeenCalledTimes(1);
    const [ctx, msg] = logger.warn.mock.calls[0] as [Record<string, unknown>, string];
    expect(ctx).toMatchObject({ orgId: ORG, metric: 'verifications' });
    expect(typeof ctx.err).toBe('string');
    expect(msg).toContain('increment failed');
  });

  it('keeps the new count when expire() throws (TTL miss is non-fatal)', async () => {
    __testFailures.add('expire');
    const result = await svc.increment(ORG, 'verifications');
    expect(result).toBe(1);
    expect(logger.warn).toHaveBeenCalledTimes(1);
    const [, msg] = logger.warn.mock.calls[0] as [Record<string, unknown>, string];
    expect(msg).toContain('failed to set TTL');
  });
});

describe('UsageService.current', () => {
  let logger: ReturnType<typeof makeFakeLogger>;
  let prismaCount: ReturnType<typeof vi.fn>;
  let svc: UsageService;

  beforeEach(() => {
    __testStore.clear();
    __testFailures.clear();
    logger = makeFakeLogger();
    prismaCount = vi.fn(async () => 0);
    svc = new UsageService({ qRCode: { count: prismaCount } } as never, logger);
  });

  it('returns 0 on key miss (no entry, no Redis error)', async () => {
    expect(await svc.current(ORG, 'verifications')).toBe(0);
    expect(logger.warn).not.toHaveBeenCalled();
  });

  it('returns the stored numeric count', async () => {
    __testStore.set(expectKey(ORG, 'verifications'), '42');
    expect(await svc.current(ORG, 'verifications')).toBe(42);
  });

  it('returns 0 when GET throws and logs a warn', async () => {
    __testFailures.add('get');
    expect(await svc.current(ORG, 'verifications')).toBe(0);
    expect(logger.warn).toHaveBeenCalledTimes(1);
  });

  it('uses Prisma (not Redis) for the qrcodes metric', async () => {
    prismaCount.mockResolvedValueOnce(7);
    expect(await svc.current(ORG, 'qrcodes')).toBe(7);
    expect(prismaCount).toHaveBeenCalledTimes(1);
  });
});

describe('UsageService.snapshot', () => {
  it('returns all four metrics in one call, including 0 fills for empty keys', async () => {
    __testStore.clear();
    __testStore.set(expectKey(ORG, 'verifications'), '12');
    __testStore.set(expectKey(ORG, 'authSessions'), '3');
    // ephemeralSessions key absent → 0
    const prisma = { qRCode: { count: vi.fn(async () => 5) } };
    const svc = new UsageService(prisma as never, makeFakeLogger());

    const snap = await svc.snapshot(ORG);

    expect(snap).toEqual({
      verifications: 12,
      qrcodes: 5,
      authSessions: 3,
      ephemeralSessions: 0,
    });
  });
});
