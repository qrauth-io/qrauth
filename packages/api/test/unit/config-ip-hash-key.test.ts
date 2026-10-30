/**
 * IP_HASH_KEY: the server secret for keyed IP hashes (lib/ip-hash.ts).
 * Required in production (at least 32 characters); development and test
 * use a fixed, public key so hashes are stable across runs.
 */
import { describe, it, expect, beforeAll } from 'vitest';

type ResolveFn = (env: { NODE_ENV: 'development' | 'test' | 'production'; IP_HASH_KEY?: string }) => string;

let resolveIpHashKey: ResolveFn;
let DEV_IP_HASH_KEY: string;

beforeAll(async () => {
  process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
  process.env.REDIS_URL ??= 'redis://localhost:6379';
  process.env.JWT_SECRET ??= 'test-jwt-secret-not-for-production-use-only-xx';
  process.env.NODE_ENV ??= 'test';
  const mod = await import('../../src/lib/config.js');
  resolveIpHashKey = mod.resolveIpHashKey;
  DEV_IP_HASH_KEY = mod.DEV_IP_HASH_KEY;
});

const KEY = 'k'.repeat(44);

describe('resolveIpHashKey', () => {
  it('production without IP_HASH_KEY fails with a clear message', () => {
    expect(() => resolveIpHashKey({ NODE_ENV: 'production' })).toThrow(/IP_HASH_KEY is required in production.*openssl rand -base64 32/s);
  });

  it('production with a key shorter than 32 characters fails', () => {
    expect(() => resolveIpHashKey({ NODE_ENV: 'production', IP_HASH_KEY: 'short' })).toThrow(/at least 32 characters/);
  });

  it('production uses the configured key', () => {
    expect(resolveIpHashKey({ NODE_ENV: 'production', IP_HASH_KEY: KEY })).toBe(KEY);
  });

  it.each(['development', 'test'] as const)('%s falls back to the fixed dev key', (NODE_ENV) => {
    expect(resolveIpHashKey({ NODE_ENV })).toBe(DEV_IP_HASH_KEY);
    expect(resolveIpHashKey({ NODE_ENV, IP_HASH_KEY: KEY })).toBe(KEY);
  });

  it('a short key is refused outside production too', () => {
    expect(() => resolveIpHashKey({ NODE_ENV: 'development', IP_HASH_KEY: 'short' })).toThrow(/at least 32 characters/);
  });
});
