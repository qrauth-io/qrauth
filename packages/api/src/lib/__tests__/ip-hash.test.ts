import { createHash, createHmac } from 'node:crypto';
import { describe, it, expect, beforeAll } from 'vitest';

process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);

let hashIp: (ip: string | undefined | null) => string;
let keyedHash: (key: string, ip: string) => string;
let IP_HASH_PATTERN: RegExp;
let DEV_IP_HASH_KEY: string;

beforeAll(async () => {
  ({ hashIp, keyedHash, IP_HASH_PATTERN } = await import('../ip-hash.js'));
  ({ DEV_IP_HASH_KEY } = await import('../config.js'));
});

describe('hashIp (keyed IP hash)', () => {
  it('is HMAC-SHA256 under the server key, with a version prefix', () => {
    const expected = `k1:${createHmac('sha256', DEV_IP_HASH_KEY).update('203.0.113.7').digest('hex')}`;
    expect(hashIp('203.0.113.7')).toBe(expected);
    expect(hashIp('203.0.113.7')).toMatch(IP_HASH_PATTERN);
  });

  it('is stable for the same IP, so velocity and clustering signals still match', () => {
    expect(hashIp('2001:db8::1')).toBe(hashIp('2001:db8::1'));
    expect(hashIp('203.0.113.7')).not.toBe(hashIp('203.0.113.8'));
  });

  it('is not the plain SHA-256 of the IP', () => {
    const plain = createHash('sha256').update('203.0.113.7').digest('hex');
    expect(hashIp('203.0.113.7')).not.toContain(plain);
  });

  it('depends on the key', () => {
    expect(keyedHash('a'.repeat(32), '203.0.113.7')).not.toBe(keyedHash('b'.repeat(32), '203.0.113.7'));
  });

  it('a missing IP hashes as "unknown"', () => {
    expect(hashIp(undefined)).toBe(hashIp('unknown'));
    expect(hashIp('')).toBe(hashIp('unknown'));
  });
});
