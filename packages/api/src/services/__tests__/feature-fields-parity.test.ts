import { describe, it, expect, vi } from 'vitest';

// In-memory stand-in for the Redis calls extractFeatures makes, so the test
// runs the real extraction code and inspects the object it returns.
const fakeRedis = vi.hoisted(() => ({
  zadd: vi.fn(async () => 1),
  expire: vi.fn(async () => 1),
  zremrangebyscore: vi.fn(async () => 0),
  zcount: vi.fn(async () => 1),
  pfadd: vi.fn(async () => 1),
  pfcount: vi.fn(async () => 1),
  sismember: vi.fn(async () => 0),
  sadd: vi.fn(async () => 1),
  get: vi.fn(async () => null),
  set: vi.fn(async () => 'OK'),
  lpush: vi.fn(async () => 1),
  ltrim: vi.fn(async () => 'OK'),
  lrange: vi.fn(async () => ['90']),
}));
vi.mock('../../lib/cache.js', () => ({ redis: fakeRedis }));

import { FRAUD_RULE_FEATURE_FIELDS } from '@qrauth/shared';
import { FEATURE_KEYS, FeatureExtractionService } from '../feature-extraction.js';

const sorted = (xs: readonly string[]) => [...xs].sort();

describe('fraud rule feature fields', () => {
  it('extractFeatures returns exactly the declared FEATURE_KEYS', async () => {
    const features = await new FeatureExtractionService().extractFeatures({
      qrCodeId: 'qr_1',
      clientIpHash: 'ip_1',
      userAgent: 'Mozilla/5.0',
      trustScore: 90,
    });

    expect(sorted(Object.keys(features))).toEqual(sorted(FEATURE_KEYS));
  });

  it('the rule schema allows exactly the produced feature keys', () => {
    expect(sorted(FRAUD_RULE_FEATURE_FIELDS)).toEqual(sorted(FEATURE_KEYS));
  });
});
