import { describe, it, expect } from 'vitest';
import { checkoutBodySchema } from '../billing.js';

describe('checkoutBodySchema', () => {
  it('accepts every self-serve plan and interval', () => {
    for (const plan of ['PRO', 'BUSINESS']) {
      for (const interval of ['month', 'year']) {
        expect(checkoutBodySchema.safeParse({ plan, interval }).success).toBe(true);
      }
    }
  });

  it.each([
    ['ENTERPRISE (contract only)', { plan: 'ENTERPRISE', interval: 'year' }],
    ['FREE', { plan: 'FREE', interval: 'month' }],
    ['a missing interval', { plan: 'PRO' }],
    ['an unknown interval', { plan: 'PRO', interval: 'week' }],
    ['a client-supplied price id', { plan: 'PRO', interval: 'month', price: 'price_cheap' }],
  ])('rejects %s', (_label, body) => {
    expect(checkoutBodySchema.safeParse(body).success).toBe(false);
  });
});
