import { afterEach, describe, expect, it, vi } from 'vitest';

const retrieve = vi.fn();
vi.mock('stripe', () => ({ default: class { subscriptions = { retrieve }; } }));

async function load(secret: string | undefined) {
  vi.resetModules();
  if (secret) process.env.STRIPE_SECRET_KEY = secret;
  else delete process.env.STRIPE_SECRET_KEY;
  process.env.DATABASE_URL ??= 'postgresql://t:t@localhost:5432/t';
  process.env.REDIS_URL ??= 'redis://localhost:1';
  process.env.JWT_SECRET ??= 'a'.repeat(32);
  return (await import('../stripe.js')).stripeSubscriptionState;
}

describe('stripeSubscriptionState', () => {
  afterEach(() => retrieve.mockReset());

  it('is active until the subscription ended (past_due and incomplete can still bill)', async () => {
    const check = await load('sk_test_x');
    for (const status of ['active', 'trialing', 'past_due', 'unpaid', 'incomplete', 'paused']) {
      retrieve.mockResolvedValueOnce({ status });
      expect(await check('sub_1')).toBe('active');
    }
    for (const status of ['canceled', 'incomplete_expired']) {
      retrieve.mockResolvedValueOnce({ status });
      expect(await check('sub_1')).toBe('ended');
    }
  });

  it('is missing when Stripe does not know the id (test mode or another account)', async () => {
    const check = await load('sk_test_x');
    retrieve.mockRejectedValueOnce(Object.assign(new Error('No such subscription'), { code: 'resource_missing' }));
    expect(await check('sub_old')).toBe('missing');
  });

  it('is unknown when Stripe cannot be asked, refuses the key, or is not configured', async () => {
    const check = await load('sk_test_x');
    retrieve.mockRejectedValueOnce(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }));
    expect(await check('sub_1')).toBe('unknown');
    retrieve.mockRejectedValueOnce(Object.assign(new Error('Invalid API Key provided'), { type: 'StripeAuthenticationError' }));
    expect(await check('sub_1')).toBe('unknown');
    const unconfigured = await load(undefined);
    expect(await unconfigured('sub_1')).toBe('unknown');
  });
});
