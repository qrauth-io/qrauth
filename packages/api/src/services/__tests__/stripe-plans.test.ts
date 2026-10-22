import { describe, it, expect } from 'vitest';
import { PLAN_PRICES_EUR, parseStripeLookupKey, stripeLookupKey } from '@qrauth/shared';
import {
  isSubscriptionEnded,
  planFromSubscription,
  priceMismatch,
  type StripePriceLike,
} from '../stripe-plans.js';

function price(overrides: Partial<StripePriceLike> = {}): StripePriceLike {
  return {
    id: 'price_test',
    active: true,
    currency: 'eur',
    unit_amount: 9900,
    lookup_key: 'qrauth_pro_month',
    recurring: { interval: 'month' },
    metadata: { plan: 'PRO' },
    ...overrides,
  };
}

function subscription(prices: StripePriceLike[], status = 'active') {
  return { id: 'sub_test', status, items: { data: prices.map((p) => ({ price: p })) } };
}

describe('plan catalogue prices', () => {
  it('pins the 2026-10 prices: Pro 99/990, Business 399/3990 EUR', () => {
    expect(PLAN_PRICES_EUR).toEqual({
      PRO: { month: 99, year: 990 },
      BUSINESS: { month: 399, year: 3_990 },
    });
  });

  it('round-trips every lookup key and rejects foreign ones', () => {
    for (const plan of ['PRO', 'BUSINESS'] as const) {
      for (const interval of ['month', 'year'] as const) {
        expect(parseStripeLookupKey(stripeLookupKey(plan, interval))).toEqual({ plan, interval });
      }
    }
    expect(stripeLookupKey('BUSINESS', 'year')).toBe('qrauth_business_year');
    expect(parseStripeLookupKey('qrauth_enterprise_year')).toBeNull();
    expect(parseStripeLookupKey(null)).toBeNull();
  });
});

describe('priceMismatch', () => {
  it('accepts a price that matches the catalogue exactly', () => {
    expect(priceMismatch(price(), 'PRO', 'month')).toBeNull();
    expect(
      priceMismatch(
        price({ unit_amount: 399_000, recurring: { interval: 'year' }, metadata: { plan: 'BUSINESS' } }),
        'BUSINESS',
        'year',
      ),
    ).toBeNull();
  });

  it.each([
    ['the old 49 EUR amount', price({ unit_amount: 4900 }), 'amount is 4900, expected 9900'],
    ['another currency', price({ currency: 'usd' }), 'currency is usd'],
    ['the wrong interval', price({ recurring: { interval: 'year' } }), 'interval is year'],
    ['an archived price', price({ active: false }), 'is archived'],
    ['a metadata plan mismatch', price({ metadata: { plan: 'BUSINESS' } }), 'metadata.plan is BUSINESS'],
    ['no metadata plan', price({ metadata: {} }), 'metadata.plan is unset'],
  ])('refuses %s', (_label, candidate, expected) => {
    expect(priceMismatch(candidate, 'PRO', 'month')).toContain(expected);
  });
});

describe('planFromSubscription', () => {
  it('maps each catalogue price to its plan', () => {
    expect(planFromSubscription(subscription([price()]))).toBe('PRO');
    expect(
      planFromSubscription(
        subscription([price({ lookup_key: 'qrauth_business_year', metadata: { plan: 'BUSINESS' } })]),
      ),
    ).toBe('BUSINESS');
  });

  it('returns null rather than guessing a plan', () => {
    expect(planFromSubscription(subscription([price({ lookup_key: null })]))).toBeNull();
    expect(planFromSubscription(subscription([price({ lookup_key: 'something_else' })]))).toBeNull();
    expect(planFromSubscription(subscription([]))).toBeNull();
    expect(planFromSubscription(subscription([price(), price()]))).toBeNull();
    // Lookup key and metadata disagree.
    expect(planFromSubscription(subscription([price({ metadata: { plan: 'BUSINESS' } })]))).toBeNull();
  });
});

describe('isSubscriptionEnded', () => {
  it('downgrades only on terminal statuses', () => {
    expect(isSubscriptionEnded('canceled')).toBe(true);
    expect(isSubscriptionEnded('incomplete_expired')).toBe(true);
    for (const status of ['active', 'trialing', 'past_due', 'incomplete', 'unpaid', 'paused']) {
      expect(isSubscriptionEnded(status)).toBe(false);
    }
  });
});
