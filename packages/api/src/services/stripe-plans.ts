import {
  PLAN_PRICES_EUR,
  parseStripeLookupKey,
  type BillingInterval,
  type SelfServePlan,
} from '@qrauth/shared';

/**
 * Pure mapping between Stripe Prices and QRAuth plans.
 *
 * A Price is identified by its lookup key (`qrauth_<plan>_<interval>`, see
 * stripeLookupKey in @qrauth/shared), never by a price id in env config, so
 * the plan an org gets is derived from what Stripe actually charges.
 */

/** The subset of a Stripe Price object this module reads. */
export interface StripePriceLike {
  id: string;
  active: boolean;
  currency: string;
  unit_amount: number | null;
  lookup_key: string | null;
  recurring: { interval: string } | null;
  metadata?: Record<string, string>;
}

export interface StripeSubscriptionLike {
  id: string;
  status: string;
  items: { data: Array<{ price: StripePriceLike }> };
}

/** Subscription statuses after which the org drops back to FREE. */
const ENDED_STATUSES = new Set(['canceled', 'incomplete_expired']);

export function isSubscriptionEnded(status: string): boolean {
  return ENDED_STATUSES.has(status);
}

/**
 * Null when the Price charges exactly the catalogue amount for this plan and
 * interval, otherwise a description of the mismatch. Checkout refuses a
 * mismatched Price, so the pricing page can never show one amount while
 * Stripe charges another.
 */
export function priceMismatch(
  price: StripePriceLike,
  plan: SelfServePlan,
  interval: BillingInterval,
): string | null {
  const expectedCents = PLAN_PRICES_EUR[plan][interval] * 100;
  if (!price.active) return `price ${price.id} is archived`;
  if (price.currency !== 'eur') return `price ${price.id} currency is ${price.currency}, expected eur`;
  if (price.unit_amount !== expectedCents) {
    return `price ${price.id} amount is ${price.unit_amount}, expected ${expectedCents}`;
  }
  if (price.recurring?.interval !== interval) {
    return `price ${price.id} interval is ${price.recurring?.interval ?? 'none'}, expected ${interval}`;
  }
  if (price.metadata?.plan !== plan) {
    return `price ${price.id} metadata.plan is ${price.metadata?.plan ?? 'unset'}, expected ${plan}`;
  }
  return null;
}

/**
 * The plan a subscription pays for, or null when it is not exactly one item
 * on a catalogue Price. Callers treat null as a configuration error and do
 * not change the org's plan.
 */
export function planFromSubscription(subscription: StripeSubscriptionLike): SelfServePlan | null {
  const items = subscription.items?.data ?? [];
  if (items.length !== 1) return null;
  const { price } = items[0];
  const parsed = parseStripeLookupKey(price.lookup_key);
  if (!parsed) return null;
  if (price.metadata?.plan !== undefined && price.metadata.plan !== parsed.plan) return null;
  return parsed.plan;
}
