import type { PrismaClient } from '@prisma/client';
import {
  stripeLookupKey,
  type BillingInterval,
  type SelfServePlan,
} from '@qrauth/shared';
import { config } from '../lib/config.js';
import { sendPlanChangedEmail } from '../lib/email.js';
import {
  isSubscriptionEnded,
  planFromSubscription,
  priceMismatch,
  type StripePriceLike,
  type StripeSubscriptionLike,
} from './stripe-plans.js';
import { recordAudit, type AuditContext } from './audit.js';

/** The Stripe event a plan change came from, for its audit entry. */
type WebhookAudit = { readonly ctx: AuditContext; readonly eventId: string; readonly eventType: string };

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const APP_URL = config.webauthn.origin;

// Lazy-load Stripe to avoid crashes when STRIPE_SECRET_KEY is not set
let stripeInstance: any = null;
async function getStripe() {
  if (!STRIPE_SECRET_KEY) throw new Error('Stripe is not configured');
  if (!stripeInstance) {
    const { default: Stripe } = await import('stripe');
    stripeInstance = new Stripe(STRIPE_SECRET_KEY);
  }
  return stripeInstance;
}

/**
 * What Stripe says about a stored subscription id:
 *   active  — Stripe has it and it has not ended (it can bill and send events);
 *   ended   — Stripe has it and it ended (canceled, incomplete_expired);
 *   missing — Stripe answers that it does not exist in the configured account
 *             (a test-mode id, an earlier account, or a wrong STRIPE_SECRET_KEY);
 *   unknown — Stripe is not configured or could not be asked.
 * Callers treat `unknown` like `active`.
 */
export type StripeSubscriptionState = 'active' | 'ended' | 'missing' | 'unknown';

export async function stripeSubscriptionState(subscriptionId: string): Promise<StripeSubscriptionState> {
  if (!STRIPE_SECRET_KEY) return 'unknown';
  try {
    const stripe = await getStripe();
    const subscription = await stripe.subscriptions.retrieve(subscriptionId);
    return isSubscriptionEnded(subscription.status) ? 'ended' : 'active';
  } catch (err) {
    return (err as { code?: string }).code === 'resource_missing' ? 'missing' : 'unknown';
  }
}

/** An error whose message is safe to show the customer. */
export class BillingError extends Error {}

export class StripeService {
  constructor(private prisma: PrismaClient) {}

  async createCheckoutSession(
    orgId: string,
    orgEmail: string,
    plan: SelfServePlan,
    interval: BillingInterval,
  ): Promise<string> {
    const stripe = await getStripe();

    const org = await this.prisma.organization.findUnique({
      where: { id: orgId },
      select: { stripeCustomerId: true, stripeSubscriptionId: true, name: true, plan: true },
    });
    if (!org) throw new BillingError('Organization not found');
    // A second Checkout would start a second, parallel subscription. Plan
    // changes for subscribers go through the billing portal instead.
    if (org.stripeSubscriptionId) {
      throw new BillingError('This organization already has a subscription. Change plan from Manage billing.');
    }
    if (org.plan === 'ENTERPRISE') {
      throw new BillingError('This organization is on a Regulated licence. Contact hello@qrauth.io to change it.');
    }

    const price = await this.resolveCataloguePrice(stripe, plan, interval);

    let customerId = org.stripeCustomerId;
    if (!customerId) {
      const customer = await stripe.customers.create({
        email: orgEmail,
        name: org.name,
        metadata: { orgId },
      });
      customerId = customer.id;
      await this.prisma.organization.update({
        where: { id: orgId },
        data: { stripeCustomerId: customerId },
      });
    }

    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      mode: 'subscription',
      line_items: [{ price: price.id, quantity: 1 }],
      success_url: `${APP_URL}/dashboard/settings?upgraded=true`,
      cancel_url: `${APP_URL}/dashboard/pricing`,
      metadata: { orgId },
      subscription_data: { metadata: { orgId } },
    });

    return session.url!;
  }

  /** The active catalogue Price for plan+interval; throws if Stripe disagrees with the catalogue. */
  private async resolveCataloguePrice(
    stripe: any,
    plan: SelfServePlan,
    interval: BillingInterval,
  ): Promise<StripePriceLike> {
    const lookupKey = stripeLookupKey(plan, interval);
    const { data } = await stripe.prices.list({ lookup_keys: [lookupKey], active: true, limit: 2 });
    if (data.length !== 1) {
      throw new Error(`Stripe has ${data.length} active prices for lookup key ${lookupKey}`);
    }
    const mismatch = priceMismatch(data[0], plan, interval);
    if (mismatch) throw new Error(`Stripe price does not match the plan catalogue: ${mismatch}`);
    return data[0];
  }

  /** Applies a verified Stripe event; a plan change is audited under `ctx` (the Stripe system actor). */
  async handleWebhook(payload: string, signature: string, ctx: AuditContext): Promise<void> {
    const stripe = await getStripe();
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
    if (!webhookSecret) throw new Error('Stripe webhook secret not configured');

    const event = stripe.webhooks.constructEvent(payload, signature, webhookSecret);
    const audit: WebhookAudit = { ctx, eventId: event.id, eventType: event.type };

    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        const orgId = session.metadata?.orgId;
        if (!orgId || !session.subscription) break;
        const subscription: StripeSubscriptionLike = await stripe.subscriptions.retrieve(
          session.subscription as string,
        );
        await this.applySubscription(orgId, subscription, audit);
        break;
      }
      case 'customer.subscription.updated': {
        const subscription: StripeSubscriptionLike = event.data.object;
        const org = await this.prisma.organization.findFirst({
          where: { stripeSubscriptionId: subscription.id },
          select: { id: true },
        });
        if (!org) break;
        if (isSubscriptionEnded(subscription.status)) {
          await this.setPlan(org.id, 'FREE', null, audit);
        } else {
          // Covers plan switches made in the billing portal.
          await this.applySubscription(org.id, subscription, audit);
        }
        break;
      }
      case 'customer.subscription.deleted': {
        const subscription: StripeSubscriptionLike = event.data.object;
        const org = await this.prisma.organization.findFirst({
          where: { stripeSubscriptionId: subscription.id },
          select: { id: true },
        });
        if (org) await this.setPlan(org.id, 'FREE', null, audit);
        break;
      }
    }
  }

  /**
   * Set the org's plan from what the subscription is charged for. An
   * unrecognised Price throws, so the webhook answers 400 and Stripe retries
   * while the error is visible in the logs, instead of granting a guessed plan.
   */
  private async applySubscription(orgId: string, subscription: StripeSubscriptionLike, audit: WebhookAudit): Promise<void> {
    const plan = planFromSubscription(subscription);
    if (!plan) {
      const prices = subscription.items?.data?.map((item) => item.price.lookup_key ?? item.price.id);
      throw new Error(
        `Subscription ${subscription.id} is not on a catalogue price (${JSON.stringify(prices)}); org ${orgId} plan unchanged`,
      );
    }
    await this.setPlan(orgId, plan, subscription.id, audit);
  }

  /**
   * Sets the plan and subscription. In the same transaction: billing.plan.change
   * when the plan changed, billing.subscription.cancel when the subscription
   * ended (stripeSubscriptionId null) and the organization had one.
   */
  private async setPlan(
    orgId: string,
    plan: 'FREE' | SelfServePlan,
    stripeSubscriptionId: string | null,
    audit: WebhookAudit,
  ): Promise<void> {
    const result = await this.prisma.$transaction(async (tx) => {
      const before = await tx.organization.findUnique({
        where: { id: orgId },
        select: { plan: true, stripeSubscriptionId: true },
      });
      if (!before) return null;
      const updated = await tx.organization.update({
        where: { id: orgId },
        data: { plan, stripeSubscriptionId },
        select: { email: true, billingEmail: true, name: true },
      });
      const stripe = { stripeEventId: audit.eventId, stripeEventType: audit.eventType };
      if (before.plan !== plan) {
        await recordAudit(tx, audit.ctx, {
          organizationId: orgId,
          action: 'billing.plan.change',
          resource: 'Organization',
          resourceId: orgId,
          metadata: { from: before.plan, to: plan, stripeSubscriptionId, ...stripe },
        });
      }
      if (stripeSubscriptionId === null && before.stripeSubscriptionId !== null) {
        await recordAudit(tx, audit.ctx, {
          organizationId: orgId,
          action: 'billing.subscription.cancel',
          resource: 'Organization',
          resourceId: orgId,
          metadata: { stripeSubscriptionId: before.stripeSubscriptionId, plan: { from: before.plan, to: plan }, ...stripe },
        });
      }
      return { before, updated };
    });
    if (!result || result.before.plan === plan) return;
    const { before, updated } = result;
    sendPlanChangedEmail(updated.billingEmail || updated.email, updated.name, before.plan, plan).catch(() => {});
  }

  async createPortalSession(orgId: string): Promise<string> {
    const stripe = await getStripe();
    const org = await this.prisma.organization.findUnique({
      where: { id: orgId },
      select: { stripeCustomerId: true },
    });
    if (!org?.stripeCustomerId) throw new BillingError('No billing account found for this organization');

    const session = await stripe.billingPortal.sessions.create({
      customer: org.stripeCustomerId,
      return_url: `${APP_URL}/dashboard/settings`,
    });
    return session.url;
  }
}
