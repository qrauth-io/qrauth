import type { PrismaClient } from '@prisma/client';
import { sendPlanChangedEmail } from '../lib/email.js';

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const STRIPE_PRICE_PRO = process.env.STRIPE_PRICE_PRO || 'price_pro_monthly';
const APP_URL = process.env.WEBAUTHN_ORIGIN || 'https://qrauth.io';

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

export class StripeService {
  constructor(private prisma: PrismaClient) {}

  async createCheckoutSession(orgId: string, orgEmail: string): Promise<string> {
    const stripe = await getStripe();

    // Get or create Stripe customer
    const org = await this.prisma.organization.findUnique({
      where: { id: orgId },
      select: { stripeCustomerId: true, name: true, email: true },
    });

    let customerId = org?.stripeCustomerId;
    if (!customerId) {
      const customer = await stripe.customers.create({
        email: orgEmail,
        name: org?.name,
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
      line_items: [{ price: STRIPE_PRICE_PRO, quantity: 1 }],
      success_url: `${APP_URL}/dashboard/settings?upgraded=true`,
      cancel_url: `${APP_URL}/dashboard/usage`,
      metadata: { orgId },
    });

    return session.url!;
  }

  async handleWebhook(payload: string, signature: string): Promise<void> {
    const stripe = await getStripe();
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
    if (!webhookSecret) throw new Error('Stripe webhook secret not configured');

    const event = stripe.webhooks.constructEvent(payload, signature, webhookSecret);

    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        const orgId = session.metadata?.orgId;
        if (orgId && session.subscription) {
          await this.prisma.organization.update({
            where: { id: orgId },
            data: {
              plan: 'PRO',
              stripeSubscriptionId: session.subscription as string,
            },
          });
          const updatedOrg = await this.prisma.organization.findUnique({
            where: { id: orgId }, select: { email: true, billingEmail: true, name: true },
          });
          if (updatedOrg) {
            sendPlanChangedEmail(updatedOrg.billingEmail || updatedOrg.email, updatedOrg.name, 'FREE', 'PRO').catch(() => {});
          }
        }
        break;
      }
      case 'customer.subscription.deleted': {
        const subscription = event.data.object;
        const org = await this.prisma.organization.findFirst({
          where: { stripeSubscriptionId: subscription.id },
        });
        if (org) {
          await this.prisma.organization.update({
            where: { id: org.id },
            data: { plan: 'FREE', stripeSubscriptionId: null },
          });
          const updatedOrg = await this.prisma.organization.findUnique({
            where: { id: org.id }, select: { email: true, billingEmail: true, name: true, plan: true },
          });
          if (updatedOrg) {
            sendPlanChangedEmail(updatedOrg.billingEmail || updatedOrg.email, updatedOrg.name, 'PRO', 'FREE').catch(() => {});
          }
        }
        break;
      }
      case 'customer.subscription.updated': {
        const subscription = event.data.object;
        const org = await this.prisma.organization.findFirst({
          where: { stripeSubscriptionId: subscription.id },
        });
        if (org && subscription.status === 'canceled') {
          await this.prisma.organization.update({
            where: { id: org.id },
            data: { plan: 'FREE', stripeSubscriptionId: null },
          });
        }
        break;
      }
    }
  }

  async createPortalSession(orgId: string): Promise<string> {
    const stripe = await getStripe();
    const org = await this.prisma.organization.findUnique({
      where: { id: orgId },
      select: { stripeCustomerId: true },
    });
    if (!org?.stripeCustomerId) throw new Error('No Stripe customer found');

    const session = await stripe.billingPortal.sessions.create({
      customer: org.stripeCustomerId,
      return_url: `${APP_URL}/dashboard/settings`,
    });
    return session.url;
  }
}
