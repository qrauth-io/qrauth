import type { FastifyInstance, FastifyReply } from 'fastify';
import { z } from 'zod';
import { SELF_SERVE_PLANS, BILLING_INTERVALS } from '@qrauth/shared';
import { rateLimitAuth } from '../middleware/rateLimit.js';
import { authorize } from '../middleware/authorize.js';
import { zodValidator } from '../middleware/validate.js';
import { StripeService, BillingError } from '../services/stripe.js';

export const checkoutBodySchema = z
  .object({
    plan: z.enum(SELF_SERVE_PLANS),
    interval: z.enum(BILLING_INTERVALS),
  })
  .strict();
type CheckoutBody = z.infer<typeof checkoutBodySchema>;

export default async function billingRoutes(fastify: FastifyInstance): Promise<void> {
  const { authenticate } = fastify;
  const stripeService = new StripeService(fastify.prisma);

  // Customer-safe messages pass through; anything else (Stripe outage, a
  // price that disagrees with the catalogue) is logged and answered generically.
  const billingFailure = (reply: FastifyReply, err: unknown) => {
    if (err instanceof BillingError) {
      return reply.status(400).send({ statusCode: 400, error: 'Billing Error', message: err.message });
    }
    fastify.log.error({ err }, 'Billing request failed');
    return reply.status(502).send({
      statusCode: 502,
      error: 'Billing Error',
      message: 'Billing is temporarily unavailable. Please try again or contact hello@qrauth.io.',
    });
  };

  // POST /checkout — create Stripe Checkout session for a self-serve plan
  fastify.post('/checkout', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
    preValidation: zodValidator({ body: checkoutBodySchema }),
  }, async (request, reply) => {
    const { plan, interval } = request.body as CheckoutBody;
    try {
      const url = await stripeService.createCheckoutSession(
        request.user!.orgId,
        request.user!.email,
        plan,
        interval,
      );
      return reply.send({ url });
    } catch (err) {
      return billingFailure(reply, err);
    }
  });

  // POST /portal — create Stripe Customer Portal session
  fastify.post('/portal', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
  }, async (request, reply) => {
    try {
      const url = await stripeService.createPortalSession(request.user!.orgId);
      return reply.send({ url });
    } catch (err) {
      return billingFailure(reply, err);
    }
  });

  // POST /webhook — Stripe webhook handler (no auth — uses Stripe signature verification)
  // The raw body must be preserved exactly as received so Stripe can verify the HMAC
  // signature. The raw-buffer content-type parser is registered in a child scope so
  // it applies to this route only and /checkout keeps normal JSON parsing.
  await fastify.register(async (webhookScope) => {
    webhookScope.addContentTypeParser(
      'application/json',
      { parseAs: 'buffer' },
      (_req, body, done) => {
        done(null, body);
      },
    );

    webhookScope.post('/webhook', async (request, reply) => {
      const signature = request.headers['stripe-signature'] as string;
      if (!signature) {
        return reply.status(400).send({ error: 'Missing stripe-signature header' });
      }
      try {
        // request.body is the raw Buffer from the content-type parser above.
        const rawBody = (request.body as Buffer).toString('utf8');
        await stripeService.handleWebhook(rawBody, signature);
        return reply.send({ received: true });
      } catch (err: any) {
        fastify.log.error({ err }, 'Stripe webhook error');
        return reply.status(400).send({ error: err.message });
      }
    });
  });
}
