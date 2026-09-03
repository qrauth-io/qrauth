import type { FastifyInstance } from 'fastify';
import { rateLimitAuth } from '../middleware/rateLimit.js';
import { authorize } from '../middleware/authorize.js';
import { StripeService } from '../services/stripe.js';

export default async function billingRoutes(fastify: FastifyInstance): Promise<void> {
  const { authenticate } = fastify;
  const stripeService = new StripeService(fastify.prisma);

  // POST /checkout — create Stripe Checkout session
  fastify.post('/checkout', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
  }, async (request, reply) => {
    try {
      const url = await stripeService.createCheckoutSession(
        request.user!.orgId,
        request.user!.email,
      );
      return reply.send({ url });
    } catch (err: any) {
      return reply.status(400).send({ statusCode: 400, error: 'Billing Error', message: err.message });
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
    } catch (err: any) {
      return reply.status(400).send({ statusCode: 400, error: 'Billing Error', message: err.message });
    }
  });

  // POST /webhook — Stripe webhook handler (no auth — uses Stripe signature verification)
  // The raw body must be preserved exactly as received so Stripe can verify the HMAC
  // signature. We register a custom content-type parser for this route's encapsulation
  // scope that buffers the payload as a string instead of parsing it as JSON.
  fastify.addContentTypeParser(
    'application/json',
    { parseAs: 'buffer' },
    (_req, body, done) => {
      // Make the raw buffer available on the request object for the handler.
      // We pass the buffer through so downstream code can stringify when needed.
      done(null, body);
    },
  );

  fastify.post('/webhook', async (request, reply) => {
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
}
