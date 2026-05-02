import type { FastifyInstance } from 'fastify';
import { zodValidator } from '../middleware/validate.js';
import { authorize } from '../middleware/authorize.js';
import { createAppSchema, updateAppSchema } from '@qrauth/shared';
import { AppService } from '../services/app.js';
import { rateLimitAuth } from '../middleware/rateLimit.js';

export default async function appRoutes(fastify: FastifyInstance): Promise<void> {
  const { authenticate } = fastify;
  const appService = new AppService(fastify.prisma);

  // ---------------------------------------------------------------------------
  // POST / — Create app
  // ---------------------------------------------------------------------------

  fastify.post('/', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
    preValidation: zodValidator({ body: createAppSchema }),
  }, async (request, reply) => {
    const body = request.body as any;
    const result = await appService.createApp(request.user!.orgId, body);

    // Return with clientSecret visible (only time it's shown)
    return reply.status(201).send({
      id: result.id,
      name: result.name,
      slug: result.slug,
      clientId: result.clientId,
      clientSecret: result.clientSecret, // SHOWN ONCE
      redirectUrls: result.redirectUrls,
      webhookUrl: result.webhookUrl,
      allowedScopes: result.allowedScopes,
      status: result.status,
      createdAt: result.createdAt,
    });
  });

  // ---------------------------------------------------------------------------
  // GET / — List apps
  // ---------------------------------------------------------------------------

  fastify.get('/', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER')],
  }, async (request, reply) => {
    const apps = await appService.listApps(request.user!.orgId);
    return reply.send({ data: apps });
  });

  // ---------------------------------------------------------------------------
  // GET /:id — Get app details
  // ---------------------------------------------------------------------------

  fastify.get('/:id', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER')],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const app = await appService.getApp(id, request.user!.orgId);
    if (!app) {
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'App not found' });
    }
    return reply.send(app);
  });

  // ---------------------------------------------------------------------------
  // PATCH /:id — Update app
  // ---------------------------------------------------------------------------

  fastify.patch('/:id', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
    preValidation: zodValidator({ body: updateAppSchema }),
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    try {
      const app = await appService.updateApp(id, request.user!.orgId, request.body as any);
      return reply.send(app);
    } catch (err: any) {
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: err.message });
    }
  });

  // ---------------------------------------------------------------------------
  // DELETE /:id — Soft delete app
  // ---------------------------------------------------------------------------

  fastify.delete('/:id', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    try {
      await appService.deleteApp(id, request.user!.orgId);
      return reply.status(204).send();
    } catch (err: any) {
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: err.message });
    }
  });

  // ---------------------------------------------------------------------------
  // POST /:id/rotate-secret — Rotate client secret
  // ---------------------------------------------------------------------------

  fastify.post('/:id/rotate-secret', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    try {
      const result = await appService.rotateSecret(id, request.user!.orgId);
      return reply.send({
        clientSecret: result.clientSecret, // SHOWN ONCE
        message: 'Secret rotated. Store this value securely — it will not be shown again.',
      });
    } catch (err: any) {
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: err.message });
    }
  });
}
