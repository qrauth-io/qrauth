import type { FastifyInstance } from 'fastify';
import { paginationSchema } from '@qrauth/shared';
import { zodValidator } from '../middleware/validate.js';
import { authorize } from '../middleware/authorize.js';
import { rateLimitAuth } from '../middleware/rateLimit.js';

// ---------------------------------------------------------------------------
// Route plugin
// ---------------------------------------------------------------------------

export default async function webhookDeliveryRoutes(fastify: FastifyInstance): Promise<void> {
  const { authenticate } = fastify;

  // -------------------------------------------------------------------------
  // GET / — List webhook deliveries for the organization's apps
  // -------------------------------------------------------------------------

  fastify.get('/', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
    preValidation: zodValidator({ querystring: paginationSchema }),
  }, async (request, reply) => {
    const query = request.query as { page: number; pageSize: number };
    const { page, pageSize } = query;
    const skip = (page - 1) * pageSize;
    const organizationId = request.user!.orgId;

    const where = {
      app: { organizationId },
    };

    const [data, total] = await Promise.all([
      fastify.prisma.webhookDelivery.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take: pageSize,
        select: {
          id: true,
          event: true,
          url: true,
          statusCode: true,
          attempts: true,
          deliveredAt: true,
          failedAt: true,
          error: true,
          createdAt: true,
          app: {
            select: { id: true, name: true },
          },
        },
      }),
      fastify.prisma.webhookDelivery.count({ where }),
    ]);

    return reply.send({
      data,
      total,
      page,
      pageSize,
      totalPages: Math.ceil(total / pageSize),
    });
  });
}
