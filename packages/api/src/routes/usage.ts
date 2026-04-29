import type { FastifyInstance } from 'fastify';
import { rateLimitAuth } from '../middleware/rateLimit.js';
import { authorize } from '../middleware/authorize.js';
import { UsageService } from '../services/usage.js';

export default async function usageRoutes(fastify: FastifyInstance): Promise<void> {
  const { authenticate } = fastify;
  const usageService = new UsageService(fastify.prisma);

  fastify.get('/', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER')],
  }, async (request, reply) => {
    const org = await fastify.prisma.organization.findUnique({
      where: { id: request.user!.orgId },
      select: { plan: true },
    });

    const plan = org?.plan || 'FREE';
    const usage = await usageService.getUsage(request.user!.orgId);
    const limits = usageService.getLimits(plan);

    return reply.send({
      plan,
      period: usage.period,
      usage: {
        qrCodes: { current: usage.qrCodes, limit: limits.qrCodes },
        verifications: { current: usage.verifications, limit: limits.verifications },
        authSessions: { current: usage.authSessions, limit: limits.authSessions },
      },
    });
  });
}
