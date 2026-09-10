import type { FastifyInstance } from 'fastify';
import { rateLimitAuth } from '../middleware/rateLimit.js';
import { authorize } from '../middleware/authorize.js';
import { UsageService, type UsageMetric, type Limit } from '../services/usage.js';
import { serializeLimit } from '../config/plan-limits.js';

// ---------------------------------------------------------------------------
// Pure response builder (Issue #65)
// ---------------------------------------------------------------------------

interface UsageResponseShape {
  plan: string;
  period: string;
  usage: {
    qrCodes: { current: number; limit: number };
    verifications: { current: number; limit: number };
    authSessions: { current: number; limit: number };
    ephemeralSessions: { current: number; limit: number };
  };
}

/**
 * Build the JSON body for `GET /usage`. Pure function — extracted from
 * the route handler so the wire-format invariants (camelCase keys, the
 * `-1` unlimited sentinel applied via `serializeLimit`) can be unit
 * tested without spinning up Fastify + Prisma + Redis.
 *
 * The `qrCodes` key in the response intentionally diverges from the
 * `qrcodes` metric name. The dashboard predates the lower-case metric
 * convention and the wire shape is stable; renaming would break the
 * UI. Internally the metric is `qrcodes` everywhere else.
 */
export function buildUsageResponse(
  plan: string,
  period: string,
  snapshot: Record<UsageMetric, number>,
  limits: Record<UsageMetric, Limit>,
): UsageResponseShape {
  return {
    plan,
    period,
    usage: {
      qrCodes: { current: snapshot.qrcodes, limit: serializeLimit(limits.qrcodes) },
      verifications: { current: snapshot.verifications, limit: serializeLimit(limits.verifications) },
      authSessions: { current: snapshot.authSessions, limit: serializeLimit(limits.authSessions) },
      ephemeralSessions: { current: snapshot.ephemeralSessions, limit: serializeLimit(limits.ephemeralSessions) },
    },
  };
}

function monthKey(): string {
  const now = new Date();
  return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
}

// ---------------------------------------------------------------------------
// Route
// ---------------------------------------------------------------------------

export default async function usageRoutes(fastify: FastifyInstance): Promise<void> {
  const { authenticate } = fastify;
  const usageService = new UsageService(fastify.prisma, fastify.log);

  fastify.get('/', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER')],
  }, async (request, reply) => {
    const org = await fastify.prisma.organization.findUnique({
      where: { id: request.user!.orgId },
      select: { plan: true },
    });

    const plan = org?.plan || 'FREE';
    const snapshot = await usageService.snapshot(request.user!.orgId);
    const limits = usageService.getLimits(plan);

    return reply.send(buildUsageResponse(plan, monthKey(), snapshot, limits));
  });
}
