import type { FastifyInstance } from 'fastify';
import {
  POLICY_MANAGER_ROLES,
  orgPolicyPreviewSchema,
  orgPolicyUpdateSchema,
  planAllowsGovernance,
} from '@qrauth/shared';
import type { z } from 'zod';

import { GOVERNANCE_PLAN_REQUIRED_CODE, POLICY_PLAN_MESSAGE, gateRefusalBody } from '../config/plan-limits.js';
import { authorize } from '../middleware/authorize.js';
import { rateLimitAuth } from '../middleware/rateLimit.js';
import { zodValidator } from '../middleware/validate.js';
import { auditContext } from '../services/audit.js';
import { assertPolicyManager, PolicyUpdateError, policyView, previewPolicy, updatePolicy } from '../services/org-policy.js';

/**
 * Organization policies (ADR-0008 D8), the caller's organization only,
 * OWNER and ADMIN:
 *   GET  /api/v1/policies          the policy, on every plan (a lower plan
 *                                  still sees a policy it can switch off);
 *   PUT  /api/v1/policies          replace it: Business plan and above, or
 *                                  only switching off below it;
 *   POST /api/v1/policies/preview  how an allowlist would be normalised and
 *                                  which active codes it would leave outside;
 *                                  stores nothing; Business plan and above.
 */
export default async function orgPolicyRoutes(fastify: FastifyInstance): Promise<void> {
  const { authenticate } = fastify;
  const managers = authorize(...POLICY_MANAGER_ROLES);

  fastify.get('/', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, managers],
  }, async (request, reply) => reply.send(await policyView(fastify.prisma, request.user!.orgId)));

  fastify.put('/', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, managers],
    preValidation: zodValidator({ body: orgPolicyUpdateSchema }),
  }, async (request, reply) => {
    const body = request.body as z.output<typeof orgPolicyUpdateSchema>;
    try {
      await updatePolicy(fastify.prisma, request.user!.orgId, body, auditContext(request), request.user!);
    } catch (err) {
      if (err instanceof PolicyUpdateError) return reply.status(err.status).send(err.body);
      throw err;
    }
    return reply.send(await policyView(fastify.prisma, request.user!.orgId));
  });

  fastify.post('/preview', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, managers],
    preValidation: zodValidator({ body: orgPolicyPreviewSchema }),
  }, async (request, reply) => {
    try {
      await assertPolicyManager(fastify.prisma, request.user!);
    } catch (err) {
      if (err instanceof PolicyUpdateError) return reply.status(err.status).send(err.body);
      throw err;
    }
    const org = await fastify.prisma.organization.findUniqueOrThrow({
      where: { id: request.user!.orgId },
      select: { plan: true },
    });
    if (!planAllowsGovernance(org.plan)) {
      return reply.status(403).send(gateRefusalBody({ code: GOVERNANCE_PLAN_REQUIRED_CODE, message: POLICY_PLAN_MESSAGE }));
    }
    const { allowlist } = request.body as z.output<typeof orgPolicyPreviewSchema>;
    return reply.send(await previewPolicy(fastify.prisma, request.user!.orgId, allowlist));
  });
}
