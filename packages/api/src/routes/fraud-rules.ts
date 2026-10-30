import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { FraudRuleStatus, Prisma } from '@prisma/client';
import { z } from 'zod';
import { FRAUD_RULE_STATUSES } from '@qrauth/shared';
import { rateLimitAuth } from '../middleware/rateLimit.js';
import { zodValidator } from '../middleware/validate.js';
// Platform-admin guard, shared with admin.ts — fraud rules are global, not org-scoped.
import { requireAdmin } from '../lib/admin.js';
import { cacheDel } from '../lib/cache.js';
import { notFoundError } from '../lib/responses.js';
import { FRAUD_RULE_CACHE_KEY, ruleStatusData, statusFromEnabled } from '../lib/fraud-rule-status.js';
import { QRAUTH_PLATFORM_ORG_SLUG } from '../lib/oidc-signing-keys.js';
import { AuditLogService } from '../services/audit.js';

/**
 * Superadmin fraud-rule management, registered under /api/v1/analytics:
 *   GET   /fraud-rules
 *   PATCH /fraud-rules/:id                  { enabled?, status?, conditions?, action?, priority? }
 *   GET   /fraud-rules/:id/shadow-summary   shadow incidents recorded by the rule
 *   POST  /fraud-rules/:id/promote          SHADOW → ACTIVE
 *   POST  /fraud-rules/:id/demote           ACTIVE → SHADOW
 *
 * Rules are global, so status changes are audit-logged against the platform
 * organization (falling back to the acting admin's organization when it does
 * not exist, e.g. a local database). Every write busts the engine's rule cache.
 */

const SHADOW_SAMPLE_SIZE = 5;

export const fraudRulePatchSchema = z
  .object({
    enabled: z.boolean().optional(),
    status: z.enum(FRAUD_RULE_STATUSES).optional(),
    conditions: z.array(z.unknown()).optional(),
    action: z.record(z.string(), z.unknown()).optional(),
    priority: z.number().int().optional(),
  })
  .refine(
    (b) => b.enabled === undefined || b.status === undefined || (b.status === 'ACTIVE') === b.enabled,
    { message: 'enabled and status disagree', path: ['status'] },
  );

type FraudRulePatch = z.infer<typeof fraudRulePatchSchema>;

type Transition = { from: FraudRuleStatus; to: FraudRuleStatus; action: string };

const PROMOTE: Transition = { from: 'SHADOW', to: 'ACTIVE', action: 'admin.fraudRule.promote' };
const DEMOTE: Transition = { from: 'ACTIVE', to: 'SHADOW', action: 'admin.fraudRule.demote' };

function shadowIncidentsOf(ruleId: string): Prisma.FraudIncidentWhereInput {
  return { shadow: true, details: { path: ['ruleId'], equals: ruleId } };
}

function conflict(message: string) {
  return { statusCode: 409, error: 'Conflict', message } as const;
}

function patchData(body: FraudRulePatch): Prisma.FraudRuleUpdateInput {
  const status = body.status ?? (body.enabled !== undefined ? statusFromEnabled(body.enabled) : undefined);
  return {
    ...(status ? ruleStatusData(status) : {}),
    ...(body.conditions ? { conditions: body.conditions as Prisma.InputJsonValue } : {}),
    ...(body.action ? { action: body.action as Prisma.InputJsonValue } : {}),
    ...(body.priority !== undefined ? { priority: body.priority } : {}),
    version: { increment: 1 },
  };
}

export default async function fraudRuleRoutes(fastify: FastifyInstance): Promise<void> {
  const { authenticate } = fastify;
  const guard = { config: { rateLimit: rateLimitAuth }, preHandler: [authenticate, requireAdmin] };

  async function auditOrgId(request: FastifyRequest): Promise<string> {
    const platform = await fastify.prisma.organization.findUnique({
      where: { slug: QRAUTH_PLATFORM_ORG_SLUG },
      select: { id: true },
    });
    return platform?.id ?? request.user!.orgId;
  }

  async function audit(
    request: FastifyRequest,
    action: string,
    rule: { id: string; name: string },
    metadata: Record<string, unknown>,
  ): Promise<void> {
    await new AuditLogService(fastify.prisma).log({
      organizationId: await auditOrgId(request),
      userId: request.user!.id,
      action,
      resource: 'FraudRule',
      resourceId: rule.id,
      metadata: { name: rule.name, ...metadata },
      ipAddress: request.ip,
    });
  }

  async function shadowSummary(ruleId: string) {
    const where = shadowIncidentsOf(ruleId);
    const [count, range, samples] = await Promise.all([
      fastify.prisma.fraudIncident.count({ where }),
      fastify.prisma.fraudIncident.aggregate({ where, _min: { createdAt: true }, _max: { createdAt: true } }),
      fastify.prisma.fraudIncident.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        take: SHADOW_SAMPLE_SIZE,
        select: {
          id: true,
          createdAt: true,
          type: true,
          severity: true,
          details: true,
          qrCode: { select: { token: true, organizationId: true } },
        },
      }),
    ]);
    return {
      count,
      firstSeen: range._min.createdAt,
      lastSeen: range._max.createdAt,
      samples: samples.map((s) => ({
        id: s.id,
        createdAt: s.createdAt,
        type: s.type,
        severity: s.severity,
        qrCodeToken: s.qrCode.token,
        organizationId: s.qrCode.organizationId,
        features: (s.details as { features?: unknown } | null)?.features ?? null,
      })),
    };
  }

  /** Guarded single-step transition: refuses unless the rule is in `from`. */
  const transition = (t: Transition) => async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const rule = await fastify.prisma.fraudRule.findUnique({ where: { id } });
    if (!rule) return reply.status(404).send(notFoundError('Fraud rule'));
    if (rule.status !== t.from) {
      return reply.status(409).send(conflict(`Fraud rule is ${rule.status}; only a ${t.from} rule can move to ${t.to}.`));
    }

    // The status condition makes a concurrent transition lose cleanly.
    const { count } = await fastify.prisma.fraudRule.updateMany({
      where: { id, status: t.from },
      data: { ...ruleStatusData(t.to), version: { increment: 1 } },
    });
    if (count === 0) return reply.status(409).send(conflict('Fraud rule status changed concurrently.'));

    await audit(request, t.action, rule, { from: t.from, to: t.to });
    await cacheDel(FRAUD_RULE_CACHE_KEY);
    return reply.send({ ...rule, ...ruleStatusData(t.to), version: rule.version + 1 });
  };

  fastify.get('/fraud-rules', guard, async (_request, reply) => {
    const rules = await fastify.prisma.fraudRule.findMany({ orderBy: { priority: 'asc' } });
    return reply.send({ data: rules });
  });

  fastify.patch('/fraud-rules/:id', {
    ...guard,
    preValidation: zodValidator({ body: fraudRulePatchSchema }),
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = request.body as FraudRulePatch;

    const existing = await fastify.prisma.fraudRule.findUnique({ where: { id } });
    if (!existing) return reply.status(404).send(notFoundError('Fraud rule'));

    const data = patchData(body);
    const rule = await fastify.prisma.fraudRule.update({ where: { id }, data });

    if (data.status && data.status !== existing.status) {
      await audit(request, 'admin.fraudRule.update', existing, { from: existing.status, to: data.status });
    }
    // Bust the rule cache so changes take effect immediately
    await cacheDel(FRAUD_RULE_CACHE_KEY);
    return reply.send(rule);
  });

  fastify.get('/fraud-rules/:id/shadow-summary', guard, async (request, reply) => {
    const { id } = request.params as { id: string };
    const rule = await fastify.prisma.fraudRule.findUnique({ where: { id } });
    if (!rule) return reply.status(404).send(notFoundError('Fraud rule'));
    return reply.send({ rule, shadow: await shadowSummary(id) });
  });

  fastify.post('/fraud-rules/:id/promote', guard, transition(PROMOTE));
  fastify.post('/fraud-rules/:id/demote', guard, transition(DEMOTE));
}
