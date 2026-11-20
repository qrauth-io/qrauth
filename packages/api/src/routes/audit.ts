import { Readable } from 'node:stream';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { AUDIT_ACTOR_TYPES, AUDIT_VIEWER_ROLES } from '@qrauth/shared';

import { auditLogGate, gateRefusalBody } from '../config/plan-limits.js';
import { authorize } from '../middleware/authorize.js';
import { rateLimitAuth } from '../middleware/rateLimit.js';
import { zodValidator } from '../middleware/validate.js';
import {
  AUDIT_PAGE_DEFAULT,
  AUDIT_CSV_MAX_ROWS,
  AUDIT_PAGE_MAX,
  InvalidCursorError,
  auditCsvLines,
  countAuditEntries,
  listAuditEntries,
  type AuditFilters,
} from '../services/audit-query.js';

/**
 * GET /api/v1/audit — the organization's audit log (ADR-0008): audit
 * entries and QR code changes, newest first, cursor-paginated; and
 * GET /api/v1/audit/export.csv with the same filters and a required date
 * range, streamed, at most AUDIT_CSV_MAX_ROWS entries. The
 * caller's organization only; OWNER and ADMIN; Business plan and above.
 */

const ID = z.string().trim().min(1).max(128);

const filterFields = {
  actor: ID.optional(),
  actorType: z.enum(AUDIT_ACTOR_TYPES).optional(),
  action: z.string().trim().min(1).max(64).regex(/^[A-Za-z0-9_.]+$/).optional(),
  resourceType: z.string().trim().min(1).max(64).regex(/^[A-Za-z0-9_]+$/).optional(),
  resourceId: ID.optional(),
  from: z.string().datetime({ offset: true }).optional(),
  to: z.string().datetime({ offset: true }).optional(),
};

const rangeInOrder = (q: { from?: string; to?: string }) => !q.from || !q.to || new Date(q.from) <= new Date(q.to);
const RANGE_MESSAGE = { message: '`from` must not be after `to`.' };

/** The export needs a date range (ADR-0008 D7). */
const exportSchema = z
  .object({ ...filterFields, from: filterFields.from.unwrap(), to: filterFields.to.unwrap() })
  .strict()
  .refine(rangeInOrder, RANGE_MESSAGE);

const listSchema = z
  .object({
    ...filterFields,
    cursor: z.string().max(512).optional(),
    limit: z.coerce.number().int().min(1).max(AUDIT_PAGE_MAX).default(AUDIT_PAGE_DEFAULT),
  })
  .strict()
  .refine(rangeInOrder, RANGE_MESSAGE);

type FilterQuery = z.infer<typeof listSchema>;

function toFilters(q: FilterQuery): AuditFilters {
  return {
    actorId: q.actor,
    actorType: q.actorType,
    action: q.action,
    resourceType: q.resourceType,
    resourceId: q.resourceId,
    from: q.from ? new Date(q.from) : undefined,
    to: q.to ? new Date(q.to) : undefined,
  };
}

export const AUDIT_ROLE_MESSAGE = 'The audit log is available to organization owners and admins.';

export default async function auditRoutes(fastify: FastifyInstance): Promise<void> {
  const { authenticate } = fastify;

  /** OWNER/ADMIN, with an explanation instead of the generic 403. */
  async function viewerRole(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    if (request.user && !(AUDIT_VIEWER_ROLES as readonly string[]).includes(request.user.role)) {
      await reply.status(403).send({ statusCode: 403, error: 'Forbidden', code: 'audit-role-required', message: AUDIT_ROLE_MESSAGE });
      return;
    }
    return authorize(...AUDIT_VIEWER_ROLES)(request, reply);
  }

  /** Business plan and above (ADR-0008 D5). */
  async function planGate(request: FastifyRequest, reply: FastifyReply): Promise<void> {
    const org = await fastify.prisma.organization.findUnique({ where: { id: request.user!.orgId }, select: { plan: true } });
    const refusal = auditLogGate(org?.plan);
    if (refusal) await reply.status(403).send(gateRefusalBody(refusal));
  }

  fastify.get('/', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, viewerRole, planGate],
    preValidation: zodValidator({ querystring: listSchema }),
  }, async (request, reply) => {
    const q = request.query as z.infer<typeof listSchema>;
    try {
      return reply.send(await listAuditEntries(fastify.prisma, request.user!.orgId, toFilters(q), { limit: q.limit, cursor: q.cursor }));
    } catch (err) {
      if (err instanceof InvalidCursorError) {
        return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: err.message });
      }
      throw err;
    }
  });

  fastify.get('/export.csv', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, viewerRole, planGate],
    preValidation: zodValidator({ querystring: exportSchema }),
  }, async (request, reply) => {
    const filters = toFilters(request.query as FilterQuery);
    const rows = await countAuditEntries(fastify.prisma, request.user!.orgId, filters);
    if (rows > AUDIT_CSV_MAX_ROWS) {
      return reply.status(422).send({
        statusCode: 422,
        error: 'Unprocessable Entity',
        code: 'audit-export-too-large',
        message: `This export would contain ${rows.toLocaleString('en-US')} entries; one export holds at most ${AUDIT_CSV_MAX_ROWS.toLocaleString('en-US')}. Choose a shorter date range or add filters.`,
        rows,
        maxRows: AUDIT_CSV_MAX_ROWS,
      });
    }
    const day = new Date().toISOString().slice(0, 10);
    return reply
      .header('Content-Type', 'text/csv; charset=utf-8')
      .header('Content-Disposition', `attachment; filename="qrauth-audit-log-${day}.csv"`)
      .header('Cache-Control', 'no-store')
      .send(Readable.from(auditCsvLines(fastify.prisma, request.user!.orgId, filters)));
  });
}
