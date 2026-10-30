import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { rateLimitAuth } from '../middleware/rateLimit.js';
import { zodValidator } from '../middleware/validate.js';
import { requireAdmin } from '../lib/admin.js';
import { paginationSkip } from '../lib/pagination.js';
import { notFoundError } from '../lib/responses.js';
import { AuditLogService } from '../services/audit.js';
import { cacheDel } from '../lib/cache.js';

/**
 * Superadmin abuse-report review, registered under /api/v1/admin:
 *   GET  /abuse-reports?status=OPEN|RESOLVED|DISMISSED&page=&pageSize=
 *   GET  /abuse-reports/:id
 *   POST /abuse-reports/:id/resolve   { note }
 *   POST /abuse-reports/:id/dismiss   { note }
 *   POST /qrcodes/:token/clear-destination-flag   { note }
 * Resolve, dismiss and flag clearing are audit-logged against the
 * organization concerned.
 */

const STATUSES = ['OPEN', 'RESOLVED', 'DISMISSED'] as const;

const listQuerySchema = z.object({
  status: z.enum(STATUSES).optional(),
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
});

export const abuseResolutionSchema = z
  .object({ note: z.string().trim().min(3).max(1000) })
  .strict();

export default async function adminAbuseRoutes(fastify: FastifyInstance): Promise<void> {
  const { authenticate } = fastify;

  fastify.get('/abuse-reports', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, requireAdmin],
    preValidation: zodValidator({ querystring: listQuerySchema }),
  }, async (request, reply) => {
    const { status, page, pageSize } = request.query as z.infer<typeof listQuerySchema>;
    const where = status ? { status } : {};
    const [data, total] = await Promise.all([
      fastify.prisma.abuseReport.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip: paginationSkip(page, pageSize),
        take: pageSize,
      }),
      fastify.prisma.abuseReport.count({ where }),
    ]);
    return reply.send({
      data,
      pagination: { total, page, pageSize, totalPages: Math.ceil(total / pageSize) },
    });
  });

  fastify.get('/abuse-reports/:id', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, requireAdmin],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const report = await fastify.prisma.abuseReport.findUnique({ where: { id } });
    if (!report) return reply.status(404).send(notFoundError('Abuse report', id));

    // Context for the reviewer: the code and its organization, when they still exist.
    const qrCode = await fastify.prisma.qRCode.findUnique({
      where: { token: report.token },
      select: {
        token: true,
        status: true,
        destinationUrl: true,
        createdAt: true,
        organization: { select: { id: true, name: true, slug: true, suspendedAt: true } },
      },
    });
    return reply.send({ ...report, qrCode });
  });

  const decide = (status: 'RESOLVED' | 'DISMISSED', action: string) => async (
    request: FastifyRequest,
    reply: FastifyReply,
  ) => {
    const { id } = request.params as { id: string };
    const { note } = request.body as z.infer<typeof abuseResolutionSchema>;
    const existing = await fastify.prisma.abuseReport.findUnique({ where: { id } });
    if (!existing) return reply.status(404).send(notFoundError('Abuse report', id));
    if (existing.status !== 'OPEN') {
      return reply.status(409).send({
        statusCode: 409,
        error: 'Conflict',
        message: `Abuse report is already ${existing.status.toLowerCase()}.`,
      });
    }

    const report = await fastify.prisma.abuseReport.update({
      where: { id },
      data: { status, resolvedAt: new Date(), resolvedBy: request.user!.email, resolutionNote: note },
    });

    await new AuditLogService(fastify.prisma).log({
      organizationId: existing.organizationId,
      userId: request.user!.id,
      action,
      resource: 'AbuseReport',
      resourceId: id,
      metadata: { token: existing.token, reason: existing.reason, note },
      ipAddress: request.ip,
    });

    return reply.send(report);
  };

  fastify.post('/abuse-reports/:id/resolve', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, requireAdmin],
    preValidation: zodValidator({ body: abuseResolutionSchema }),
  }, decide('RESOLVED', 'admin.abuseReport.resolve'));

  fastify.post('/abuse-reports/:id/dismiss', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, requireAdmin],
    preValidation: zodValidator({ body: abuseResolutionSchema }),
  }, decide('DISMISSED', 'admin.abuseReport.dismiss'));

  // Clear a Web Risk destination flag (e.g. a false positive). The code
  // verifies normally again on the next scan.
  fastify.post('/qrcodes/:token/clear-destination-flag', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, requireAdmin],
    preValidation: zodValidator({ body: abuseResolutionSchema }),
  }, async (request, reply) => {
    const { token } = request.params as { token: string };
    const { note } = request.body as z.infer<typeof abuseResolutionSchema>;
    const code = await fastify.prisma.qRCode.findUnique({
      where: { token },
      select: { token: true, organizationId: true, destinationFlaggedAt: true, destinationFlagReason: true },
    });
    if (!code) return reply.status(404).send(notFoundError('QR code', token));
    if (!code.destinationFlaggedAt) {
      return reply.status(409).send({ statusCode: 409, error: 'Conflict', message: 'This QR code is not flagged.' });
    }

    await fastify.prisma.qRCode.update({
      where: { token },
      data: { destinationFlaggedAt: null, destinationFlagReason: null },
    });
    try {
      await cacheDel(`verify:${token}`);
    } catch {
      // the verify path reads the flag from the database
    }

    await new AuditLogService(fastify.prisma).log({
      organizationId: code.organizationId,
      userId: request.user!.id,
      action: 'admin.qrcode.clearDestinationFlag',
      resource: 'QRCode',
      resourceId: token,
      metadata: {
        note,
        previousReason: code.destinationFlagReason,
        flaggedAt: code.destinationFlaggedAt.toISOString(),
      },
      ipAddress: request.ip,
    });

    return reply.send({ token, flagged: false });
  });
}
