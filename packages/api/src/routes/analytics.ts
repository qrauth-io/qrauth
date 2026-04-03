import type { FastifyInstance } from 'fastify';
import { analyticsQuerySchema } from '@qrauth/shared';
import { zodValidator } from '../middleware/validate.js';
import { authorize } from '../middleware/authorize.js';
import { rateLimitAuth } from '../middleware/rateLimit.js';
import { z } from 'zod';

// ---------------------------------------------------------------------------
// Local schemas
// ---------------------------------------------------------------------------

const fraudQuerySchema = analyticsQuerySchema.extend({
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
  resolved: z
    .enum(['true', 'false'])
    .transform((v) => v === 'true')
    .optional(),
});

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export default async function analyticsRoutes(fastify: FastifyInstance): Promise<void> {
  const { authenticate } = fastify;

  // -------------------------------------------------------------------------
  // GET /scans — Paginated scan history for issuer's QR codes
  // -------------------------------------------------------------------------

  fastify.get('/scans', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER')],
    preValidation: zodValidator({ querystring: analyticsQuerySchema }),
  }, async (request, reply) => {
    const query = request.query as {
      page: number;
      pageSize: number;
      startDate?: string;
      endDate?: string;
    };

    const { page, pageSize, startDate, endDate } = query;
    const skip = (page - 1) * pageSize;
    const organizationId = request.user!.orgId;

    const dateFilter =
      startDate || endDate
        ? {
            createdAt: {
              ...(startDate ? { gte: new Date(startDate) } : {}),
              ...(endDate ? { lte: new Date(endDate) } : {}),
            },
          }
        : {};

    const where = {
      qrCode: { organizationId },
      ...dateFilter,
    };

    const [data, total] = await Promise.all([
      fastify.prisma.scan.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take: pageSize,
        select: {
          id: true,
          clientIpHash: true,
          clientLat: true,
          clientLng: true,
          trustScore: true,
          proxyDetected: true,
          passkeyVerified: true,
          userAgent: true,
          createdAt: true,
          qrCode: {
            select: { token: true, label: true },
          },
        },
      }),
      fastify.prisma.scan.count({ where }),
    ]);

    return reply.send({
      data,
      total,
      page,
      pageSize,
      totalPages: Math.ceil(total / pageSize),
    });
  });

  // -------------------------------------------------------------------------
  // GET /heatmap — Aggregated scan location density
  // -------------------------------------------------------------------------

  fastify.get('/heatmap', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER')],
  }, async (request, reply) => {
    const organizationId = request.user!.orgId;

    // Fetch all scans for this organization that have lat/lng coordinates.
    const scans = await fastify.prisma.scan.findMany({
      where: {
        qrCode: { organizationId },
        clientLat: { not: null },
        clientLng: { not: null },
      },
      select: {
        clientLat: true,
        clientLng: true,
      },
    });

    // Group by lat/lng rounded to 3 decimal places (~111 m per 0.001 degree).
    const buckets = new Map<string, { lat: number; lng: number; count: number }>();

    for (const scan of scans) {
      if (scan.clientLat === null || scan.clientLng === null) continue;

      const lat = Math.round(scan.clientLat * 1000) / 1000;
      const lng = Math.round(scan.clientLng * 1000) / 1000;
      const key = `${lat},${lng}`;

      const existing = buckets.get(key);
      if (existing) {
        existing.count++;
      } else {
        buckets.set(key, { lat, lng, count: 1 });
      }
    }

    const heatmap = Array.from(buckets.values()).sort((a, b) => b.count - a.count);

    return reply.send({ data: heatmap, total: heatmap.length });
  });

  // -------------------------------------------------------------------------
  // GET /fraud — Fraud incidents for issuer's QR codes
  // -------------------------------------------------------------------------

  fastify.get('/fraud', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER')],
    preValidation: zodValidator({ querystring: fraudQuerySchema }),
  }, async (request, reply) => {
    const query = request.query as {
      page: number;
      pageSize: number;
      startDate?: string;
      endDate?: string;
      severity?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
      resolved?: boolean;
    };

    const { page, pageSize, severity, resolved, startDate, endDate } = query;
    const skip = (page - 1) * pageSize;
    const organizationId = request.user!.orgId;

    const dateFilter =
      startDate || endDate
        ? {
            createdAt: {
              ...(startDate ? { gte: new Date(startDate) } : {}),
              ...(endDate ? { lte: new Date(endDate) } : {}),
            },
          }
        : {};

    const where = {
      qrCode: { organizationId },
      ...(severity !== undefined ? { severity } : {}),
      ...(resolved !== undefined ? { resolved } : {}),
      ...dateFilter,
    };

    const [data, total] = await Promise.all([
      fastify.prisma.fraudIncident.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take: pageSize,
        include: {
          qrCode: {
            select: { token: true, label: true },
          },
        },
      }),
      fastify.prisma.fraudIncident.count({ where }),
    ]);

    return reply.send({
      data,
      total,
      page,
      pageSize,
      totalPages: Math.ceil(total / pageSize),
    });
  });

  // -------------------------------------------------------------------------
  // GET /fraud/:id — Incident detail
  // -------------------------------------------------------------------------

  fastify.get('/fraud/:id', {
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER')],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const organizationId = request.user!.orgId;

    const incident = await fastify.prisma.fraudIncident.findFirst({
      where: { id, qrCode: { organizationId } },
      include: {
        qrCode: { select: { token: true, label: true, destinationUrl: true, latitude: true, longitude: true } },
        scan: { select: { id: true, clientIpHash: true, clientLat: true, clientLng: true, userAgent: true, trustScore: true, createdAt: true } },
      },
    });

    if (!incident) {
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'Incident not found' });
    }

    return reply.send(incident);
  });

  // -------------------------------------------------------------------------
  // POST /fraud/:id/acknowledge — Acknowledge an incident
  // -------------------------------------------------------------------------

  fastify.post('/fraud/:id/acknowledge', {
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER')],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const organizationId = request.user!.orgId;

    const incident = await fastify.prisma.fraudIncident.findFirst({
      where: { id, qrCode: { organizationId } },
    });
    if (!incident) return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'Incident not found' });

    const updated = await fastify.prisma.fraudIncident.update({
      where: { id },
      data: { acknowledgedAt: new Date() },
    });

    return reply.send(updated);
  });

  // -------------------------------------------------------------------------
  // POST /fraud/:id/resolve — Resolve an incident
  // -------------------------------------------------------------------------

  fastify.post('/fraud/:id/resolve', {
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER')],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = request.body as { note?: string } | undefined;
    const organizationId = request.user!.orgId;

    const incident = await fastify.prisma.fraudIncident.findFirst({
      where: { id, qrCode: { organizationId } },
    });
    if (!incident) return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'Incident not found' });

    const updated = await fastify.prisma.fraudIncident.update({
      where: { id },
      data: {
        resolved: true,
        resolvedAt: new Date(),
        resolvedBy: request.user!.id,
        resolutionNote: body?.note || null,
      },
    });

    return reply.send(updated);
  });

  // -------------------------------------------------------------------------
  // GET /fraud-rules — List all dynamic fraud rules
  // -------------------------------------------------------------------------

  fastify.get('/fraud-rules', {
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER')],
  }, async (_request, reply) => {
    const rules = await fastify.prisma.fraudRule.findMany({
      orderBy: { priority: 'asc' },
    });
    return reply.send({ data: rules });
  });

  // -------------------------------------------------------------------------
  // PATCH /fraud-rules/:id — Enable/disable or update a rule
  // -------------------------------------------------------------------------

  fastify.patch('/fraud-rules/:id', {
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = request.body as { enabled?: boolean; conditions?: any; action?: any; priority?: number };

    const rule = await fastify.prisma.fraudRule.update({
      where: { id },
      data: {
        ...(body.enabled !== undefined ? { enabled: body.enabled } : {}),
        ...(body.conditions ? { conditions: body.conditions } : {}),
        ...(body.action ? { action: body.action } : {}),
        ...(body.priority !== undefined ? { priority: body.priority } : {}),
        version: { increment: 1 },
      },
    });

    // Bust the rule cache so changes take effect immediately
    const { cacheDel } = await import('../lib/cache.js');
    await cacheDel('fraud_rules:active');

    return reply.send(rule);
  });

  // -------------------------------------------------------------------------
  // GET /feedback/:token — Get feedback submissions for a QR code
  // -------------------------------------------------------------------------

  fastify.get('/feedback/:token', {
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER')],
  }, async (request, reply) => {
    const { token } = request.params as { token: string };
    const organizationId = request.user!.orgId;

    const qrCode = await fastify.prisma.qRCode.findFirst({
      where: { token, organizationId },
      select: { id: true },
    });

    if (!qrCode) {
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'QR code not found' });
    }

    const submissions = await fastify.prisma.feedbackSubmission.findMany({
      where: { qrCodeId: qrCode.id },
      orderBy: { createdAt: 'desc' },
      take: 100,
    });

    const avgRating = submissions.length > 0
      ? submissions.reduce((sum, s) => sum + s.rating, 0) / submissions.length
      : null;

    return reply.send({
      data: submissions,
      total: submissions.length,
      avgRating: avgRating ? Math.round(avgRating * 10) / 10 : null,
    });
  });

  // -------------------------------------------------------------------------
  // GET /summary — Aggregated dashboard statistics
  // -------------------------------------------------------------------------

  fastify.get('/summary', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER')],
  }, async (request, reply) => {
    const organizationId = request.user!.orgId;
    const now = new Date();
    const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

    const [
      totalQRCodes,
      totalScans,
      scansLast7d,
      scansLast30d,
      activeFraudIncidents,
      avgTrustScoreResult,
      // Auth session stats
      totalAuthSessions,
      authSessionsApproved,
      authSessionsLast7d,
      totalApps,
    ] = await Promise.all([
      fastify.prisma.qRCode.count({
        where: { organizationId },
      }),

      fastify.prisma.scan.count({
        where: { qrCode: { organizationId } },
      }),

      fastify.prisma.scan.count({
        where: {
          qrCode: { organizationId },
          createdAt: { gte: sevenDaysAgo },
        },
      }),

      fastify.prisma.scan.count({
        where: {
          qrCode: { organizationId },
          createdAt: { gte: thirtyDaysAgo },
        },
      }),

      fastify.prisma.fraudIncident.count({
        where: {
          qrCode: { organizationId },
          resolved: false,
        },
      }),

      fastify.prisma.scan.aggregate({
        where: { qrCode: { organizationId } },
        _avg: { trustScore: true },
      }),

      // Auth sessions
      fastify.prisma.authSession.count({
        where: { app: { organizationId } },
      }),

      fastify.prisma.authSession.count({
        where: { app: { organizationId }, status: 'APPROVED' },
      }),

      fastify.prisma.authSession.count({
        where: { app: { organizationId }, createdAt: { gte: sevenDaysAgo } },
      }),

      fastify.prisma.app.count({
        where: { organizationId, status: 'ACTIVE' },
      }),
    ]);

    const avgTrustScore =
      avgTrustScoreResult._avg.trustScore !== null
        ? Math.round(avgTrustScoreResult._avg.trustScore)
        : null;

    return reply.send({
      totalQRCodes,
      totalScans,
      scansLast7d,
      scansLast30d,
      activeFraudIncidents,
      avgTrustScore,
      // Auth
      totalAuthSessions,
      authSessionsApproved,
      authSessionsLast7d,
      totalApps,
    });
  });

  // -------------------------------------------------------------------------
  // GET /auth-sessions — Auth session history for org's apps
  // -------------------------------------------------------------------------

  fastify.get('/auth-sessions', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER')],
    preValidation: zodValidator({ querystring: analyticsQuerySchema }),
  }, async (request, reply) => {
    const query = request.query as {
      page: number;
      pageSize: number;
      startDate?: string;
      endDate?: string;
    };
    const { page, pageSize, startDate, endDate } = query;
    const skip = (page - 1) * pageSize;
    const organizationId = request.user!.orgId;

    const dateFilter =
      startDate || endDate
        ? {
            createdAt: {
              ...(startDate ? { gte: new Date(startDate) } : {}),
              ...(endDate ? { lte: new Date(endDate) } : {}),
            },
          }
        : {};

    const where = {
      app: { organizationId },
      ...dateFilter,
    };

    const [data, total] = await Promise.all([
      fastify.prisma.authSession.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take: pageSize,
        select: {
          id: true,
          status: true,
          scopes: true,
          ipCountry: true,
          ipCity: true,
          deviceFingerprint: true,
          referrer: true,
          scannedAt: true,
          resolvedAt: true,
          createdAt: true,
          app: { select: { name: true, clientId: true } },
          user: { select: { id: true, name: true, email: true } },
        },
      }),
      fastify.prisma.authSession.count({ where }),
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
