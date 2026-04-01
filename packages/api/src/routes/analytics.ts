import type { FastifyInstance } from 'fastify';
import { analyticsQuerySchema } from '@vqr/shared';
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

      // Prisma aggregate for average trust score.
      fastify.prisma.scan.aggregate({
        where: { qrCode: { organizationId } },
        _avg: { trustScore: true },
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
    });
  });
}
