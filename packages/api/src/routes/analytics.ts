import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { analyticsQuerySchema } from '@qrauth/shared';
import { zodValidator } from '../middleware/validate.js';
import { authorize } from '../middleware/authorize.js';
import { rateLimitAuth } from '../middleware/rateLimit.js';
import { PqcHealthService } from '../services/pqc-health.js';
import { paginationSkip } from '../lib/pagination.js';
import { notFoundError } from '../lib/responses.js';
import { z } from 'zod';
import { Readable } from 'node:stream';
import { analyticsGate, gateRefusalBody } from '../config/plan-limits.js';
import {
  breakdownQuerySchema,
  codeAnalyticsQuerySchema,
  resolveRange,
  timeSeriesQuerySchema,
  analyticsRangeQuerySchema,
} from '../lib/analytics-range.js';
import {
  BREAKDOWN_DIMENSIONS,
  breakdown,
  heatmap,
  lastSevenDays,
  timeSeries,
  type AnalyticsScope,
  type BreakdownDimension,
  type DayRange,
  type Granularity,
} from '../services/scan-analytics.js';
import { scanCsvLines } from '../services/scan-export.js';
import { auditContext, recordAudit } from '../services/audit.js';

/** What an audit entry records about a fraud incident (never its raw details). */
function incidentSummary(incident: { qrCodeId: string; type: string; severity: string }) {
  return { qrCodeId: incident.qrCodeId, type: incident.type, severity: incident.severity };
}

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
  const pqcHealthService = new PqcHealthService(fastify.prisma);

  // -------------------------------------------------------------------------
  // GET /pqc-health — Operational visibility into the PQC migration state
  //
  // Aggregates QR alg-version distribution, stuck pending rows, passkey
  // bridge coverage, MAC key rotation watchdog, and signed batch counts
  // for the calling user's organization. Returns a green/yellow/red
  // status plus a human-readable warning list.
  //
  // Available to every role above VIEWER so any team member can see
  // whether the PQC stack is healthy without admin permissions. The
  // response carries no sensitive material — only counts.
  // -------------------------------------------------------------------------

  fastify.get('/pqc-health', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER')],
  }, async (request, reply) => {
    const report = await pqcHealthService.getOrgHealth(request.user!.orgId);
    return reply.send(report);
  });

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
    const skip = paginationSkip(page, pageSize);
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
          country: true,
          city: true,
          deviceType: true,
          os: true,
          browser: true,
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

    // Grouped in SQL by coordinates rounded to 3 decimals (~111 m), capped
    // (ADR-0006): the scans themselves are never loaded.
    const buckets = await heatmap(fastify.prisma, organizationId);

    return reply.send({ data: buckets, total: buckets.length });
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
    const skip = paginationSkip(page, pageSize);
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

    // Shadow incidents (from fraud rules under superadmin review) are internal
    // and never part of any customer-facing list, count or stat.
    const where = {
      qrCode: { organizationId },
      shadow: false,
      ...(severity !== undefined ? { severity } : {}),
      ...(resolved !== undefined ? { resolved } : {}),
      ...dateFilter,
    };

    // Stat cards + type donut are org-wide KPIs computed over the FULL incident
    // set (date-filtered if a range is set) — NOT the current page and NOT the
    // severity/resolved table filters. The dashboard previously derived these
    // from the paginated rows, so they were wrong as soon as there was >1 page.
    const statsWhere = { qrCode: { organizationId }, shadow: false, ...dateFilter };

    const [data, total, activeCount, criticalCount, highCount, typeGroups] = await Promise.all([
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
      fastify.prisma.fraudIncident.count({ where: { ...statsWhere, resolved: false } }),
      fastify.prisma.fraudIncident.count({ where: { ...statsWhere, resolved: false, severity: 'CRITICAL' } }),
      fastify.prisma.fraudIncident.count({ where: { ...statsWhere, resolved: false, severity: 'HIGH' } }),
      fastify.prisma.fraudIncident.groupBy({
        by: ['type'],
        where: statsWhere,
        _count: { _all: true },
      }),
    ]);

    return reply.send({
      data,
      total,
      page,
      pageSize,
      totalPages: Math.ceil(total / pageSize),
      stats: {
        active: activeCount,
        critical: criticalCount,
        high: highCount,
        byType: typeGroups.map((g) => ({ type: g.type, count: g._count._all })),
      },
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
      where: { id, qrCode: { organizationId }, shadow: false },
      include: {
        qrCode: { select: { token: true, label: true, destinationUrl: true, latitude: true, longitude: true } },
        scan: { select: { id: true, clientIpHash: true, clientLat: true, clientLng: true, userAgent: true, trustScore: true, createdAt: true } },
      },
    });

    if (!incident) {
      return reply.status(404).send(notFoundError('Incident'));
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
      where: { id, qrCode: { organizationId }, shadow: false },
    });
    if (!incident) return reply.status(404).send(notFoundError('Incident'));

    const ctx = auditContext(request);
    // Acknowledging twice changes nothing and writes no entry; the
    // condition also makes concurrent calls write one entry.
    const updated = await fastify.prisma.$transaction(async (tx) => {
      const { count } = await tx.fraudIncident.updateMany({
        where: { id, acknowledgedAt: null },
        data: { acknowledgedAt: new Date() },
      });
      if (count > 0) {
        await recordAudit(tx, ctx, {
          organizationId,
          action: 'fraudIncident.acknowledge',
          resource: 'FraudIncident',
          resourceId: id,
          metadata: incidentSummary(incident),
        });
      }
      return tx.fraudIncident.findUniqueOrThrow({ where: { id } });
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
      where: { id, qrCode: { organizationId }, shadow: false },
    });
    if (!incident) return reply.status(404).send(notFoundError('Incident'));

    const ctx = auditContext(request);
    // Resolving a resolved incident changes nothing and writes no entry.
    const updated = await fastify.prisma.$transaction(async (tx) => {
      const { count } = await tx.fraudIncident.updateMany({
        where: { id, resolved: false },
        data: {
          resolved: true,
          resolvedAt: new Date(),
          resolvedBy: request.user!.id,
          resolutionNote: body?.note || null,
        },
      });
      if (count > 0) {
        await recordAudit(tx, ctx, {
          organizationId,
          action: 'fraudIncident.resolve',
          resource: 'FraudIncident',
          resourceId: id,
          metadata: { ...incidentSummary(incident), hasNote: Boolean(body?.note) },
        });
      }
      return tx.fraudIncident.findUniqueOrThrow({ where: { id } });
    });

    return reply.send(updated);
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
      return reply.status(404).send(notFoundError('QR code'));
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
      trustHigh,
      trustMedium,
      trustLow,
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
          shadow: false,
        },
      }),

      fastify.prisma.scan.aggregate({
        where: { qrCode: { organizationId } },
        _avg: { trustScore: true },
      }),

      // Trust-score distribution over ALL of the org's scans (not the current
      // analytics page). Bucket boundaries match the dashboard donut:
      // high ≥ 80, medium 50–79, low < 50.
      fastify.prisma.scan.count({
        where: { qrCode: { organizationId }, trustScore: { gte: 80 } },
      }),
      fastify.prisma.scan.count({
        where: { qrCode: { organizationId }, trustScore: { gte: 50, lt: 80 } },
      }),
      fastify.prisma.scan.count({
        where: { qrCode: { organizationId }, trustScore: { lt: 50 } },
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
    // Daily totals of the last 7 UTC days for the overview sparkline, on
    // every plan (ADR-0006 D6, D7).
    const scansDaily7d = (await lastSevenDays(fastify.prisma, organizationId)).map(({ date, total }) => ({ date, total }));

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
      trustDistribution: { high: trustHigh, medium: trustMedium, low: trustLow },
      // Auth
      totalAuthSessions,
      authSessionsApproved,
      authSessionsLast7d,
      totalApps,
      scansDaily7d,
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
    const skip = paginationSkip(page, pageSize);
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

  // -------------------------------------------------------------------------
  // Scan analytics (ADR-0006): time series, breakdowns, per-code analytics
  // and CSV export. Paid plans (D6), enforced here.
  // -------------------------------------------------------------------------

  const ANALYTICS_ROLES = ['OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER'] as const;

  /** Sends the 403 for a plan without paid analytics; true when refused. */
  async function refuseUnlessPaid(organizationId: string, reply: FastifyReply): Promise<boolean> {
    const org = await fastify.prisma.organization.findUnique({ where: { id: organizationId }, select: { plan: true } });
    const refusal = analyticsGate(org?.plan);
    if (!refusal) return false;
    await reply.status(403).send(gateRefusalBody(refusal));
    return true;
  }

  /** The day range of the query, or a 400 sent (null). */
  async function rangeOrRefuse(query: { from?: string; to?: string }, reply: FastifyReply): Promise<DayRange | null> {
    const range = resolveRange(query);
    if ('error' in range) {
      await reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: range.error });
      return null;
    }
    return range;
  }

  /** Scope for the organisation, narrowed to one of its codes; null after a 404. */
  async function scopeOrNotFound(
    organizationId: string,
    token: string | undefined,
    reply: FastifyReply,
  ): Promise<{ scope: AnalyticsScope; qrCode: { token: string; label: string | null } | null } | null> {
    if (!token) return { scope: { organizationId }, qrCode: null };
    const qrCode = await fastify.prisma.qRCode.findFirst({
      where: { token, organizationId },
      select: { id: true, token: true, label: true },
    });
    if (!qrCode) {
      await reply.status(404).send(notFoundError('QR code not found'));
      return null;
    }
    return { scope: { organizationId, qrCodeId: qrCode.id }, qrCode: { token: qrCode.token, label: qrCode.label } };
  }

  // GET /timeseries — scans per day or ISO week (Monday) over a UTC day range
  fastify.get('/timeseries', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize(...ANALYTICS_ROLES)],
    preValidation: zodValidator({ querystring: timeSeriesQuerySchema }),
  }, async (request, reply) => {
    const organizationId = request.user!.orgId;
    const query = request.query as { from?: string; to?: string; token?: string; granularity: Granularity };
    if (await refuseUnlessPaid(organizationId, reply)) return reply;
    const range = await rangeOrRefuse(query, reply);
    if (!range) return reply;
    const target = await scopeOrNotFound(organizationId, query.token, reply);
    if (!target) return reply;
    const points = await timeSeries(fastify.prisma, target.scope, range, query.granularity);
    return reply.send({
      granularity: query.granularity,
      ...range,
      total: points.reduce((sum, p) => sum + p.total, 0),
      unique: points.reduce((sum, p) => sum + p.unique, 0),
      points,
    });
  });

  // GET /breakdown — scans per country, city, device type, OS or browser
  fastify.get('/breakdown', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize(...ANALYTICS_ROLES)],
    preValidation: zodValidator({ querystring: breakdownQuerySchema }),
  }, async (request, reply) => {
    const organizationId = request.user!.orgId;
    const query = request.query as { from?: string; to?: string; token?: string; dimension: BreakdownDimension };
    if (await refuseUnlessPaid(organizationId, reply)) return reply;
    const range = await rangeOrRefuse(query, reply);
    if (!range) return reply;
    const target = await scopeOrNotFound(organizationId, query.token, reply);
    if (!target) return reply;
    return reply.send({ ...range, ...(await breakdown(fastify.prisma, target.scope, range, query.dimension)) });
  });

  // GET /qrcodes/:token — one code: totals, series and the four breakdowns
  fastify.get('/qrcodes/:token', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize(...ANALYTICS_ROLES)],
    preValidation: zodValidator({ querystring: codeAnalyticsQuerySchema }),
  }, async (request, reply) => {
    const organizationId = request.user!.orgId;
    const { token } = request.params as { token: string };
    const query = request.query as { from?: string; to?: string; granularity: Granularity };
    if (await refuseUnlessPaid(organizationId, reply)) return reply;
    const range = await rangeOrRefuse(query, reply);
    if (!range) return reply;
    const target = await scopeOrNotFound(organizationId, token, reply);
    if (!target) return reply;
    const CODE_BREAKDOWN_LIMIT = 10;
    const dims = BREAKDOWN_DIMENSIONS.filter((d) => d !== 'city');
    const [points, ...parts] = await Promise.all([
      timeSeries(fastify.prisma, target.scope, range, query.granularity),
      ...dims.map((d) => breakdown(fastify.prisma, target.scope, range, d, new Date(), CODE_BREAKDOWN_LIMIT)),
    ]);
    return reply.send({
      qrCode: target.qrCode,
      granularity: query.granularity,
      ...range,
      total: points.reduce((sum, p) => sum + p.total, 0),
      unique: points.reduce((sum, p) => sum + p.unique, 0),
      points,
      breakdowns: Object.fromEntries(parts.map((b) => [b.dimension, { total: b.total, items: b.items, other: b.other }])),
    });
  });

  // GET /export.csv — scans in the range as CSV, streamed
  fastify.get('/export.csv', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize(...ANALYTICS_ROLES)],
    preValidation: zodValidator({ querystring: analyticsRangeQuerySchema }),
  }, async (request, reply) => {
    const organizationId = request.user!.orgId;
    const query = request.query as { from?: string; to?: string; token?: string };
    if (await refuseUnlessPaid(organizationId, reply)) return reply;
    const range = await rangeOrRefuse(query, reply);
    if (!range) return reply;
    const target = await scopeOrNotFound(organizationId, query.token, reply);
    if (!target) return reply;
    const name = `qrauth-scans-${target.qrCode ? `${target.qrCode.token}-` : ''}${range.from}-to-${range.to}.csv`;
    return reply
      .header('Content-Type', 'text/csv; charset=utf-8')
      .header('Content-Disposition', `attachment; filename="${name}"`)
      .header('Cache-Control', 'no-store')
      .send(Readable.from(scanCsvLines(fastify.prisma, target.scope, range)));
  });
}
