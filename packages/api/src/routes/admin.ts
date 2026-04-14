import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { rateLimitAuth } from '../middleware/rateLimit.js';
import { sendKycApprovedEmail, sendKycRejectedEmail } from '../lib/email.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Resolve the list of admin emails from the environment.
 * Returns an empty list when `ADMIN_EMAILS` is unset — no admin access
 * is granted in that case. Fail closed: we'd rather lock the founder
 * out of the admin panel than accidentally grant access in a misconfigured
 * deployment.
 */
function getAdminEmails(): string[] {
  return (process.env.ADMIN_EMAILS ?? '')
    .split(',')
    .map((e) => e.trim())
    .filter(Boolean);
}

/**
 * preHandler guard — returns a 403 when the authenticated user is not in the
 * admin email list.  Must be placed after `authenticate` in the preHandler
 * chain so `request.user` is already populated.
 */
async function requireAdmin(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  if (!request.user || !getAdminEmails().includes(request.user.email)) {
    return reply.status(403).send({
      statusCode: 403,
      error: 'Forbidden',
      message: 'Admin access required',
    });
  }
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export default async function adminRoutes(fastify: FastifyInstance): Promise<void> {
  const authenticate = fastify.authenticate;

  // -------------------------------------------------------------------------
  // GET /kyc-reviews — List organizations with their KYC status
  //
  // Query params:
  //   status   – optional KycStatus filter (PENDING | UNDER_REVIEW | VERIFIED | REJECTED)
  //   page     – 1-based page number (default 1)
  //   pageSize – records per page (default 20, max 100)
  // -------------------------------------------------------------------------

  fastify.get('/kyc-reviews', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, requireAdmin],
  }, async (request, reply) => {
    const { status, page: rawPage, pageSize: rawPageSize } = request.query as {
      status?: string;
      page?: string;
      pageSize?: string;
    };

    const page = Math.max(1, parseInt(rawPage ?? '1', 10) || 1);
    const pageSize = Math.min(100, Math.max(1, parseInt(rawPageSize ?? '20', 10) || 20));
    const skip = (page - 1) * pageSize;

    // Build the optional status filter.  Ignore unknown values to avoid a
    // Prisma runtime error from an invalid enum cast.
    const validStatuses = ['PENDING', 'UNDER_REVIEW', 'VERIFIED', 'REJECTED'];
    const statusFilter =
      status && validStatuses.includes(status)
        ? { kycStatus: status as any }
        : {};

    const [organizations, total] = await Promise.all([
      fastify.prisma.organization.findMany({
        where: statusFilter,
        orderBy: { createdAt: 'desc' },
        skip,
        take: pageSize,
        select: {
          id: true,
          name: true,
          slug: true,
          email: true,
          domain: true,
          domainVerified: true,
          trustLevel: true,
          kycStatus: true,
          kycData: true,
          plan: true,
          createdAt: true,
          _count: {
            select: {
              qrCodes: true,
              memberships: true,
            },
          },
        },
      }),
      fastify.prisma.organization.count({ where: statusFilter }),
    ]);

    return reply.send({
      data: organizations,
      pagination: {
        total,
        page,
        pageSize,
        totalPages: Math.ceil(total / pageSize),
      },
    });
  });

  // -------------------------------------------------------------------------
  // POST /kyc-reviews/:orgId/approve — Approve KYC for an organization
  //
  // Body (optional):
  //   note – freeform string stored in kycData
  // -------------------------------------------------------------------------

  fastify.post('/kyc-reviews/:orgId/approve', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, requireAdmin],
  }, async (request, reply) => {
    const { orgId } = request.params as { orgId: string };
    const body = (request.body ?? {}) as { note?: string };

    const existing = await fastify.prisma.organization.findUnique({
      where: { id: orgId },
      select: { id: true, kycStatus: true, kycData: true },
    });

    if (!existing) {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: `Organization "${orgId}" not found.`,
      });
    }

    const updatedKycData = {
      ...(existing.kycData as Record<string, unknown> | null ?? {}),
      reviewedBy: request.user!.email,
      reviewedAt: new Date().toISOString(),
      ...(body.note !== undefined ? { note: body.note } : {}),
    };

    const org = await fastify.prisma.organization.update({
      where: { id: orgId },
      data: {
        kycStatus: 'VERIFIED',
        kycData: updatedKycData,
      },
      select: {
        id: true,
        name: true,
        slug: true,
        email: true,
        kycStatus: true,
        kycData: true,
        updatedAt: true,
      },
    });

    if (org.email) {
      sendKycApprovedEmail(org.email, org.name).catch((err) => {
        fastify.log.error({ err, orgId }, 'Failed to send KYC approved email');
      });
    }

    return reply.send(org);
  });

  // -------------------------------------------------------------------------
  // POST /kyc-reviews/:orgId/reject — Reject KYC for an organization
  //
  // Body (required):
  //   reason – rejection reason stored in kycData
  // -------------------------------------------------------------------------

  fastify.post('/kyc-reviews/:orgId/reject', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, requireAdmin],
  }, async (request, reply) => {
    const { orgId } = request.params as { orgId: string };
    const body = (request.body ?? {}) as { reason?: string };

    if (!body.reason || typeof body.reason !== 'string' || body.reason.trim() === '') {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: 'A rejection reason is required.',
      });
    }

    const existing = await fastify.prisma.organization.findUnique({
      where: { id: orgId },
      select: { id: true, kycStatus: true, kycData: true },
    });

    if (!existing) {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: `Organization "${orgId}" not found.`,
      });
    }

    const updatedKycData = {
      ...(existing.kycData as Record<string, unknown> | null ?? {}),
      reviewedBy: request.user!.email,
      reviewedAt: new Date().toISOString(),
      reason: body.reason.trim(),
    };

    const org = await fastify.prisma.organization.update({
      where: { id: orgId },
      data: {
        kycStatus: 'REJECTED',
        kycData: updatedKycData,
      },
      select: {
        id: true,
        name: true,
        slug: true,
        email: true,
        kycStatus: true,
        kycData: true,
        updatedAt: true,
      },
    });

    if (org.email) {
      sendKycRejectedEmail(org.email, org.name, body.reason!.trim()).catch((err) => {
        fastify.log.error({ err, orgId }, 'Failed to send KYC rejected email');
      });
    }

    return reply.send(org);
  });
}
