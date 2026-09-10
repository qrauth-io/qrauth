import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { rateLimitAuth } from '../middleware/rateLimit.js';
import { zodValidator } from '../middleware/validate.js';
import { sendKycApprovedEmail, sendKycRejectedEmail } from '../lib/email.js';
import { isAdminEmail } from '../lib/admin.js';
import { paginationSkip } from '../lib/pagination.js';
import { notFoundError } from '../lib/responses.js';
import { AuditLogService } from '../services/audit.js';

// Superadmin org-plan control (FREE | PRO | ENTERPRISE). Scoped to
// Organization.plan ONLY — trustLevel / kycStatus are KYC-gated by a
// ratified decision and deliberately untouched here.
export const adminPlanChangeSchema = z
  .object({
    plan: z.enum(['FREE', 'PRO', 'ENTERPRISE']),
    // Required only when the org has an active Stripe subscription — the
    // subscription guard surfaces a 409 first, then the client retries with
    // this flag set.
    confirmStripeOverride: z.boolean().optional(),
  })
  .strict();
export type AdminPlanChangeBody = z.infer<typeof adminPlanChangeSchema>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * preHandler guard — returns a 403 when the authenticated user is not in the
 * admin email list. Must be placed after `authenticate` in the preHandler
 * chain so `request.user` is already populated. Fails closed when
 * `ADMIN_EMAILS` is unset.
 */
async function requireAdmin(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  if (!request.user || !isAdminEmail(request.user.email)) {
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
    const skip = paginationSkip(page, pageSize);

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
      return reply.status(404).send(notFoundError('Organization', orgId));
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
      return reply.status(404).send(notFoundError('Organization', orgId));
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

  // -------------------------------------------------------------------------
  // GET /organizations — List every organization with usage stats.
  //
  // Query params:
  //   q        – optional free-text search over name / email / slug / domain
  //   plan     – optional Plan filter (FREE | PRO | ENTERPRISE)
  //   page     – 1-based page number (default 1)
  //   pageSize – records per page (default 20, max 100)
  // -------------------------------------------------------------------------

  fastify.get('/organizations', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, requireAdmin],
  }, async (request, reply) => {
    const { q, plan, domainStatus, page: rawPage, pageSize: rawPageSize } = request.query as {
      q?: string;
      plan?: string;
      // Server-side domain filter so the admin Domain Verification view can page
      // the FULL set (it previously fetched only page 1 of 100 and filtered
      // client-side, so domains outside the newest 100 were unreachable):
      //   verified   – has a domain, domainVerified = true
      //   unverified – has a domain, domainVerified = false
      //   missing    – no domain set
      domainStatus?: string;
      page?: string;
      pageSize?: string;
    };

    const page = Math.max(1, parseInt(rawPage ?? '1', 10) || 1);
    const pageSize = Math.min(100, Math.max(1, parseInt(rawPageSize ?? '20', 10) || 20));
    const skip = paginationSkip(page, pageSize);

    const validPlans = ['FREE', 'PRO', 'ENTERPRISE'];
    const where: Record<string, unknown> = {};
    if (plan && validPlans.includes(plan)) {
      where.plan = plan;
    }
    if (domainStatus === 'verified') {
      where.domain = { not: null };
      where.domainVerified = true;
    } else if (domainStatus === 'unverified') {
      where.domain = { not: null };
      where.domainVerified = false;
    } else if (domainStatus === 'missing') {
      where.domain = null;
    }
    if (q && q.trim()) {
      const term = q.trim();
      where.OR = [
        { name: { contains: term, mode: 'insensitive' } },
        { email: { contains: term, mode: 'insensitive' } },
        { slug: { contains: term, mode: 'insensitive' } },
        { domain: { contains: term, mode: 'insensitive' } },
      ];
    }

    const [organizations, total] = await Promise.all([
      fastify.prisma.organization.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take: pageSize,
        select: {
          id: true,
          name: true,
          slug: true,
          email: true,
          billingEmail: true,
          domain: true,
          domainVerified: true,
          trustLevel: true,
          kycStatus: true,
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
      fastify.prisma.organization.count({ where }),
    ]);

    const orgIds = organizations.map((o) => o.id);
    const scanRows = orgIds.length
      ? await fastify.prisma.$queryRaw<Array<{ organizationId: string; count: bigint }>>`
          SELECT q."organizationId", COUNT(s.id)::bigint AS count
          FROM scans s
          INNER JOIN qr_codes q ON s."qrCodeId" = q.id
          WHERE q."organizationId" = ANY(${orgIds}::text[])
          GROUP BY q."organizationId"
        `
      : [];
    const scansByOrg = new Map<string, number>(
      scanRows.map((row) => [row.organizationId, Number(row.count)]),
    );

    return reply.send({
      data: organizations.map((o) => ({
        ...o,
        scanCount: scansByOrg.get(o.id) ?? 0,
      })),
      pagination: {
        total,
        page,
        pageSize,
        totalPages: Math.ceil(total / pageSize),
      },
    });
  });

  // -------------------------------------------------------------------------
  // POST /organizations/:orgId/verify-domain — Superadmin override:
  // mark the org's domain as verified WITHOUT performing a DNS lookup.
  //
  // Use when the org cannot add a DNS TXT record (e.g. shared hosting,
  // enterprise customer verified out-of-band). Audit trail is preserved
  // via kycData.domainVerification.
  // -------------------------------------------------------------------------

  fastify.post('/organizations/:orgId/verify-domain', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, requireAdmin],
  }, async (request, reply) => {
    const { orgId } = request.params as { orgId: string };
    const body = (request.body ?? {}) as { note?: string };

    const existing = await fastify.prisma.organization.findUnique({
      where: { id: orgId },
      select: { id: true, domain: true, kycData: true },
    });

    if (!existing) {
      return reply.status(404).send(notFoundError('Organization', orgId));
    }

    if (!existing.domain) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Organization has no domain set; update the org domain before verifying.',
      });
    }

    const updatedKycData = {
      ...(existing.kycData as Record<string, unknown> | null ?? {}),
      domainVerification: {
        verifiedBy: request.user!.email,
        verifiedAt: new Date().toISOString(),
        method: 'superadmin-override',
        ...(body.note !== undefined ? { note: body.note } : {}),
      },
    };

    const org = await fastify.prisma.organization.update({
      where: { id: orgId },
      data: {
        domainVerified: true,
        domainVerifyToken: null,
        kycData: updatedKycData,
      },
      select: {
        id: true,
        name: true,
        domain: true,
        domainVerified: true,
        updatedAt: true,
      },
    });

    return reply.send({ verified: true, organization: org });
  });

  // -------------------------------------------------------------------------
  // POST /organizations/:orgId/unverify-domain — Reverse a prior
  // superadmin domain verification.
  // -------------------------------------------------------------------------

  fastify.post('/organizations/:orgId/unverify-domain', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, requireAdmin],
  }, async (request, reply) => {
    const { orgId } = request.params as { orgId: string };

    const existing = await fastify.prisma.organization.findUnique({
      where: { id: orgId },
      select: { id: true, kycData: true },
    });

    if (!existing) {
      return reply.status(404).send(notFoundError('Organization', orgId));
    }

    const currentKycData = (existing.kycData as Record<string, unknown> | null) ?? {};
    const { domainVerification: _prev, ...rest } = currentKycData;
    const updatedKycData = {
      ...rest,
      domainVerification: {
        revokedBy: request.user!.email,
        revokedAt: new Date().toISOString(),
      },
    };

    const org = await fastify.prisma.organization.update({
      where: { id: orgId },
      data: {
        domainVerified: false,
        kycData: updatedKycData,
      },
      select: {
        id: true,
        name: true,
        domain: true,
        domainVerified: true,
        updatedAt: true,
      },
    });

    return reply.send({ verified: false, organization: org });
  });

  // -------------------------------------------------------------------------
  // PATCH /organizations/:orgId/plan — Superadmin manual plan grant/change.
  //
  // Changes Organization.plan ONLY (FREE | PRO | ENTERPRISE). Never touches
  // trustLevel or kycStatus (KYC-gated, separate ratified decision).
  //
  // Subscription guard: the ONLY automatic writer of `plan` is the Stripe
  // webhook (services/stripe.ts: checkout.session.completed → PRO,
  // subscription.deleted / .updated(canceled) → FREE). An org with a live
  // stripeSubscriptionId can therefore have a manual change silently
  // overwritten by a future billing event, so a manual change to such an org
  // requires an explicit `confirmStripeOverride: true`; without it we 409.
  // No-op (same plan) short-circuits to 200 and skips the audit entry.
  // -------------------------------------------------------------------------

  fastify.patch('/organizations/:orgId/plan', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, requireAdmin],
    preValidation: zodValidator({ body: adminPlanChangeSchema }),
  }, async (request, reply) => {
    const { orgId } = request.params as { orgId: string };
    const body = request.body as AdminPlanChangeBody;

    const existing = await fastify.prisma.organization.findUnique({
      where: { id: orgId },
      select: { id: true, plan: true, stripeSubscriptionId: true },
    });

    if (!existing) {
      return reply.status(404).send(notFoundError('Organization', orgId));
    }

    const hasStripeSubscription = existing.stripeSubscriptionId !== null;
    const from = existing.plan;
    const to = body.plan;

    // No-op: same plan in, same plan out. 200, no mutation, no audit entry.
    if (from === to) {
      return reply.send({
        id: existing.id,
        oldPlan: from,
        newPlan: to,
        hasStripeSubscription,
        noop: true,
      });
    }

    // Subscription guard — refuse to fight billing silently.
    if (hasStripeSubscription && body.confirmStripeOverride !== true) {
      return reply.status(409).send({
        statusCode: 409,
        error: 'Conflict',
        message:
          'This organization has an active Stripe subscription. A manual plan change may be overwritten by a future billing event (e.g. a subscription update or cancellation). Re-submit with confirmStripeOverride: true to proceed anyway.',
        hasStripeSubscription: true,
      });
    }

    const org = await fastify.prisma.organization.update({
      where: { id: orgId },
      data: { plan: to },
      select: { id: true, plan: true },
    });

    const auditService = new AuditLogService(fastify.prisma);
    await auditService.log({
      organizationId: orgId,
      userId: request.user!.id,
      action: 'admin.organization.planChange',
      resource: 'Organization',
      resourceId: orgId,
      metadata: { from, to, confirmStripeOverride: body.confirmStripeOverride === true },
    });

    return reply.send({
      id: org.id,
      oldPlan: from,
      newPlan: org.plan,
      hasStripeSubscription,
    });
  });
}
