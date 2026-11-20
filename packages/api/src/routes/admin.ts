import { Prisma } from '@prisma/client';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { PLAN_TIERS } from '@qrauth/shared';
import { rateLimitAuth } from '../middleware/rateLimit.js';
import { zodValidator } from '../middleware/validate.js';
import { sendKycApprovedEmail, sendKycRejectedEmail } from '../lib/email.js';
import { requireAdmin } from '../lib/admin.js';
import { paginationSkip } from '../lib/pagination.js';
import { notFoundError } from '../lib/responses.js';
import { auditContext, recordAudit, type AuditContext, type AuditEvent } from '../services/audit.js';
import { DomainService, type DomainReview } from '../services/domain.js';
import { revokeAllActiveForOrg } from '../services/qr-revocation.js';
import { stripeSubscriptionState, type StripeSubscriptionState } from '../services/stripe.js';
import { systemContext } from '../services/qr-revisions.js';
import { QRAUTH_PLATFORM_ORG_SLUG } from '../lib/oidc-signing-keys.js';

// Superadmin org-plan control (FREE | PRO | BUSINESS | ENTERPRISE). Scoped to
// Organization.plan ONLY — trustLevel / kycStatus are KYC-gated by a
// ratified decision and deliberately untouched here.
// Reason for a superadmin action (suspend, revoke all codes); kept in the audit log.
export const adminReasonSchema = z
  .object({ reason: z.string().trim().min(3).max(500) })
  .strict();

export const adminPlanChangeSchema = z
  .object({
    plan: z.enum(PLAN_TIERS),
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

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

/** The plan-change 409, by what Stripe reports for the stored subscription. */
export function subscriptionGuardMessage(state: StripeSubscriptionState, subscriptionId: string): string {
  switch (state) {
    case 'missing':
      return `Stripe has no subscription ${subscriptionId} in the configured account (a test-mode or old id). It cannot bill or change this plan. Confirm to change the plan and remove the stored id. If this organization does pay, stop and check STRIPE_SECRET_KEY first.`;
    case 'ended':
      return `Subscription ${subscriptionId} has ended in Stripe and cannot bill or change this plan. Confirm to change the plan and remove the stored id.`;
    case 'unknown':
      return 'This organization has a Stripe subscription, and Stripe could not be asked about it. If it is active, a manual plan change may be overwritten by a future billing event. Confirm to change the plan anyway; the subscription is kept.';
    case 'active':
      return 'This organization has an active Stripe subscription. A manual plan change may be overwritten by a future billing event (e.g. a subscription update or cancellation). Confirm to change the plan anyway; the subscription is kept.';
  }
}

export default async function adminRoutes(fastify: FastifyInstance): Promise<void> {
  const authenticate = fastify.authenticate;
  const staff = (request: FastifyRequest): AuditContext => auditContext(request, { superadmin: true });
  const KYC_REVIEW_SELECT = { id: true, name: true, slug: true, email: true, kycStatus: true, kycData: true, updatedAt: true } as const;

  /** Applies an organization update and its staff audit entry in one transaction. */
  async function updateOrgAudited<T>(
    request: FastifyRequest,
    write: (tx: Prisma.TransactionClient) => Promise<T>,
    event: Omit<AuditEvent, 'resource' | 'resourceId'> & { resourceId?: string },
  ): Promise<T> {
    return fastify.prisma.$transaction(async (tx) => {
      const result = await write(tx);
      await recordAudit(tx, staff(request), { resource: 'Organization', resourceId: event.organizationId, ...event });
      return result;
    });
  }
  const domainService = new DomainService(fastify.prisma, fastify.log);

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

    const priorKyc = (existing.kycData as Record<string, unknown> | null) ?? {};
    // Approved already, and no new note: nothing changes, no entry.
    if (existing.kycStatus === 'VERIFIED' && (body.note === undefined || body.note === priorKyc.note)) {
      return reply.send(await fastify.prisma.organization.findUniqueOrThrow({ where: { id: orgId }, select: KYC_REVIEW_SELECT }));
    }

    const updatedKycData = {
      ...priorKyc,
      reviewedBy: request.user!.email,
      reviewedAt: new Date().toISOString(),
      ...(body.note !== undefined ? { note: body.note } : {}),
    };

    const org = await updateOrgAudited(request, (tx) => tx.organization.update({
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
    }), {
      organizationId: orgId,
      action: 'admin.organization.kycApproved',
      metadata: { from: existing.kycStatus, ...(body.note !== undefined ? { note: body.note } : {}) },
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

    const priorKyc = (existing.kycData as Record<string, unknown> | null) ?? {};
    // Rejected already, for the same reason: nothing changes, no entry.
    if (existing.kycStatus === 'REJECTED' && priorKyc.reason === body.reason.trim()) {
      return reply.send(await fastify.prisma.organization.findUniqueOrThrow({ where: { id: orgId }, select: KYC_REVIEW_SELECT }));
    }

    const updatedKycData = {
      ...priorKyc,
      reviewedBy: request.user!.email,
      reviewedAt: new Date().toISOString(),
      reason: body.reason.trim(),
    };

    const org = await updateOrgAudited(request, (tx) => tx.organization.update({
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
    }), {
      organizationId: orgId,
      action: 'admin.organization.kycRejected',
      metadata: { from: existing.kycStatus, reason: body.reason.trim() },
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
      //   pending_review – held as a possible lookalike (ADR-0007 D9)
      domainStatus?: string;
      page?: string;
      pageSize?: string;
    };

    const page = Math.max(1, parseInt(rawPage ?? '1', 10) || 1);
    const pageSize = Math.min(100, Math.max(1, parseInt(rawPageSize ?? '20', 10) || 20));
    const skip = paginationSkip(page, pageSize);

    const validPlans: readonly string[] = PLAN_TIERS;
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
    } else if (domainStatus === 'pending_review') {
      where.domainReviewStatus = 'PENDING_REVIEW';
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
          domainReviewStatus: true,
          domainReview: true,
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

    // The override is reviewed like any verification: a lookalike of a
    // protected domain is held for an explicit approve or reject (ADR-0007
    // D9). The override record and the audit entry commit with the outcome.
    const outcome = await domainService.applyDomainVerification(orgId, 'admin_override', async (tx, result) => {
      await tx.organization.update({ where: { id: orgId }, data: { domainVerifyToken: null, kycData: updatedKycData } });
      await recordAudit(tx, staff(request), {
        organizationId: orgId,
        action: result.pendingReview ? 'admin.organization.domainHeldForReview' : 'admin.organization.domainVerified',
        resource: 'Organization',
        resourceId: orgId,
        metadata: {
          domain: result.domain ?? existing.domain,
          source: 'admin_override',
          ...(result.pendingReview ? { matches: result.matches } : {}),
          ...(body.note !== undefined ? { note: body.note } : {}),
        },
      });
    });
    if (!outcome.verified) {
      return reply.status(409).send({
        statusCode: 409,
        error: 'Conflict',
        code: outcome.pendingReview ? 'domain-review-required' : 'domain-review-rejected',
        message: outcome.pendingReview
          ? 'This domain resembles a protected domain and is held for review. Approve or reject it in Domains.'
          : 'This domain was rejected in review.',
        matches: outcome.matches ?? [],
      });
    }
    const org = await fastify.prisma.organization.findUniqueOrThrow({
      where: { id: orgId },
      select: { id: true, name: true, domain: true, domainVerified: true, updatedAt: true },
    });

    return reply.send({ verified: true, organization: org });
  });

  // -------------------------------------------------------------------------
  // POST /organizations/:orgId/domain-review/approve | reject — Decide a
  // domain held as a possible lookalike (ADR-0007 D9). Approve: the domain
  // is verified if ownership was established (DNS or override), otherwise
  // the organization can now complete DNS verification; the organization's
  // own codes on it are then not flagged as lookalikes (D10). Reject: it
  // cannot be verified while it stays the organization's domain; rejecting
  // an approved domain revokes the approval and its exemption. Audit-logged.
  // -------------------------------------------------------------------------

  const domainDecisionSchema = z.object({ note: z.string().trim().max(500).optional() }).strict();

  for (const decision of ['approve', 'reject'] as const) {
    fastify.post(`/organizations/:orgId/domain-review/${decision}`, {
      config: { rateLimit: rateLimitAuth },
      preHandler: [authenticate, requireAdmin],
      preValidation: zodValidator({ body: domainDecisionSchema }),
    }, async (request, reply) => {
      const { orgId } = request.params as { orgId: string };
      const { note } = (request.body ?? {}) as { note?: string };
      const org = await fastify.prisma.organization.findUnique({
        where: { id: orgId },
        select: { id: true, domain: true, domainReviewStatus: true, domainReview: true },
      });
      if (!org) return reply.status(404).send(notFoundError('Organization', orgId));
      const review = org.domainReview as DomainReview | null;
      // Approve a pending review; reject a pending review or revoke an approval.
      const decidable = decision === 'approve'
        ? org.domainReviewStatus === 'PENDING_REVIEW'
        : org.domainReviewStatus === 'PENDING_REVIEW' || org.domainReviewStatus === 'APPROVED';
      if (!decidable || !review) {
        return reply.status(409).send({
          statusCode: 409,
          error: 'Conflict',
          code: 'no-pending-review',
          message: decision === 'approve' ? 'This domain is not waiting for review.' : 'This domain has no pending review or approval to reject.',
        });
      }
      const decided: DomainReview = {
        ...review,
        decision: decision === 'approve' ? 'approved' : 'rejected',
        decidedBy: request.user!.email,
        decidedAt: new Date().toISOString(),
        ...(note ? { note } : {}),
      };
      const verified = decision === 'approve' && review.ownershipProven;
      const updated = await updateOrgAudited(request, (tx) => tx.organization.update({
        where: { id: orgId },
        data: {
          domainReviewStatus: decision === 'approve' ? 'APPROVED' : 'REJECTED',
          domainReview: decided as never,
          domainVerified: verified,
        },
        select: { id: true, name: true, domain: true, domainVerified: true, domainReviewStatus: true, domainReview: true },
      }), {
        organizationId: orgId,
        action: decision === 'approve'
          ? 'admin.organization.domainReviewApproved'
          : org.domainReviewStatus === 'APPROVED' ? 'admin.organization.domainApprovalRevoked' : 'admin.organization.domainReviewRejected',
        metadata: { domain: review.domain, matches: review.matches, source: review.source, verified, ...(note ? { note } : {}) },
      });
      return reply.send({ organization: updated });
    });
  }

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
      select: { id: true, domain: true, domainVerified: true, kycData: true, domainReviewStatus: true },
    });

    if (!existing) {
      return reply.status(404).send(notFoundError('Organization', orgId));
    }

    // Not verified and nothing under review: nothing to remove, no entry.
    if (!existing.domainVerified && existing.domainReviewStatus === null) {
      return reply.send({ verified: false, organization: { id: existing.id, domain: existing.domain, domainVerified: false } });
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

    const org = await updateOrgAudited(request, (tx) => tx.organization.update({
      where: { id: orgId },
      data: {
        domainVerified: false,
        kycData: updatedKycData,
        // An approval (or pending hold) ends with the verification, so
        // verifying again runs the lookalike review again (ADR-0007 D10). A
        // rejection stays: revoking a verification never undoes it.
        ...(existing.domainReviewStatus !== 'REJECTED' ? { domainReviewStatus: null, domainReview: Prisma.DbNull } : {}),
      },
      select: {
        id: true,
        name: true,
        domain: true,
        domainVerified: true,
        updatedAt: true,
      },
    }), {
      organizationId: orgId,
      action: 'admin.organization.domainUnverified',
      metadata: { domain: existing.domain, wasVerified: existing.domainVerified },
    });

    return reply.send({ verified: false, organization: org });
  });

  // -------------------------------------------------------------------------
  // PATCH /organizations/:orgId/plan — Superadmin manual plan grant/change.
  //
  // Changes Organization.plan ONLY (FREE | PRO | BUSINESS | ENTERPRISE). Never touches
  // trustLevel or kycStatus (KYC-gated, separate ratified decision).
  //
  // Subscription guard: the ONLY automatic writer of `plan` is the Stripe
  // webhook (services/stripe.ts: checkout.session.completed → PRO,
  // subscription.deleted / .updated(canceled) → FREE). An org with a live
  // stripeSubscriptionId can therefore have a manual change silently
  // overwritten by a future billing event, so a manual change to such an org
  // requires an explicit `confirmStripeOverride: true`; without it we 409.
  // The 409 says what Stripe reports for the id (active, ended, missing,
  // unknown). A confirmed change to an org whose id Stripe reports missing or
  // ended also removes the id; an active or unknown one is kept.
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

    // Subscription guard — refuse to fight billing silently. Stripe is asked
    // what the stored id is, so the warning says what will happen; nothing
    // changes without confirmStripeOverride.
    const stripeState: StripeSubscriptionState | null = existing.stripeSubscriptionId
      ? await stripeSubscriptionState(existing.stripeSubscriptionId)
      : null;
    if (stripeState && body.confirmStripeOverride !== true) {
      return reply.status(409).send({
        statusCode: 409,
        error: 'Conflict',
        message: subscriptionGuardMessage(stripeState, existing.stripeSubscriptionId!),
        hasStripeSubscription: true,
        stripeSubscriptionState: stripeState,
      });
    }
    // Confirmed: an id Stripe reports as missing or ended cannot bill or send
    // events again, so it is removed with the change (and named in the audit
    // entry). An active or unknown one is kept.
    const clearSubscription = stripeState === 'missing' || stripeState === 'ended';

    const org = await updateOrgAudited(request, (tx) => tx.organization.update({
      where: { id: orgId },
      data: { plan: to, ...(clearSubscription ? { stripeSubscriptionId: null } : {}) },
      select: { id: true, plan: true },
    }), {
      organizationId: orgId,
      action: 'admin.organization.planChange',
      metadata: {
        from,
        to,
        confirmStripeOverride: body.confirmStripeOverride === true,
        ...(stripeState ? { stripeSubscriptionState: stripeState } : {}),
        ...(clearSubscription ? { stripeSubscriptionCleared: existing.stripeSubscriptionId } : {}),
      },
    });

    return reply.send({
      id: org.id,
      oldPlan: from,
      newPlan: org.plan,
      hasStripeSubscription: hasStripeSubscription && !clearSubscription,
      ...(clearSubscription ? { stripeSubscriptionCleared: true } : {}),
    });
  });

  // -------------------------------------------------------------------------
  // POST /organizations/:orgId/suspend — Superadmin suspension.
  //
  // Sets suspendedAt + suspendedReason. While set, every code of the org
  // verifies as UNTRUSTED ("This code has been disabled", no destination, no
  // org name) and the org's mutating API calls get 403 (lib/org-suspension.ts).
  // QR rows are not touched. The verify path reads suspendedAt from the
  // database on every request, so the change applies to the next scan.
  // -------------------------------------------------------------------------

  fastify.post('/organizations/:orgId/suspend', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, requireAdmin],
    preValidation: zodValidator({ body: adminReasonSchema }),
  }, async (request, reply) => {
    const { orgId } = request.params as { orgId: string };
    const { reason } = request.body as z.infer<typeof adminReasonSchema>;

    const existing = await fastify.prisma.organization.findUnique({
      where: { id: orgId },
      select: { id: true, slug: true, suspendedAt: true, suspendedReason: true },
    });
    if (!existing) {
      return reply.status(404).send(notFoundError('Organization', orgId));
    }
    // The platform organization owns the OP signing keys and the FIRST_PARTY
    // OIDC clients; suspending it would disable sign-in for all of them.
    if (existing.slug === QRAUTH_PLATFORM_ORG_SLUG) {
      return reply.status(409).send({
        statusCode: 409,
        error: 'Conflict',
        message: 'The platform organization cannot be suspended.',
      });
    }

    // Suspended already, for the same reason: nothing changes, no entry.
    if (existing.suspendedAt !== null && existing.suspendedReason === reason) {
      return reply.send({ suspended: true, organization: { id: existing.id, suspendedAt: existing.suspendedAt, suspendedReason: reason } });
    }

    const org = await updateOrgAudited(request, (tx) => tx.organization.update({
      where: { id: orgId },
      data: { suspendedAt: existing.suspendedAt ?? new Date(), suspendedReason: reason },
      select: { id: true, name: true, suspendedAt: true, suspendedReason: true },
    }), {
      organizationId: orgId,
      action: 'admin.organization.suspend',
      metadata: { reason, alreadySuspended: existing.suspendedAt !== null },
    });

    return reply.send({ suspended: true, organization: org });
  });

  // -------------------------------------------------------------------------
  // POST /organizations/:orgId/unsuspend — Lift a suspension. Codes and API
  // access return to their prior behavior; nothing else is restored because
  // nothing else was changed.
  // -------------------------------------------------------------------------

  fastify.post('/organizations/:orgId/unsuspend', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, requireAdmin],
  }, async (request, reply) => {
    const { orgId } = request.params as { orgId: string };

    const existing = await fastify.prisma.organization.findUnique({
      where: { id: orgId },
      select: { id: true, suspendedAt: true, suspendedReason: true },
    });
    if (!existing) {
      return reply.status(404).send(notFoundError('Organization', orgId));
    }
    // Not suspended: nothing to lift, no entry.
    if (existing.suspendedAt === null) {
      return reply.send({ suspended: false, organization: { id: existing.id, suspendedAt: null, suspendedReason: null } });
    }

    const org = await updateOrgAudited(request, (tx) => tx.organization.update({
      where: { id: orgId },
      data: { suspendedAt: null, suspendedReason: null },
      select: { id: true, name: true, suspendedAt: true, suspendedReason: true },
    }), {
      organizationId: orgId,
      action: 'admin.organization.unsuspend',
      metadata: {
        previousReason: existing.suspendedReason,
        suspendedAt: existing.suspendedAt?.toISOString() ?? null,
      },
    });

    return reply.send({ suspended: false, organization: org });
  });

  // -------------------------------------------------------------------------
  // POST /organizations/:orgId/revoke-all-codes — Superadmin: revoke every
  // ACTIVE code of an organization (reason required). Each code is revoked
  // as DELETE /qrcodes/:token does, with its verify cache entry removed.
  // Unlike suspension this changes the rows and is not undone by unsuspend.
  // -------------------------------------------------------------------------

  fastify.post('/organizations/:orgId/revoke-all-codes', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, requireAdmin],
    preValidation: zodValidator({ body: adminReasonSchema }),
  }, async (request, reply) => {
    const { orgId } = request.params as { orgId: string };
    const { reason } = request.body as z.infer<typeof adminReasonSchema>;

    const existing = await fastify.prisma.organization.findUnique({
      where: { id: orgId },
      select: { id: true },
    });
    if (!existing) {
      return reply.status(404).send(notFoundError('Organization', orgId));
    }

    // A started entry, then a summary whatever happens: the batches commit
    // one by one (each code's revision with it, under this request id), so a
    // failure part-way leaves a record of how far it got (ADR-0008 D3).
    const ctx = staff(request);
    const activeCodes = await fastify.prisma.qRCode.count({ where: { organizationId: orgId, status: 'ACTIVE' } });
    await recordAudit(fastify.prisma, ctx, {
      organizationId: orgId,
      action: 'admin.organization.revokeAllCodesStarted',
      resource: 'Organization',
      resourceId: orgId,
      metadata: { reason, activeCodes },
    });
    let revoked = 0;
    let completed = false;
    try {
      revoked = await revokeAllActiveForOrg(
        fastify.prisma,
        request.log,
        orgId,
        // Customers see "QRAuth" in their history, not the staff member.
        systemContext('qrauth-admin', request.id),
        (soFar) => { revoked = soFar; },
      );
      completed = true;
    } finally {
      await recordAudit(fastify.prisma, ctx, {
        organizationId: orgId,
        action: 'admin.organization.revokeAllCodes',
        resource: 'Organization',
        resourceId: orgId,
        metadata: { reason, activeCodes, revoked, completed },
      }).catch((err: unknown) => request.log.error({ err, orgId, revoked, completed }, 'revoke-all: summary audit entry failed'));
    }

    return reply.send({ revoked });
  });
}
