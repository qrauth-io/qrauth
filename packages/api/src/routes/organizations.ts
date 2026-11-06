import { signingKeyRotationEvent } from '../services/signing.js';
import { auditLogGate, gateRefusalBody } from '../config/plan-limits.js';
import { createHash } from 'node:crypto';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { zodValidator } from '../middleware/validate.js';
import { authorize } from '../middleware/authorize.js';
import { Prisma } from '@prisma/client';
import { DomainService, referenceHost, type DomainOutcomeAudit, type DomainReview } from '../services/domain.js';
import { normalizeEmail } from '../lib/email-normalize.js';
import { removeMember, changeMemberRole } from '../services/membership-admin.js';
import { acceptInvitation, findPendingInvitation, invitationMatchesEmail } from '../services/invitations.js';
import type { MembershipRole } from '@qrauth/shared';
import { sendInvitationEmail, sendMemberRemovedEmail, sendRoleChangedEmail, sendSigningKeyRotatedEmail, sendDomainVerifiedEmail } from '../lib/email.js';
import {
  selfUpdateOrganizationSchema,
  inviteUserSchema,
  updateMemberRoleSchema,
  createApiKeySchema,
  INVITATION_EXPIRY_HOURS,
} from '@qrauth/shared';
import { randomBytes } from 'node:crypto';
import { rateLimitAuth, rateLimitSensitive } from '../middleware/rateLimit.js';
import { auditContext, recordAudit, type AuditContext } from '../services/audit.js';
import { ApiKeyIssueError, createOwnedKey, keyIssuer } from '../services/api-key-issue.js';


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Verify that the authenticated user's active org matches the :id route param.
 * Throws a 403 HTTP error if they differ.
 */
function checkOrgAccess(request: FastifyRequest): void {
  const { id } = request.params as { id: string };

  if (request.user?.orgId !== id) {
    const err = Object.assign(
      new Error('Forbidden: you do not have access to this organization.'),
      { statusCode: 403 },
    );
    throw err;
  }
}

const INVITATION_UNUSABLE = {
  statusCode: 404,
  error: 'Not Found',
  message: 'Invitation is invalid, expired, or has already been accepted.',
};

/** Map a refused member removal / role change to its HTTP response. */
function sendMemberRefusal(
  reply: FastifyReply,
  outcome: 'not_found' | 'forbidden' | 'last_owner' | 'conflict',
  action: 'remove' | 'change the role of',
) {
  switch (outcome) {
    case 'not_found':
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'Membership not found.' });
    case 'forbidden':
      return reply.status(403).send({
        statusCode: 403,
        error: 'Forbidden',
        message: `You can only ${action} a member with a lower role than your own.`,
      });
    case 'last_owner':
      return reply.status(422).send({
        statusCode: 422,
        error: 'Unprocessable Entity',
        message: action === 'remove'
          ? 'Cannot remove the last owner of an organization.'
          : 'Cannot demote the last owner of an organization.',
      });
    case 'conflict':
      return reply.status(409).send({
        statusCode: 409,
        error: 'Conflict',
        message: 'Membership was changed by another request. Please try again.',
      });
  }
}

/** Organization fields a self-service update can change, as audited. */
const ORG_AUDIT_FIELDS = ['name', 'slug', 'email', 'billingEmail', 'domain', 'domainVerified'] as const;
const ORG_AUDIT_SELECT = Object.fromEntries(ORG_AUDIT_FIELDS.map((f) => [f, true])) as Record<(typeof ORG_AUDIT_FIELDS)[number], true>;
type OrgAuditFields = Partial<Record<(typeof ORG_AUDIT_FIELDS)[number], unknown>>;

/** Address fields: the audit log records that they changed, never the addresses. */
const ORG_EMAIL_FIELDS: ReadonlySet<string> = new Set(['email', 'billingEmail']);
export const AUDIT_VALUE_HASH_LENGTH = 12;

function shortHash(value: unknown): string | null {
  return value === null || value === undefined || value === ''
    ? null
    : createHash('sha256').update(String(value)).digest('hex').slice(0, AUDIT_VALUE_HASH_LENGTH);
}

/**
 * `{ field: { before, after } }` for each audited field the update changed;
 * for address fields `{ changed: true, afterHash }` instead (a short hash
 * that tells later changes apart without storing the address).
 */
export function orgFieldChanges(before: OrgAuditFields, after: OrgAuditFields): Record<string, unknown> {
  return Object.fromEntries(
    ORG_AUDIT_FIELDS
      .filter((f) => (before[f] ?? null) !== (after[f] ?? null))
      .map((f) => [
        f,
        ORG_EMAIL_FIELDS.has(f) ? { changed: true, afterHash: shortHash(after[f]) } : { before: before[f] ?? null, after: after[f] ?? null },
      ]),
  );
}

/** Audit hook for DNS domain verification: verified or held, in the transaction that stores it. */
function domainOutcomeAudit(ctx: AuditContext, organizationId: string): DomainOutcomeAudit {
  return async (tx, outcome) => {
    const base = { organizationId, resource: 'Organization', resourceId: organizationId } as const;
    if (outcome.pendingReview) {
      await recordAudit(tx, ctx, {
        ...base,
        action: 'organization.domain.heldForReview',
        metadata: { domain: outcome.domain, matches: outcome.matches, source: 'dns' },
      });
    } else if (outcome.verified) {
      await recordAudit(tx, ctx, { ...base, action: 'organization.domain.verify', metadata: { domain: outcome.domain, source: 'dns' } });
    }
  };
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export default async function organizationRoutes(fastify: FastifyInstance): Promise<void> {
  const signingService = fastify.signingService;
  const domainService = new DomainService(fastify.prisma, fastify.log);
  const authenticate = fastify.authenticate;

  // -------------------------------------------------------------------------
  // GET /:id — Get organization details
  // -------------------------------------------------------------------------

  fastify.get('/:id', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER')],
  }, async (request, reply) => {
    checkOrgAccess(request);

    const { id } = request.params as { id: string };

    const org = await fastify.prisma.organization.findUnique({
      where: { id },
      include: {
        _count: {
          select: {
            qrCodes: true,
            signingKeys: true,
            memberships: true,
          },
        },
      },
    });

    if (!org) {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: `Organization "${id}" not found.`,
      });
    }

    return reply.send(org);
  });

  // -------------------------------------------------------------------------
  // PATCH /:id — Update organization
  // -------------------------------------------------------------------------

  fastify.patch('/:id', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
    preValidation: zodValidator({ body: selfUpdateOrganizationSchema }),
  }, async (request, reply) => {
    checkOrgAccess(request);

    const { id } = request.params as { id: string };
    const body = request.body as {
      name?: string;
      email?: string;
      domain?: string;
      billingEmail?: string;
    };

    // Recompute slug when name changes.
    const slugUpdate = body.name
      ? {
          slug: body.name
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, '-')
            .replace(/^-+|-+$/g, ''),
        }
      : {};

    // IDOR-001: `plan` and `trustLevel` are intentionally NOT writable via this
    // self-service route. They are controlled by billing.ts (Stripe webhook)
    // and admin.ts only. The validation schema already strips them; this
    // handler no longer spreads them into the Prisma update.
    // A verified domain proves control of THAT domain only. Changing it drops
    // the verified state in the same update (audit 2026-10 FINDING-007).
    // A new domain is also reviewed for lookalikes (ADR-0007 D9): one that
    // resembles a protected domain is held (PENDING_REVIEW) and cannot be
    // verified until a superadmin approves it.
    const current = await fastify.prisma.organization.findUnique({
      where: { id },
      select: { name: true, slug: true, email: true, billingEmail: true, domain: true, domainVerified: true },
    });
    let domainReset = {};
    let domainHold: DomainReview | null = null;
    if (body.domain !== undefined) {
      if (current?.domain !== body.domain) {
        const check = body.domain ? await domainService.reviewDomain(body.domain, id) : null;
        domainHold = check?.isSuspicious
          ? { domain: referenceHost(body.domain!) ?? body.domain!, matches: check.warnings.slice(0, 5), source: 'domain_set', ownershipProven: false, heldAt: new Date().toISOString() }
          : null;
        domainReset = {
          domainVerified: false,
          domainVerifyToken: null,
          domainReviewStatus: domainHold ? 'PENDING_REVIEW' : null,
          domainReview: domainHold ? (domainHold as never) : Prisma.DbNull,
        };
      }
    }

    const ctx = auditContext(request);
    const base = { organizationId: id, resource: 'Organization', resourceId: id } as const;
    const org = await fastify.prisma.$transaction(async (tx) => {
      // "before" is read under the row lock, so a concurrent change is not reported as ours.
      await tx.$queryRaw`SELECT "id" FROM "organizations" WHERE "id" = ${id} FOR UPDATE`;
      const locked = await tx.organization.findUnique({ where: { id }, select: ORG_AUDIT_SELECT });
      const updated = await tx.organization.update({
        where: { id },
        data: {
          ...body,
          ...slugUpdate,
          ...domainReset,
        },
      });
      const changes = orgFieldChanges(locked ?? {}, updated);
      if (Object.keys(changes).length > 0) {
        await recordAudit(tx, ctx, { ...base, action: 'organization.update', metadata: { changes } });
      }
      if (domainHold) {
        await recordAudit(tx, ctx, {
          ...base,
          action: 'organization.domain.heldForReview',
          metadata: { domain: domainHold.domain, matches: domainHold.matches, source: domainHold.source },
        });
      }
      return updated;
    });

    return reply.send(org);
  });

  // -------------------------------------------------------------------------
  // POST /:id/verify — Submit KYC
  // -------------------------------------------------------------------------

  fastify.post('/:id/verify', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
  }, async (request, reply) => {
    checkOrgAccess(request);

    const { id } = request.params as { id: string };

    const org = await fastify.prisma.$transaction(async (tx) => {
      const before = await tx.organization.findUnique({ where: { id }, select: { kycStatus: true } });
      const updated = await tx.organization.update({
        where: { id },
        data: { kycStatus: 'UNDER_REVIEW' },
      });
      await recordAudit(tx, auditContext(request), {
        organizationId: id,
        action: 'organization.kyc.submit',
        resource: 'Organization',
        resourceId: id,
        metadata: { kycStatus: { before: before?.kycStatus ?? null, after: updated.kycStatus } },
      });
      return updated;
    });

    return reply.send({
      id: org.id,
      kycStatus: org.kycStatus,
      updatedAt: org.updatedAt,
    });
  });

  // -------------------------------------------------------------------------
  // GET /:id/keys — List signing keys
  // -------------------------------------------------------------------------

  fastify.get('/:id/keys', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
  }, async (request, reply) => {
    checkOrgAccess(request);

    const { id } = request.params as { id: string };

    const keys = await fastify.prisma.signingKey.findMany({
      where: { organizationId: id },
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        keyId: true,
        algorithm: true,
        status: true,
        publicKey: true,
        createdAt: true,
        rotatedAt: true,
        revokedAt: true,
      },
    });

    return reply.send({ data: keys, total: keys.length });
  });

  // -------------------------------------------------------------------------
  // POST /:id/keys/rotate — Rotate active signing key
  // -------------------------------------------------------------------------

  fastify.post('/:id/keys/rotate', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
  }, async (request, reply) => {
    checkOrgAccess(request);

    const { id } = request.params as { id: string };

    const ctx = auditContext(request);
    const newKey = await signingService.rotateKey(id, 'ES256', (tx, rotation) =>
      recordAudit(tx, ctx, signingKeyRotationEvent(rotation, 'manual')),
    );

    const org = await fastify.prisma.organization.findUnique({
      where: { id }, select: { email: true, name: true },
    });
    if (org?.email) {
      sendSigningKeyRotatedEmail(org.email, org.name, request.user!.email, newKey.keyId).catch((err) => {
        fastify.log.error({ err }, 'Failed to send signing key rotated email');
      });
    }

    return reply.status(201).send({
      id: newKey.id,
      keyId: newKey.keyId,
      algorithm: newKey.algorithm,
      status: newKey.status,
      publicKey: newKey.publicKey,
      createdAt: newKey.createdAt,
    });
  });

  // -------------------------------------------------------------------------
  // GET /:id/members — List members
  // -------------------------------------------------------------------------

  fastify.get('/:id/members', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER')],
  }, async (request, reply) => {
    checkOrgAccess(request);

    const { id } = request.params as { id: string };

    const memberships = await fastify.prisma.membership.findMany({
      where: { organizationId: id },
      include: {
        user: {
          select: { id: true, name: true, email: true },
        },
      },
      orderBy: { joinedAt: 'asc' },
    });

    return reply.send({
      data: memberships.map((m) => ({
        id: m.id,
        userId: m.userId,
        role: m.role,
        joinedAt: m.joinedAt,
        user: {
          id: m.user.id,
          name: m.user.name,
          email: m.user.email,
        },
      })),
      total: memberships.length,
    });
  });

  // -------------------------------------------------------------------------
  // POST /:id/invitations — Invite a user to the organization
  // -------------------------------------------------------------------------

  fastify.post('/:id/invitations', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
    preValidation: zodValidator({ body: inviteUserSchema }),
  }, async (request, reply) => {
    checkOrgAccess(request);

    const { id } = request.params as { id: string };
    const { role } = request.body as { email: string; role: string };
    // Invitations are stored and matched on the canonical (lowercased) address.
    const body = { email: normalizeEmail((request.body as { email: string }).email), role };

    // Check whether the invitee is already a member.
    const existingUser = await fastify.prisma.user.findUnique({
      where: { email: body.email },
      select: { id: true },
    });

    if (existingUser) {
      const existingMembership = await fastify.prisma.membership.findUnique({
        where: {
          userId_organizationId: {
            userId: existingUser.id,
            organizationId: id,
          },
        },
      });

      if (existingMembership) {
        return reply.status(409).send({
          statusCode: 409,
          error: 'Conflict',
          message: 'This user is already a member of the organization.',
        });
      }
    }

    const rawToken = randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + INVITATION_EXPIRY_HOURS * 60 * 60 * 1000);

    const invitation = await fastify.prisma.$transaction(async (tx) => {
      const created = await tx.invitation.create({
        data: {
          organizationId: id,
          email: body.email,
          role: body.role as any,
          token: rawToken,
          invitedBy: request.user!.id,
          expiresAt,
        },
      });
      await recordAudit(tx, auditContext(request), {
        organizationId: id,
        action: 'invitation.create',
        resource: 'Invitation',
        resourceId: created.id,
        metadata: { email: created.email, role: created.role, expiresAt: created.expiresAt.toISOString() },
      });
      return created;
    });

    const org = await fastify.prisma.organization.findUnique({
      where: { id },
      select: { name: true },
    });

    sendInvitationEmail(
      body.email,
      request.user!.email || 'A team member',
      org?.name ?? id,
      body.role,
      rawToken,
    ).catch((err) => {
      fastify.log.error({ err, email: body.email }, 'Failed to send invitation email');
    });

    return reply.status(201).send({
      id: invitation.id,
      organizationId: invitation.organizationId,
      email: invitation.email,
      role: invitation.role,
      expiresAt: invitation.expiresAt,
      createdAt: invitation.createdAt,
    });
  });

  // -------------------------------------------------------------------------
  // GET /:id/invitations — List PENDING invitations (not yet accepted, not
  // expired). Without this, invites were created but never visible — an OWNER
  // could not see, chase, or audit who had been invited.
  // -------------------------------------------------------------------------

  fastify.get('/:id/invitations', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
  }, async (request, reply) => {
    checkOrgAccess(request);

    const { id } = request.params as { id: string };

    const invitations = await fastify.prisma.invitation.findMany({
      where: { organizationId: id, acceptedAt: null, expiresAt: { gt: new Date() } },
      orderBy: { createdAt: 'desc' },
      select: { id: true, email: true, role: true, expiresAt: true, createdAt: true },
    });

    return reply.send({ data: invitations, total: invitations.length });
  });

  // -------------------------------------------------------------------------
  // GET /invitations/:token — What an invitation is for (public: the token is
  // the secret, sent only to the invited address). Lets the sign-up and
  // accept pages say which organization and role the link is for.
  // -------------------------------------------------------------------------

  fastify.get('/invitations/:token', {
    config: { rateLimit: rateLimitSensitive },
  }, async (request, reply) => {
    const { token } = request.params as { token: string };
    const invitation = await findPendingInvitation(fastify.prisma, token);
    if (!invitation) return reply.status(404).send(INVITATION_UNUSABLE);

    const org = await fastify.prisma.organization.findUnique({
      where: { id: invitation.organizationId },
      select: { name: true },
    });
    if (!org) return reply.status(404).send(INVITATION_UNUSABLE);

    return reply.send({
      organizationName: org.name,
      email: invitation.email,
      role: invitation.role,
      expiresAt: invitation.expiresAt,
    });
  });

  // -------------------------------------------------------------------------
  // POST /invitations/:token/accept — Accept an invitation (authenticated)
  // -------------------------------------------------------------------------

  fastify.post('/invitations/:token/accept', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate],
  }, async (request, reply) => {
    const { token } = request.params as { token: string };

    const invitation = await findPendingInvitation(fastify.prisma, token);
    if (!invitation) return reply.status(400).send({ ...INVITATION_UNUSABLE, statusCode: 400, error: 'Bad Request' });

    // Ensure the authenticated user's email matches the invitation.
    if (!invitationMatchesEmail(invitation, request.user!.email)) {
      return reply.status(403).send({
        statusCode: 403,
        error: 'Forbidden',
        message: 'This invitation was issued to a different email address.',
      });
    }

    // The address match only counts for an address the account has proven.
    // The invitation is left pending so it can be accepted once verified.
    const accepting = await fastify.prisma.user.findUnique({
      where: { id: request.user!.id },
      select: { emailVerified: true },
    });
    if (accepting?.emailVerified !== true) {
      return reply.status(403).send({
        statusCode: 403,
        error: 'Forbidden',
        message: 'Verify your email address to accept this invitation',
      });
    }

    // Logged in the organization joined, with the accepting user as actor.
    const ctx = auditContext(request);
    const result = await fastify.prisma.$transaction(
      (tx) => acceptInvitation(tx, ctx, invitation, request.user!.id),
    );
    if (result.outcome === 'already_member') {
      return reply.status(409).send({
        statusCode: 409,
        error: 'Conflict',
        message: 'You are already a member of this organization.',
      });
    }
    if (result.outcome === 'spent') {
      return reply.status(400).send({ ...INVITATION_UNUSABLE, statusCode: 400, error: 'Bad Request' });
    }
    const { membership } = result;

    return reply.status(201).send({
      id: membership.id,
      userId: membership.userId,
      organizationId: membership.organizationId,
      role: membership.role,
      joinedAt: membership.joinedAt,
    });
  });

  // -------------------------------------------------------------------------
  // DELETE /:id/members/:userId — Remove a member
  // -------------------------------------------------------------------------

  fastify.delete('/:id/members/:userId', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
  }, async (request, reply) => {
    checkOrgAccess(request);

    const { id, userId } = request.params as { id: string; userId: string };

    const [removedUser, org] = await Promise.all([
      fastify.prisma.user.findUnique({ where: { id: userId }, select: { email: true, name: true } }),
      fastify.prisma.organization.findUnique({ where: { id }, select: { name: true } }),
    ]);

    // Role boundary, last-owner check, removal and the ADR-0002 CLI-key
    // revocation cascade run in one serializable transaction.
    const ctx = auditContext(request);
    const result = await removeMember(fastify.prisma, {
      organizationId: id,
      targetUserId: userId,
      actorRole: request.user!.role as MembershipRole,
    }, (tx, removed) => recordAudit(tx, ctx, {
      organizationId: id,
      action: 'member.remove',
      resource: 'Membership',
      resourceId: userId,
      metadata: { removedUserId: userId, role: removed.previousRole, revokedCliKeys: removed.revokedCliKeys },
    }));
    if (result.outcome !== 'removed') {
      return sendMemberRefusal(reply, result.outcome, 'remove');
    }

    if (result.revokedCliKeys > 0) {
      fastify.log.info(
        { organizationId: id, userId, count: result.revokedCliKeys },
        'Revoked CLI API keys on membership removal',
      );
    }

    if (removedUser?.email) {
      sendMemberRemovedEmail(removedUser.email, removedUser.name || 'there', org?.name || 'the organization').catch((err) => {
        fastify.log.error({ err, userId }, 'Failed to send member removed email');
      });
    }

    return reply.status(204).send();
  });

  // -------------------------------------------------------------------------
  // GET /:id/api-keys — List API keys for the org
  // -------------------------------------------------------------------------

  fastify.get('/:id/api-keys', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
  }, async (request, reply) => {
    checkOrgAccess(request);

    const { id } = request.params as { id: string };
    const { includeRevoked } = request.query as { includeRevoked?: string };

    const keys = await fastify.prisma.apiKey.findMany({
      where: {
        organizationId: id,
        ...(includeRevoked !== 'true' ? { revokedAt: null } : {}),
      },
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        prefix: true,
        label: true,
        role: true,
        createdByUserId: true,
        lastUsedAt: true,
        revokedAt: true,
        createdAt: true,
      },
    });

    return reply.send({ data: keys, total: keys.length });
  });

  // -------------------------------------------------------------------------
  // POST /:id/api-keys — Create a new API key
  // -------------------------------------------------------------------------

  fastify.post('/:id/api-keys', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
    preValidation: zodValidator({ body: createApiKeySchema }),
  }, async (request, reply) => {
    checkOrgAccess(request);

    const { id } = request.params as { id: string };
    const body = request.body as z.output<typeof createApiKeySchema>;

    let issued: Awaited<ReturnType<typeof createOwnedKey>>;
    try {
      // The key belongs to the member who creates it (services/api-key-issue.ts).
      issued = await fastify.prisma.$transaction(async (tx) => createOwnedKey(tx, auditContext(request), {
        organizationId: id,
        issuer: await keyIssuer(tx, request.user!),
        label: body.label ?? null,
        role: body.role,
      }));
    } catch (err) {
      if (err instanceof ApiKeyIssueError) return reply.status(err.status).send(err.body);
      throw err;
    }
    const { key: apiKey, fullKey } = issued;

    return reply.status(201).send({
      id: apiKey.id,
      key: fullKey,
      prefix: apiKey.prefix,
      label: apiKey.label,
      role: apiKey.role,
      createdByUserId: apiKey.createdByUserId,
      createdAt: apiKey.createdAt,
    });
  });

  // -------------------------------------------------------------------------
  // DELETE /:id/api-keys/:keyId — Revoke an API key
  // -------------------------------------------------------------------------

  fastify.delete('/:id/api-keys/:keyId', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
  }, async (request, reply) => {
    checkOrgAccess(request);

    const { id, keyId } = request.params as { id: string; keyId: string };

    const apiKey = await fastify.prisma.apiKey.findUnique({
      where: { id: keyId },
    });

    if (!apiKey || apiKey.organizationId !== id) {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: 'API key not found.',
      });
    }

    if (apiKey.revokedAt !== null) {
      return reply.status(409).send({
        statusCode: 409,
        error: 'Conflict',
        message: 'API key is already revoked.',
      });
    }

    await fastify.prisma.$transaction(async (tx) => {
      await tx.apiKey.update({
        where: { id: keyId },
        data: { revokedAt: new Date() },
      });
      await recordAudit(tx, auditContext(request), {
        organizationId: id,
        action: 'apiKey.revoke',
        resource: 'ApiKey',
        resourceId: keyId,
        metadata: { prefix: apiKey.prefix, label: apiKey.label },
      });
    });

    return reply.status(204).send();
  });

  // -------------------------------------------------------------------------
  // POST /:id/generate-verify-token — Generate DNS verification token
  // -------------------------------------------------------------------------

  fastify.post('/:id/generate-verify-token', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    if (request.user!.orgId !== id) return reply.status(403).send({ statusCode: 403, error: 'Forbidden', message: 'Access denied' });

    const org = await fastify.prisma.organization.findUnique({ where: { id }, select: { domain: true } });
    if (!org?.domain) {
      return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message: 'Set a domain on your organization first (PATCH /organizations/:id)' });
    }

    // The token is published in DNS, but it is not written to the log.
    const token = randomBytes(16).toString('hex');
    await fastify.prisma.$transaction(async (tx) => {
      await tx.organization.update({ where: { id }, data: { domainVerifyToken: token } });
      await recordAudit(tx, auditContext(request), {
        organizationId: id,
        action: 'organization.domain.tokenGenerate',
        resource: 'Organization',
        resourceId: id,
        metadata: { domain: org.domain },
      });
    });
    return reply.send({
      token,
      instruction: `Add a DNS TXT record to ${org.domain}: qrauth-verify=${token}`,
      dnsRecord: {
        type: 'TXT',
        name: org.domain,
        value: `qrauth-verify=${token}`,
      },
    });
  });

  // -------------------------------------------------------------------------
  // POST /:id/verify-domain — Check DNS TXT record and verify domain
  // -------------------------------------------------------------------------

  fastify.post('/:id/verify-domain', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    if (request.user!.orgId !== id) return reply.status(403).send({ statusCode: 403, error: 'Forbidden', message: 'Access denied' });

    const result = await domainService.verifyDomain(id, domainOutcomeAudit(auditContext(request), id));
    if (result.verified) {
      const org = await fastify.prisma.organization.findUnique({
        where: { id }, select: { email: true, name: true, domain: true },
      });
      if (org?.email && org.domain) {
        sendDomainVerifiedEmail(org.email, org.name, org.domain).catch((err) => {
          fastify.log.error({ err }, 'Failed to send domain verified email');
        });
      }
    }
    return reply.send(result);
  });

  // -------------------------------------------------------------------------
  // PATCH /:id/members/:userId — Change a member's role
  // -------------------------------------------------------------------------

  fastify.patch('/:id/members/:userId', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
    preValidation: zodValidator({ body: updateMemberRoleSchema }),
  }, async (request, reply) => {
    checkOrgAccess(request);

    const { id, userId } = request.params as { id: string; userId: string };
    const { role: newRole } = request.body as { role: string };

    // ADMINs cannot promote anyone to OWNER; only OWNERs can.
    if (newRole === 'OWNER' && request.user!.role !== 'OWNER') {
      return reply.status(403).send({
        statusCode: 403,
        error: 'Forbidden',
        message: 'Only an OWNER can promote a member to OWNER.',
      });
    }

    const [affectedUser, org] = await Promise.all([
      fastify.prisma.user.findUnique({ where: { id: userId }, select: { email: true, name: true } }),
      fastify.prisma.organization.findUnique({ where: { id }, select: { name: true } }),
    ]);

    // Role boundary, last-owner check, the update and the CLI-key revocation
    // run in one serializable transaction.
    const ctx = auditContext(request);
    const result = await changeMemberRole(fastify.prisma, {
      organizationId: id,
      targetUserId: userId,
      actorRole: request.user!.role as MembershipRole,
      newRole: newRole as MembershipRole,
    }, (tx, updated) => recordAudit(tx, ctx, {
      organizationId: id,
      action: 'member.role.update',
      resource: 'Membership',
      resourceId: userId,
      metadata: { previousRole: updated.previousRole, newRole: updated.membership.role, revokedCliKeys: updated.revokedCliKeys },
    }));
    if (result.outcome !== 'updated') {
      return sendMemberRefusal(reply, result.outcome, 'change the role of');
    }
    const updated = result.membership;

    if (result.revokedCliKeys > 0) {
      fastify.log.info(
        { organizationId: id, userId, count: result.revokedCliKeys },
        'Revoked CLI API keys on role change',
      );
    }

    if (affectedUser?.email) {
      sendRoleChangedEmail(affectedUser.email, affectedUser.name || 'there', org?.name || 'the organization', newRole).catch((err) => {
        fastify.log.error({ err, userId }, 'Failed to send role changed email');
      });
    }

    return reply.send({
      id: updated.id,
      userId: updated.userId,
      organizationId: updated.organizationId,
      role: updated.role,
      joinedAt: updated.joinedAt,
    });
  });

  // -------------------------------------------------------------------------
  // GET /:id/audit-logs — Paginated audit trail (SOC 2 / ISO 27001)
  // -------------------------------------------------------------------------

  const auditLogQuerySchema = z.object({
    page: z.coerce.number().int().min(1).default(1),
    limit: z.coerce.number().int().min(1).max(100).default(50),
    action: z.string().optional(),
    resource: z.string().optional(),
    userId: z.string().optional(),
    from: z.string().datetime().optional(),
    to: z.string().datetime().optional(),
  });

  fastify.get('/:id/audit-logs', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
    preValidation: zodValidator({ querystring: auditLogQuerySchema }),
  }, async (request, reply) => {
    checkOrgAccess(request);

    const { id } = request.params as { id: string };
    // Same plan gate as GET /api/v1/audit (ADR-0008 D5).
    const plan = await fastify.prisma.organization.findUnique({ where: { id }, select: { plan: true } });
    const refusal = auditLogGate(plan?.plan);
    if (refusal) return reply.status(403).send(gateRefusalBody(refusal));
    const query = request.query as {
      page: number;
      limit: number;
      action?: string;
      resource?: string;
      userId?: string;
      from?: string;
      to?: string;
    };

    const where: Record<string, unknown> = { organizationId: id };
    if (query.action) where.action = query.action;
    if (query.resource) where.resource = query.resource;
    // Staff are never found by id (ADR-0008 D1).
    if (query.userId) Object.assign(where, { userId: query.userId, actorType: { not: 'SUPERADMIN' } });
    if (query.from || query.to) {
      where.createdAt = {
        ...(query.from ? { gte: new Date(query.from) } : {}),
        ...(query.to ? { lte: new Date(query.to) } : {}),
      };
    }

    const [total, logs] = await Promise.all([
      fastify.prisma.auditLog.count({ where: where as any }),
      fastify.prisma.auditLog.findMany({
        where: where as any,
        orderBy: { createdAt: 'desc' },
        skip: (query.page - 1) * query.limit,
        take: query.limit,
        select: {
          id: true,
          action: true,
          resource: true,
          resourceId: true,
          metadata: true,
          ipAddress: true,
          userAgent: true,
          createdAt: true,
          userId: true,
          actorType: true,
          actorId: true,
        },
      }),
    ]);

    // AuditLog has no user relation (the trail outlives deleted users).
    // QRAuth staff (SUPERADMIN) are never named to the organization.
    const userIds = [...new Set(logs.flatMap((l) => (l.actorType === 'USER' && l.userId ? [l.userId] : [])))];
    const users = userIds.length === 0
      ? []
      : await fastify.prisma.user.findMany({ where: { id: { in: userIds } }, select: { id: true, name: true, email: true } });
    const userById = new Map(users.map((u) => [u.id, u]));

    return reply.send({
      data: logs.map(({ userId, actorId, ...log }) => ({
        ...log,
        actorId: log.actorType === 'SUPERADMIN' ? null : actorId,
        // A staff member's address and browser are not the organization's data.
        ipAddress: log.actorType === 'SUPERADMIN' ? null : log.ipAddress,
        userAgent: log.actorType === 'SUPERADMIN' ? null : log.userAgent,
        user: log.actorType === 'USER' && userId ? (userById.get(userId) ?? null) : null,
      })),
      pagination: {
        page: query.page,
        limit: query.limit,
        total,
        totalPages: Math.ceil(total / query.limit),
      },
    });
  });
}
