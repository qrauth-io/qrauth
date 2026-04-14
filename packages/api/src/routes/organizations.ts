import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { zodValidator } from '../middleware/validate.js';
import { authorize } from '../middleware/authorize.js';
import { SigningService } from '../services/signing.js';
import { DomainService } from '../services/domain.js';
import { sendInvitationEmail, sendMemberRemovedEmail, sendRoleChangedEmail, sendSigningKeyRotatedEmail, sendDomainVerifiedEmail } from '../lib/email.js';
import { generateApiKey } from '../lib/crypto.js';
import {
  updateOrganizationSchema,
  inviteUserSchema,
  updateMemberRoleSchema,
  INVITATION_EXPIRY_HOURS,
} from '@qrauth/shared';
import { randomBytes } from 'node:crypto';
import { rateLimitAuth } from '../middleware/rateLimit.js';
import { AuditLogService } from '../services/audit.js';

const createApiKeySchema = z.object({
  label: z.string().max(100).optional(),
});

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

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

export default async function organizationRoutes(fastify: FastifyInstance): Promise<void> {
  const signingService = new SigningService(fastify.prisma);
  const domainService = new DomainService(fastify.prisma);
  const authenticate = fastify.authenticate;
  const auditService = new AuditLogService(fastify.prisma);

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
    preValidation: zodValidator({ body: updateOrganizationSchema }),
  }, async (request, reply) => {
    checkOrgAccess(request);

    const { id } = request.params as { id: string };
    const body = request.body as {
      name?: string;
      email?: string;
      domain?: string;
      trustLevel?: string;
      plan?: string;
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

    const org = await fastify.prisma.organization.update({
      where: { id },
      data: {
        ...body,
        ...slugUpdate,
        ...(body.trustLevel ? { trustLevel: body.trustLevel as any } : {}),
        ...(body.plan ? { plan: body.plan as any } : {}),
      },
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

    const org = await fastify.prisma.organization.update({
      where: { id },
      data: { kycStatus: 'UNDER_REVIEW' },
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

    const newKey = await signingService.rotateKey(id);

    await auditService.log({
      organizationId: id,
      userId: request.user!.id,
      action: 'signingKey.rotate',
      resource: 'SigningKey',
      resourceId: newKey.keyId,
      metadata: { newKeyId: newKey.keyId },
    });

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
    const body = request.body as { email: string; role: string };

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

    const invitation = await fastify.prisma.invitation.create({
      data: {
        organizationId: id,
        email: body.email,
        role: body.role as any,
        token: rawToken,
        invitedBy: request.user!.id,
        expiresAt,
      },
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
  // POST /invitations/:token/accept — Accept an invitation (authenticated)
  // -------------------------------------------------------------------------

  fastify.post('/invitations/:token/accept', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate],
  }, async (request, reply) => {
    const { token } = request.params as { token: string };

    const invitation = await fastify.prisma.invitation.findUnique({
      where: { token },
    });

    if (!invitation || invitation.acceptedAt !== null || invitation.expiresAt < new Date()) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Invitation is invalid, expired, or has already been accepted.',
      });
    }

    // Ensure the authenticated user's email matches the invitation.
    if (request.user!.email !== invitation.email) {
      return reply.status(403).send({
        statusCode: 403,
        error: 'Forbidden',
        message: 'This invitation was issued to a different email address.',
      });
    }

    const [membership] = await fastify.prisma.$transaction([
      fastify.prisma.membership.create({
        data: {
          userId: request.user!.id,
          organizationId: invitation.organizationId,
          role: invitation.role,
          invitedBy: invitation.invitedBy,
        },
      }),
      fastify.prisma.invitation.update({
        where: { id: invitation.id },
        data: { acceptedAt: new Date() },
      }),
    ]);

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

    const target = await fastify.prisma.membership.findUnique({
      where: { userId_organizationId: { userId, organizationId: id } },
    });

    if (!target) {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: 'Membership not found.',
      });
    }

    // Prevent removal of the last OWNER.
    if (target.role === 'OWNER') {
      const ownerCount = await fastify.prisma.membership.count({
        where: { organizationId: id, role: 'OWNER' },
      });

      if (ownerCount <= 1) {
        return reply.status(422).send({
          statusCode: 422,
          error: 'Unprocessable Entity',
          message: 'Cannot remove the last owner of an organization.',
        });
      }
    }

    const [removedUser, org] = await Promise.all([
      fastify.prisma.user.findUnique({ where: { id: userId }, select: { email: true, name: true } }),
      fastify.prisma.organization.findUnique({ where: { id }, select: { name: true } }),
    ]);

    await fastify.prisma.membership.delete({
      where: { userId_organizationId: { userId, organizationId: id } },
    });

    await auditService.log({
      organizationId: id,
      userId: request.user!.id,
      action: 'member.remove',
      resource: 'Membership',
      resourceId: userId,
      metadata: { removedUserEmail: removedUser?.email, role: target.role },
    });

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
    const body = request.body as { label?: string };

    const { fullKey, prefix, hash } = generateApiKey();

    const apiKey = await fastify.prisma.apiKey.create({
      data: {
        organizationId: id,
        keyHash: hash,
        prefix,
        label: body.label,
      },
    });

    await auditService.log({
      organizationId: id,
      userId: request.user!.id,
      action: 'apiKey.create',
      resource: 'ApiKey',
      resourceId: apiKey.id,
      metadata: { prefix, label: body.label },
    });

    return reply.status(201).send({
      id: apiKey.id,
      key: fullKey,
      prefix: apiKey.prefix,
      label: apiKey.label,
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

    await fastify.prisma.apiKey.update({
      where: { id: keyId },
      data: { revokedAt: new Date() },
    });

    await auditService.log({
      organizationId: id,
      userId: request.user!.id,
      action: 'apiKey.revoke',
      resource: 'ApiKey',
      resourceId: keyId,
      metadata: { prefix: apiKey.prefix, label: apiKey.label },
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

    const token = await domainService.generateVerifyToken(id);
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

    const result = await domainService.verifyDomain(id);
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

    const target = await fastify.prisma.membership.findUnique({
      where: { userId_organizationId: { userId, organizationId: id } },
    });

    if (!target) {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: 'Membership not found.',
      });
    }

    // Prevent demoting the last OWNER.
    if (target.role === 'OWNER' && newRole !== 'OWNER') {
      const ownerCount = await fastify.prisma.membership.count({
        where: { organizationId: id, role: 'OWNER' },
      });

      if (ownerCount <= 1) {
        return reply.status(422).send({
          statusCode: 422,
          error: 'Unprocessable Entity',
          message: 'Cannot demote the last owner of an organization.',
        });
      }
    }

    const [affectedUser, org] = await Promise.all([
      fastify.prisma.user.findUnique({ where: { id: userId }, select: { email: true, name: true } }),
      fastify.prisma.organization.findUnique({ where: { id }, select: { name: true } }),
    ]);

    const updated = await fastify.prisma.membership.update({
      where: { userId_organizationId: { userId, organizationId: id } },
      data: { role: newRole as any },
    });

    await auditService.log({
      organizationId: id,
      userId: request.user!.id,
      action: 'member.role.update',
      resource: 'Membership',
      resourceId: userId,
      metadata: { previousRole: target.role, newRole },
    });

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
    if (query.userId) where.userId = query.userId;
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
          createdAt: true,
          user: {
            select: { id: true, name: true, email: true },
          },
        },
      }),
    ]);

    return reply.send({
      data: logs,
      pagination: {
        page: query.page,
        limit: query.limit,
        total,
        totalPages: Math.ceil(total / query.limit),
      },
    });
  });
}
