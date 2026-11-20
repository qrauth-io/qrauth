import type { FastifyInstance } from 'fastify';
import { rateLimitSensitive } from '../middleware/rateLimit.js';
import { auditContext, eraseAuditPersonalData, recordAudit, recordAuditInOrgs } from '../services/audit.js';
import { revokeAllUserTokens } from '../lib/refresh-token.js';

// ---------------------------------------------------------------------------
// GDPR Data Subject Rights — Plugin
// ---------------------------------------------------------------------------

export default async function gdprRoutes(fastify: FastifyInstance): Promise<void> {
  const authenticate = fastify.authenticate;

  // -------------------------------------------------------------------------
  // GET /export — Data portability (GDPR Art. 20)
  //
  // Returns all personal data associated with the authenticated user in a
  // machine-readable JSON format.
  // -------------------------------------------------------------------------

  fastify.get('/export', {
    config: { rateLimit: rateLimitSensitive },
    preHandler: [authenticate],
  }, async (request, reply) => {
    const userId = request.user!.id;
    const orgId = request.user!.orgId;

    // Fetch all user data in parallel
    const [
      user,
      memberships,
      loginEvents,
      trustedDevices,
      passkeys,
      authSessions,
    ] = await Promise.all([
      fastify.prisma.user.findUnique({
        where: { id: userId },
        select: {
          id: true,
          name: true,
          email: true,
          provider: true,
          avatarUrl: true,
          emailVerified: true,
          onboardedAt: true,
          lastLoginAt: true,
          createdAt: true,
          updatedAt: true,
        },
      }),
      fastify.prisma.membership.findMany({
        where: { userId },
        include: {
          organization: {
            select: { id: true, name: true, slug: true },
          },
        },
      }),
      fastify.prisma.loginEvent.findMany({
        where: { userId },
        select: {
          id: true,
          success: true,
          provider: true,
          ipCountry: true,
          ipCity: true,
          deviceType: true,
          browser: true,
          os: true,
          createdAt: true,
        },
        orderBy: { createdAt: 'desc' },
        take: 500,
      }),
      fastify.prisma.trustedDevice.findMany({
        where: { userId },
        select: {
          id: true,
          name: true,
          trustLevel: true,
          deviceType: true,
          browser: true,
          os: true,
          ipCountry: true,
          ipCity: true,
          lastSeenAt: true,
          createdAt: true,
        },
      }),
      fastify.prisma.passkey.findMany({
        where: { userId },
        select: {
          id: true,
          name: true,
          transports: true,
          aaguid: true,
          lastUsedAt: true,
          createdAt: true,
        },
      }),
      fastify.prisma.authSession.findMany({
        where: { userId },
        select: {
          id: true,
          status: true,
          scopes: true,
          ipCountry: true,
          ipCity: true,
          userAgent: true,
          createdAt: true,
          resolvedAt: true,
        },
        orderBy: { createdAt: 'desc' },
        take: 200,
      }),
    ]);

    if (!user) {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: 'User not found.',
      });
    }

    // Log the export request for audit trail
    await recordAudit(fastify.prisma, auditContext(request), {
      organizationId: orgId,
      action: 'user.data_export',
      resource: 'User',
      resourceId: userId,
      metadata: { reason: 'GDPR Art. 20 data portability request' },
    });

    const exportData = {
      exportedAt: new Date().toISOString(),
      dataSubject: user,
      memberships: memberships.map((m) => ({
        organizationId: m.organizationId,
        organizationName: m.organization.name,
        role: m.role,
        joinedAt: m.joinedAt,
      })),
      loginHistory: loginEvents,
      trustedDevices,
      passkeys,
      authSessions,
    };

    reply.header('Content-Type', 'application/json');
    reply.header(
      'Content-Disposition',
      `attachment; filename="qrauth-data-export-${userId}.json"`,
    );

    return reply.send(exportData);
  });

  // -------------------------------------------------------------------------
  // DELETE /delete-account — Right to erasure (GDPR Art. 17)
  //
  // Permanently deletes the user account and anonymises associated data.
  // QR codes and scans that belong to an organization are NOT deleted
  // (they are org-owned assets), but the user linkage is removed.
  //
  // If the user is the sole OWNER of an org, the request is rejected —
  // they must transfer ownership first.
  // -------------------------------------------------------------------------

  fastify.delete('/delete-account', {
    config: { rateLimit: rateLimitSensitive },
    preHandler: [authenticate],
  }, async (request, reply) => {
    const userId = request.user!.id;
    const orgId = request.user!.orgId;

    // Prevent deletion if user is the sole OWNER of any organization
    const ownedOrgs = await fastify.prisma.membership.findMany({
      where: { userId, role: 'OWNER' },
      select: { organizationId: true },
    });

    for (const owned of ownedOrgs) {
      const ownerCount = await fastify.prisma.membership.count({
        where: {
          organizationId: owned.organizationId,
          role: 'OWNER',
        },
      });

      if (ownerCount <= 1) {
        return reply.status(409).send({
          statusCode: 409,
          error: 'Conflict',
          message:
            'You are the sole owner of an organization. Transfer ownership before deleting your account.',
        });
      }
    }

    const memberOf = await fastify.prisma.membership.findMany({ where: { userId }, select: { organizationId: true } });
    const account = await fastify.prisma.user.findUnique({ where: { id: userId }, select: { email: true } });
    // The entry recording the erasure does not keep the address or browser it erases.
    const ctx = { ...auditContext(request), ip: null, userAgent: null };

    // Execute deletion in a transaction
    await fastify.prisma.$transaction(async (tx) => {
      // 1. Revoke all refresh tokens
      await revokeAllUserTokens(tx, userId);

      // 2. Delete login events (PII: IP, user agent, etc.)
      await tx.loginEvent.deleteMany({ where: { userId } });

      // 3. Delete trusted devices + passkeys (cascade handles passkeys)
      await tx.trustedDevice.deleteMany({ where: { userId } });
      await tx.passkey.deleteMany({ where: { userId } });

      // 4. Delete refresh tokens
      await tx.refreshToken.deleteMany({ where: { userId } });

      // 5. Nullify auth sessions (keep for app audit, remove user link)
      await tx.authSession.updateMany({
        where: { userId },
        data: { userId: null },
      });

      // 6. Remove memberships (this removes org access)
      await tx.membership.deleteMany({ where: { userId } });

      // 7. Delete invitations sent by this user
      await tx.invitation.deleteMany({ where: { invitedBy: userId } });

      // 8. Anonymise audit logs: keep the trail (SOC 2); clear the IP and
      //    user agent of the user's entries and their API keys' entries, and
      //    redact their email from metadata (append-only table; erasure is
      //    the one update its trigger allows). Then record the deletion in
      //    every organization the user belonged to.
      await eraseAuditPersonalData(tx, { userId, email: account?.email ?? null });
      await recordAuditInOrgs(tx, ctx, [orgId, ...memberOf.map((m) => m.organizationId)], {
        action: 'user.delete',
        resource: 'User',
        resourceId: userId,
        metadata: { reason: 'GDPR Art. 17 right to erasure' },
      });

      // 9. Delete the user record last
      await tx.user.delete({ where: { id: userId } });
    });

    return reply.send({
      message: 'Account deleted successfully. All personal data has been erased.',
    });
  });
}
