import type { FastifyInstance } from 'fastify';
import { rateLimitAuth, rateLimitSensitive } from '../middleware/rateLimit.js';
import { revokeAllUserTokens } from '../lib/refresh-token.js';
import { AuditLogService } from '../services/audit.js';

// ---------------------------------------------------------------------------
// Session Management Routes — SOC 2 CC6.1 / GDPR Art. 32
// ---------------------------------------------------------------------------

export default async function sessionRoutes(fastify: FastifyInstance): Promise<void> {
  const authenticate = fastify.authenticate;
  const auditService = new AuditLogService(fastify.prisma);

  // -------------------------------------------------------------------------
  // GET / — List active sessions for the current user
  //
  // Returns active (non-revoked, non-expired) refresh tokens and trusted
  // devices so the user can see where they are logged in.
  // -------------------------------------------------------------------------

  fastify.get('/', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate],
  }, async (request, reply) => {
    const userId = request.user!.id;

    const [refreshTokens, trustedDevices] = await Promise.all([
      fastify.prisma.refreshToken.findMany({
        where: {
          userId,
          revokedAt: null,
          expiresAt: { gt: new Date() },
        },
        select: {
          id: true,
          family: true,
          createdAt: true,
          expiresAt: true,
        },
        orderBy: { createdAt: 'desc' },
      }),
      fastify.prisma.trustedDevice.findMany({
        where: { userId, revokedAt: null },
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
        orderBy: { lastSeenAt: 'desc' },
      }),
    ]);

    return reply.send({
      sessions: refreshTokens.map((t) => ({
        id: t.id,
        family: t.family,
        createdAt: t.createdAt,
        expiresAt: t.expiresAt,
      })),
      devices: trustedDevices,
    });
  });

  // -------------------------------------------------------------------------
  // DELETE /:id — Revoke a specific session (by refresh token family)
  // -------------------------------------------------------------------------

  fastify.delete('/:id', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate],
  }, async (request, reply) => {
    const userId = request.user!.id;
    const { id } = request.params as { id: string };

    // Find the token and verify ownership
    const token = await fastify.prisma.refreshToken.findFirst({
      where: { id, userId },
      select: { family: true },
    });

    if (!token) {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: 'Session not found.',
      });
    }

    // Revoke the entire token family
    await fastify.prisma.refreshToken.updateMany({
      where: { family: token.family, revokedAt: null },
      data: { revokedAt: new Date() },
    });

    await auditService.log({
      organizationId: request.user!.orgId,
      userId,
      action: 'session.revoke',
      resource: 'RefreshToken',
      resourceId: id,
    });

    return reply.status(204).send();
  });

  // -------------------------------------------------------------------------
  // DELETE / — Revoke all sessions (panic button / breach response)
  //
  // This is the "sign out everywhere" feature. Also useful for incident
  // response — SOC 2 CC7.3 requires the ability to revoke access quickly.
  // -------------------------------------------------------------------------

  fastify.delete('/', {
    config: { rateLimit: rateLimitSensitive },
    preHandler: [authenticate],
  }, async (request, reply) => {
    const userId = request.user!.id;

    await revokeAllUserTokens(fastify.prisma, userId);

    await auditService.log({
      organizationId: request.user!.orgId,
      userId,
      action: 'session.revoke_all',
      resource: 'User',
      resourceId: userId,
      metadata: { reason: 'User-initiated sign out everywhere' },
    });

    return reply.send({
      message: 'All sessions revoked. You will need to sign in again on all devices.',
    });
  });
}
