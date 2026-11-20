import type { FastifyInstance } from 'fastify';
import { rateLimitAuth, rateLimitSensitive } from '../middleware/rateLimit.js';
import { revokeOidcAccessForUser } from '../lib/oidc-revocation.js';
import { auditContext, recordAudit } from '../services/audit.js';

// ---------------------------------------------------------------------------
// Session Management Routes — SOC 2 CC6.1 / GDPR Art. 32
// ---------------------------------------------------------------------------

export default async function sessionRoutes(fastify: FastifyInstance): Promise<void> {
  const authenticate = fastify.authenticate;

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

    // Revoke the entire token family; the audit entry commits with it.
    const ctx = auditContext(request);
    await fastify.prisma.$transaction(async (tx) => {
      const { count } = await tx.refreshToken.updateMany({
        where: { family: token.family, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      // Already signed out: nothing changed, no entry.
      if (count === 0) return;
      await recordAudit(tx, ctx, {
        organizationId: request.user!.orgId,
        action: 'session.revoke',
        resource: 'RefreshToken',
        resourceId: id,
        metadata: { revokedTokens: count },
      });
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

    // "Sign out everywhere" includes the OP and relying parties (audit
    // 2026-10 FINDING-011).
    // One transaction: OIDC access, dashboard refresh tokens and the audit entry.
    const ctx = auditContext(request);
    await fastify.prisma.$transaction(async (tx) => {
      const oidc = await revokeOidcAccessForUser(tx, userId);
      const { count } = await tx.refreshToken.updateMany({
        where: { userId, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      // Nothing left to sign out: no entry.
      if (count === 0 && Object.values(oidc).every((n) => n === 0)) return;
      await recordAudit(tx, ctx, {
        organizationId: request.user!.orgId,
        action: 'session.revoke_all',
        resource: 'User',
        resourceId: userId,
        metadata: { reason: 'User-initiated sign out everywhere', refreshTokens: count, oidc },
      });
    });

    return reply.send({
      message: 'All sessions revoked. You will need to sign in again on all devices.',
    });
  });
}
