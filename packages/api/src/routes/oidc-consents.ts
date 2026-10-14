import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { API_KEY_PRINCIPAL_ID } from '../middleware/auth.js';
import { rateLimitAuth } from '../middleware/rateLimit.js';
import { CONSENT_REVOKED_AUDIT_ACTION } from '../lib/oidc-consent.js';

/**
 * "Connected apps" for the signed-in user (audit 2026-10 FINDING-002): the
 * OIDC clients they have consented to, and a way to take that back.
 *
 * Scoped to the caller's own user id, never the organization: a consent
 * belongs to a person. API keys act for an organization, so they are refused.
 */
export default async function oidcConsentRoutes(fastify: FastifyInstance): Promise<void> {
  const prisma = fastify.prisma;

  const refuseApiKey = async (request: FastifyRequest, reply: FastifyReply) => {
    if (request.user!.id === API_KEY_PRINCIPAL_ID) {
      return reply.status(403).send({
        statusCode: 403,
        error: 'Forbidden',
        message: 'Connected apps belong to a user and cannot be managed with an API key.',
      });
    }
  };

  fastify.get('/', {
    preHandler: [fastify.authenticate, refuseApiKey],
  }, async (request, reply) => {
    const consents = await prisma.oidcConsent.findMany({
      where: { userId: request.user!.id, revokedAt: null },
      orderBy: { grantedAt: 'desc' },
      include: { client: { select: { name: true, organization: { select: { name: true } } } } },
    });

    return reply.send({
      data: consents.map((consent) => ({
        id: consent.id,
        clientName: consent.client.name,
        organizationName: consent.client.organization.name,
        grantedScopes: consent.grantedScopes,
        grantedAt: consent.grantedAt,
      })),
    });
  });

  fastify.delete('/:id', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [fastify.authenticate, refuseApiKey],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const userId = request.user!.id;

    const consent = await prisma.oidcConsent.findFirst({
      where: { id, userId, revokedAt: null },
      select: { id: true, oidcClientId: true },
    });
    if (!consent) {
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'Connected app not found.' });
    }

    // One transaction: once the consent is gone the client must not be able
    // to keep going on tokens issued under it.
    await prisma.$transaction(async (tx) => {
      const now = new Date();
      const tokens = { userId, oidcClientId: consent.oidcClientId, revokedAt: null };
      await tx.oidcConsent.update({ where: { id: consent.id }, data: { revokedAt: now } });
      const refresh = await tx.oidcRefreshToken.updateMany({ where: tokens, data: { revokedAt: now } });
      const access = await tx.oidcAccessToken.updateMany({ where: tokens, data: { revokedAt: now } });
      // An authorization code issued a moment ago could still be redeemed
      // for fresh tokens; marking it used makes /token refuse it.
      await tx.oidcAuthCode.updateMany({
        where: { userId, oidcClientId: consent.oidcClientId, usedAt: null },
        data: { usedAt: now },
      });
      await tx.auditLog.create({
        data: {
          organizationId: request.user!.orgId,
          userId,
          action: CONSENT_REVOKED_AUDIT_ACTION,
          resource: 'OidcClient',
          resourceId: consent.oidcClientId,
          metadata: { revokedRefreshTokens: refresh.count, revokedAccessTokens: access.count },
          ipAddress: null,
        },
      });
    });

    return reply.status(204).send();
  });
}
