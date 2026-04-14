import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';
import { config } from '../lib/config.js';
import { hashString } from '../lib/crypto.js';

// ---------------------------------------------------------------------------
// Auth plugin
// ---------------------------------------------------------------------------

/**
 * Registers @fastify/jwt and exposes `fastify.authenticate` as a preHandler.
 *
 * Using fastify-plugin ensures the decorator propagates out of the plugin
 * encapsulation scope so every route in the application can access it.
 *
 * Resolution order:
 *   1. `Authorization: Bearer <token>`  →  verify JWT → set request.user
 *   2. `X-API-Key: <key>`              →  hash → lookup → set request.user
 *   3. Neither present                 →  401 Unauthorized
 */
async function authPlugin(fastify: FastifyInstance): Promise<void> {
  // Register JWT support. The validated env config guarantees JWT_SECRET is
  // at least 32 characters, so startup fails fast on misconfiguration.
  await fastify.register(import('@fastify/jwt'), {
    secret: config.auth.jwtSecret,
    sign: { expiresIn: config.auth.jwtExpiresIn, algorithm: 'HS256' },
    verify: { algorithms: ['HS256'] },
  });

  async function authenticate(
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<void> {
    const authHeader = request.headers.authorization;

    // ------------------------------------------------------------------
    // 1. JWT bearer token
    // ------------------------------------------------------------------
    if (authHeader?.startsWith('Bearer ')) {
      try {
        // jwtVerify throws on invalid / expired tokens.
        const payload = await request.jwtVerify<{
          userId: string;
          orgId: string;
          role: string;
          email: string;
        }>();

        request.user = {
          id: payload.userId,
          orgId: payload.orgId,
          role: payload.role,
          email: payload.email,
        };

        return;
      } catch {
        return reply.status(401).send({
          statusCode: 401,
          error: 'Unauthorized',
          message: 'Invalid or expired bearer token.',
        });
      }
    }

    // ------------------------------------------------------------------
    // 2. API key via X-API-Key header
    // ------------------------------------------------------------------
    const rawApiKey = request.headers['x-api-key'];

    if (typeof rawApiKey === 'string' && rawApiKey.length > 0) {
      const keyHash = hashString(rawApiKey);

      const apiKey = await fastify.prisma.apiKey.findUnique({
        where: { keyHash },
      });

      if (!apiKey || apiKey.revokedAt !== null) {
        return reply.status(401).send({
          statusCode: 401,
          error: 'Unauthorized',
          message: 'Invalid or revoked API key.',
        });
      }

      // Update lastUsedAt asynchronously — a failed write is non-critical and
      // must never delay the response.
      fastify.prisma.apiKey
        .update({
          where: { id: apiKey.id },
          data: { lastUsedAt: new Date() },
        })
        .catch((err: unknown) => {
          fastify.log.warn(
            { err, apiKeyId: apiKey.id },
            'Failed to update lastUsedAt for API key',
          );
        });

      request.user = {
        id: 'api-key',
        orgId: apiKey.organizationId,
        role: apiKey.role,
        email: '',
      };

      return;
    }

    // ------------------------------------------------------------------
    // 3. No credentials supplied
    // ------------------------------------------------------------------
    return reply.status(401).send({
      statusCode: 401,
      error: 'Unauthorized',
      message:
        'Authentication required. Provide a Bearer token or X-API-Key header.',
    });
  }

  fastify.decorate('authenticate', authenticate);
}

export const authMiddleware = fp(authPlugin, {
  name: 'qrauth-auth',
});
