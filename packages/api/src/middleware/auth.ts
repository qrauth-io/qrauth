import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';
import { config } from '../lib/config.js';
import { hashString } from '../lib/crypto.js';
import { constantTimeEqualString } from '../lib/constant-time.js';

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
  // Register JWT support with kid-based secret rotation (Audit-4 A4-H2).
  //
  // When JWT_SECRET_PREV is configured, we use @fastify/jwt's secret callback
  // to dispatch based on the token's kid. Otherwise, use a plain string secret.
  const currentKid = config.auth.jwtSecretVersion;
  const prevKid = config.auth.jwtSecretPrevVersion;
  const prevSecret = config.auth.jwtSecretPrev;

  // Determine the secret option: callback (rotation active) or string (normal)
  const secretOption = (prevKid && prevSecret)
    ? ((_request: FastifyRequest, tokenOrHeader: any) => {
        const kid = tokenOrHeader?.header?.kid ?? tokenOrHeader?.kid;
        if (kid && kid === prevKid) return Promise.resolve(prevSecret);
        return Promise.resolve(config.auth.jwtSecret);
      })
    : config.auth.jwtSecret;

  await fastify.register(import('@fastify/jwt'), {
    secret: secretOption as any,
    sign: {
      expiresIn: config.auth.jwtExpiresIn,
      algorithm: 'HS256',
      kid: currentKid,
    },
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

      // Audit-3 C-1: equalize post-lookup timing regardless of DB hit/miss.
      if (!apiKey) {
        constantTimeEqualString(keyHash, '0'.repeat(64));
        return reply.status(401).send({
          statusCode: 401,
          error: 'Unauthorized',
          message: 'Invalid or revoked API key.',
        });
      }

      if (apiKey.revokedAt !== null) {
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
