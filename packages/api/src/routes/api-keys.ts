import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { zodValidator } from '../middleware/validate.js';
import { authorize } from '../middleware/authorize.js';
import { generateApiKey } from '../lib/crypto.js';
import { rateLimitAuth } from '../middleware/rateLimit.js';

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

const createApiKeySchema = z.object({
  label: z.string().trim().min(1).max(100).optional(),
});

const deleteApiKeyParamsSchema = z.object({
  id: z.string().min(1),
});

// ---------------------------------------------------------------------------
// Route plugin
// ---------------------------------------------------------------------------

export default async function apiKeyRoutes(fastify: FastifyInstance): Promise<void> {
  const { authenticate } = fastify;

  // -------------------------------------------------------------------------
  // POST / — Generate a new API key
  // -------------------------------------------------------------------------
  // Returns the full key exactly once. The key is never stored in plain text —
  // only its SHA-256 hash and an 8-char prefix are persisted.

  fastify.post('/', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
    preValidation: zodValidator({ body: createApiKeySchema }),
  }, async (request, reply) => {
    const body = request.body as z.infer<typeof createApiKeySchema>;
    const { fullKey, prefix, hash } = generateApiKey();

    const apiKey = await fastify.prisma.apiKey.create({
      data: {
        organizationId: request.user!.orgId,
        keyHash: hash,
        prefix,
        label: body.label ?? null,
      },
    });

    return reply.status(201).send({
      id: apiKey.id,
      key: fullKey, // SHOWN ONCE — instruct caller to store securely
      prefix: apiKey.prefix,
      label: apiKey.label,
      createdAt: apiKey.createdAt,
      message: 'Store this key securely — it will not be shown again.',
    });
  });

  // -------------------------------------------------------------------------
  // GET / — List API keys for the organization
  // -------------------------------------------------------------------------
  // Never returns hashes or full keys. Returns safe metadata only.

  fastify.get('/', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
  }, async (request, reply) => {
    const apiKeys = await fastify.prisma.apiKey.findMany({
      where: {
        organizationId: request.user!.orgId,
        revokedAt: null,
      },
      select: {
        id: true,
        prefix: true,
        label: true,
        lastUsedAt: true,
        createdAt: true,
      },
      orderBy: { createdAt: 'desc' },
    });

    return reply.send({ data: apiKeys });
  });

  // -------------------------------------------------------------------------
  // DELETE /:id — Revoke an API key
  // -------------------------------------------------------------------------
  // Soft-deletes by setting revokedAt. The auth middleware already rejects
  // any key whose revokedAt is non-null, so this takes effect immediately.

  fastify.delete('/:id', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
    preValidation: zodValidator({ params: deleteApiKeyParamsSchema }),
  }, async (request, reply) => {
    const { id } = request.params as z.infer<typeof deleteApiKeyParamsSchema>;

    const existing = await fastify.prisma.apiKey.findFirst({
      where: {
        id,
        organizationId: request.user!.orgId,
        revokedAt: null,
      },
    });

    if (!existing) {
      return reply.status(404).send({
        statusCode: 404,
        error: 'Not Found',
        message: 'API key not found or already revoked.',
      });
    }

    await fastify.prisma.apiKey.update({
      where: { id },
      data: { revokedAt: new Date() },
    });

    return reply.send({ message: 'API key revoked.' });
  });
}
