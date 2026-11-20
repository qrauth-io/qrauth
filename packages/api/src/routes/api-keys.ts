import type { ApiKey, PrismaClient } from '@prisma/client';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { createApiKeySchema, rotateApiKeySchema } from '@qrauth/shared';
import { z } from 'zod';
import { zodValidator } from '../middleware/validate.js';
import { authorize } from '../middleware/authorize.js';
import { hashString } from '../lib/crypto.js';
import { sendApiKeyCreatedEmail, sendApiKeyRevokedEmail } from '../lib/email.js';
import { rateLimitAuth } from '../middleware/rateLimit.js';
import { auditContext, recordAudit, type AuditContext } from '../services/audit.js';
import {
  ApiKeyIssueError,
  createOwnedKey,
  keyAuditDetails,
  keyIssuer,
  keyOwners,
  rotateKey,
  type IssuedKey,
} from '../services/api-key-issue.js';

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

const keyIdParamsSchema = z.object({
  id: z.string().min(1),
});

const NOT_FOUND = { statusCode: 404, error: 'Not Found', message: 'API key not found or already revoked.' } as const;

/**
 * Revokes a key that is still active and records apiKey.revoke in the same
 * transaction. False when it was already revoked (no change, no entry).
 */
async function revokeKey(db: Pick<PrismaClient, '$transaction'>, ctx: AuditContext, key: ApiKey): Promise<boolean> {
  return db.$transaction(async (tx) => {
    const { count } = await tx.apiKey.updateMany({
      where: { id: key.id, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    if (count === 0) return false;
    await recordAudit(tx, ctx, {
      organizationId: key.organizationId,
      action: 'apiKey.revoke',
      resource: 'ApiKey',
      resourceId: key.id,
      metadata: keyAuditDetails(key),
    });
    return true;
  });
}

/** The new key, shown once. */
function issuedKeyBody({ key, fullKey }: IssuedKey) {
  return {
    id: key.id,
    key: fullKey, // SHOWN ONCE — instruct caller to store securely
    prefix: key.prefix,
    label: key.label,
    role: key.role,
    createdByUserId: key.createdByUserId,
    createdAt: key.createdAt,
    message: 'Store this key securely — it will not be shown again.',
  };
}

// ---------------------------------------------------------------------------
// Route plugin
// ---------------------------------------------------------------------------

export default async function apiKeyRoutes(fastify: FastifyInstance): Promise<void> {
  const { authenticate } = fastify;

  /** Sends a key notification to the organization's address, without delaying the response. */
  const notify = async (request: FastifyRequest, send: (email: string, name: string) => Promise<unknown>) => {
    const org = await fastify.prisma.organization.findUnique({
      where: { id: request.user!.orgId }, select: { email: true, name: true },
    });
    if (!org?.email) return;
    send(org.email, org.name).catch((err) => {
      fastify.log.error({ err }, 'Failed to send API key email');
    });
  };

  const sendIssueError = (err: unknown, reply: FastifyReply) => {
    if (err instanceof ApiKeyIssueError) return reply.status(err.status).send(err.body);
    throw err;
  };

  // -------------------------------------------------------------------------
  // POST / — Generate a new API key
  // -------------------------------------------------------------------------
  // Returns the full key exactly once. The key is never stored in plain text —
  // only its SHA-256 hash and an 8-char prefix are persisted. The key belongs
  // to the member who creates it (services/api-key-issue.ts).

  fastify.post('/', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
    preValidation: zodValidator({ body: createApiKeySchema }),
  }, async (request, reply) => {
    const body = request.body as z.output<typeof createApiKeySchema>;
    let issued: IssuedKey;
    try {
      issued = await fastify.prisma.$transaction(async (tx) => createOwnedKey(tx, auditContext(request), {
        organizationId: request.user!.orgId,
        issuer: await keyIssuer(tx, request.user!),
        label: body.label ?? null,
        role: body.role,
      }));
    } catch (err) {
      return sendIssueError(err, reply);
    }
    await notify(request, (email, name) => sendApiKeyCreatedEmail(email, name, request.user!.email, issued.key.prefix, issued.key.label));
    return reply.status(201).send(issuedKeyBody(issued));
  });

  // -------------------------------------------------------------------------
  // GET / — List API keys for the organization
  // -------------------------------------------------------------------------
  // Never returns hashes or full keys. Returns safe metadata only, with each
  // key's owner (null for a legacy key created before owners were recorded).

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
        role: true,
        source: true,
        createdByUserId: true,
        lastUsedAt: true,
        createdAt: true,
      },
      orderBy: { createdAt: 'desc' },
    });
    const owners = await keyOwners(fastify.prisma, request.user!.orgId, apiKeys);

    return reply.send({
      data: apiKeys.map((k) => ({ ...k, owner: k.createdByUserId ? owners.get(k.createdByUserId) ?? null : null })),
    });
  });

  // -------------------------------------------------------------------------
  // POST /:id/rotate — Replace a key with a new one owned by the caller
  // -------------------------------------------------------------------------
  // The old key stops working at once. Used to give a legacy key an owner.

  fastify.post('/:id/rotate', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
    preValidation: zodValidator({ params: keyIdParamsSchema, body: rotateApiKeySchema.optional() }),
  }, async (request, reply) => {
    const { id } = request.params as z.infer<typeof keyIdParamsSchema>;
    const { role } = (request.body ?? {}) as z.output<typeof rotateApiKeySchema>;
    let rotated: Awaited<ReturnType<typeof rotateKey>>;
    try {
      rotated = await fastify.prisma.$transaction(async (tx) => rotateKey(tx, auditContext(request), {
        organizationId: request.user!.orgId,
        keyId: id,
        issuer: await keyIssuer(tx, request.user!),
        role,
      }));
    } catch (err) {
      return sendIssueError(err, reply);
    }
    await notify(request, (email, name) => sendApiKeyRevokedEmail(email, name, request.user!.email, rotated.previous.prefix, rotated.previous.label));
    await notify(request, (email, name) => sendApiKeyCreatedEmail(email, name, request.user!.email, rotated.key.prefix, rotated.key.label));
    return reply.status(201).send({ ...issuedKeyBody(rotated), rotatedFrom: rotated.previous.id });
  });

  // -------------------------------------------------------------------------
  // POST /self-revoke — Revoke the API key presented in the request
  // -------------------------------------------------------------------------
  // For `qrauth logout` (ADR-0002 §6). No OWNER/ADMIN gate: it only ever
  // revokes the caller's own key, identified by re-hashing the presented
  // X-API-Key. Callers using a Bearer JWT have no key to revoke → 400.
  fastify.post('/self-revoke', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate],
  }, async (request, reply) => {
    const rawApiKey = request.headers['x-api-key'];
    if (typeof rawApiKey !== 'string' || rawApiKey.length === 0) {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: 'self-revoke requires X-API-Key authentication.',
      });
    }

    const keyHash = hashString(rawApiKey);
    const existing = await fastify.prisma.apiKey.findUnique({ where: { keyHash } });
    if (!existing || existing.revokedAt !== null) {
      return reply.status(404).send(NOT_FOUND);
    }

    // The actor is the key revoking itself.
    const ctx: AuditContext = { ...auditContext(request), actor: { type: 'API_KEY', apiKeyId: existing.id } };
    if (!(await revokeKey(fastify.prisma, ctx, existing))) {
      return reply.status(404).send(NOT_FOUND);
    }

    return reply.send({ message: 'API key revoked.' });
  });

  // -------------------------------------------------------------------------
  // DELETE /:id — Revoke an API key
  // -------------------------------------------------------------------------
  // Soft-deletes by setting revokedAt. The auth middleware already rejects
  // any key whose revokedAt is non-null, so this takes effect immediately.

  fastify.delete('/:id', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
    preValidation: zodValidator({ params: keyIdParamsSchema }),
  }, async (request, reply) => {
    const { id } = request.params as z.infer<typeof keyIdParamsSchema>;

    const existing = await fastify.prisma.apiKey.findFirst({
      where: {
        id,
        organizationId: request.user!.orgId,
        revokedAt: null,
      },
    });

    if (!existing || !(await revokeKey(fastify.prisma, auditContext(request), existing))) {
      return reply.status(404).send(NOT_FOUND);
    }

    await notify(request, (email, name) => sendApiKeyRevokedEmail(email, name, request.user!.email, existing.prefix, existing.label));

    return reply.send({ message: 'API key revoked.' });
  });
}
