import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { zodValidator } from '../middleware/validate.js';
import { authorize } from '../middleware/authorize.js';
import { rateLimitAuth } from '../middleware/rateLimit.js';
import { AuditLogService } from '../services/audit.js';
import {
  OidcClientAdminService,
  SELF_SERVE_ALLOWED_SCOPES,
  MAX_OIDC_CLIENTS_PER_ORG,
} from '../services/oidc-client-admin.js';

/**
 * Org-scoped OIDC client CRUD + secret rotation (ADR-0004 D4: the self-serve
 * registration surface for "Sign in with QRAuth").
 *
 * Dashboard-auth routes following the apps.ts precedent: OWNER/ADMIN mutate,
 * MANAGER may also read. The OIDC protocol runtime (oidc-flow.ts) is not
 * touched — these routes only manage the rows it consumes.
 */

const MAX_REDIRECT_URIS = 10;
const MAX_URI_LENGTH = 2000;
const SECRET_NOTICE = 'Store this clientSecret now — it is not retrievable. Only its hash is stored.';

/**
 * Exact-match redirect URI policy (mirrors the schema comment on
 * OidcClient.redirectUris): absolute URI, https: required, loopback
 * (http://localhost / http://127.0.0.1, any port) allowed for native/dev
 * clients, no fragments, no wildcards.
 */
const redirectUriSchema = z
  .string()
  .min(1)
  .max(MAX_URI_LENGTH)
  .superRefine((value, ctx) => {
    if (value.includes('*')) {
      ctx.addIssue({ code: 'custom', message: 'wildcards are not allowed; register each redirect URI exactly' });
      return;
    }
    if (value.includes('#')) {
      ctx.addIssue({ code: 'custom', message: 'redirect URIs must not contain a fragment' });
      return;
    }
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      ctx.addIssue({ code: 'custom', message: 'must be an absolute URI' });
      return;
    }
    // FINDING-004: userinfo in a redirect URI is a credential-leak footgun
    // and has no legitimate OAuth use.
    if (url.username || url.password) {
      ctx.addIssue({ code: 'custom', message: 'redirect URIs must not contain credentials' });
      return;
    }
    const isLoopbackHost = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
    if (url.protocol === 'https:') return;
    if (url.protocol === 'http:' && isLoopbackHost) return;
    ctx.addIssue({
      code: 'custom',
      message: 'https: is required (http: is allowed only for localhost / 127.0.0.1 loopback)',
    });
  });

// FINDING-004 (CWE-1023): duplicates are rejected outright rather than
// silently deduped — consistent with the .strict() posture; redirect URIs
// compare as exact strings (no normalization/lowercasing).
const redirectUrisSchema = z
  .array(redirectUriSchema)
  .min(1)
  .max(MAX_REDIRECT_URIS)
  .refine((uris) => new Set(uris).size === uris.length, {
    message: 'redirectUris must not contain duplicates',
  });

const allowedScopesSchema = z
  .array(z.enum(SELF_SERVE_ALLOWED_SCOPES))
  .min(1)
  .max(SELF_SERVE_ALLOWED_SCOPES.length)
  .refine((scopes) => new Set(scopes).size === scopes.length, {
    message: 'allowedScopes must not contain duplicates',
  })
  .refine((scopes) => scopes.includes('openid'), { message: 'allowedScopes must include "openid"' });

const sectorIdentifierUriSchema = z
  .string()
  .max(MAX_URI_LENGTH)
  .url()
  .refine((value) => value.startsWith('https://'), { message: 'sectorIdentifierUri must use https:' });

export const createOidcClientSchema = z
  .object({
    name: z.string().min(2).max(100),
    redirectUris: redirectUrisSchema,
    allowedScopes: allowedScopesSchema.default(['openid']),
    clientType: z.enum(['public', 'confidential']),
    sectorIdentifierUri: sectorIdentifierUriSchema.optional(),
    idTokenSignedResponseAlg: z.enum(['RS256', 'ES256']).default('RS256'),
  })
  .strict();
export type CreateOidcClientBody = z.infer<typeof createOidcClientSchema>;

// clientId, tier and clientType are immutable via the API — .strict() turns
// any attempt to send them into a 400 instead of silently dropping the key.
export const updateOidcClientSchema = z
  .object({
    name: z.string().min(2).max(100).optional(),
    redirectUris: redirectUrisSchema.optional(),
    allowedScopes: allowedScopesSchema.optional(),
    sectorIdentifierUri: sectorIdentifierUriSchema.nullable().optional(),
    idTokenSignedResponseAlg: z.enum(['RS256', 'ES256']).optional(),
  })
  .strict()
  .refine((body) => Object.keys(body).length > 0, { message: 'at least one field is required' });
export type UpdateOidcClientBody = z.infer<typeof updateOidcClientSchema>;

export default async function oidcClientRoutes(fastify: FastifyInstance): Promise<void> {
  const { authenticate } = fastify;
  const service = new OidcClientAdminService(fastify.prisma);
  const auditService = new AuditLogService(fastify.prisma);

  const notFound = (reply: any) =>
    reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'OIDC client not found' });

  // Audit FINDING-001: sector host must match a registered redirect URI host.
  const sectorHostMismatch = (reply: any) =>
    reply.status(400).send({
      statusCode: 400,
      error: 'Bad Request',
      message: 'sectorIdentifierUri host must match the host of a registered redirect URI',
    });

  // ---------------------------------------------------------------------------
  // POST / — Create client (tier is always CUSTOMER)
  // ---------------------------------------------------------------------------

  fastify.post('/', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
    preValidation: zodValidator({ body: createOidcClientSchema }),
  }, async (request, reply) => {
    const body = request.body as CreateOidcClientBody;
    const orgId = request.user!.orgId;

    // Cap enforcement lives inside the service's Serializable transaction
    // (FINDING-002). FINDING-003: 409 Conflict, reserving 429 for the rate
    // limiter.
    const result = await service.createClient(orgId, body);
    if (result.outcome === 'sector_host_mismatch') return sectorHostMismatch(reply);
    if (result.outcome === 'quota_exceeded') {
      return reply.status(409).send({
        statusCode: 409,
        error: 'Conflict',
        message: `OIDC client limit reached (${MAX_OIDC_CLIENTS_PER_ORG}). Delete an unused client before creating a new one.`,
      });
    }
    const { client, clientSecret } = result;

    await auditService.log({
      organizationId: orgId,
      userId: request.user!.id,
      action: 'oidcClient.create',
      resource: 'OidcClient',
      resourceId: client.id,
      metadata: { clientId: client.clientId, clientType: client.clientType, name: client.name },
    });

    // The plaintext secret appears here and at rotate-secret ONLY — never in
    // any other response, never in logs.
    return reply.status(201).send({
      ...client,
      ...(clientSecret !== null ? { clientSecret, message: SECRET_NOTICE } : {}),
    });
  });

  // ---------------------------------------------------------------------------
  // GET / — List clients (FIRST_PARTY rows are filtered out in the service)
  // ---------------------------------------------------------------------------

  fastify.get('/', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER')],
  }, async (request, reply) => {
    const clients = await service.listClients(request.user!.orgId);
    return reply.send({ data: clients });
  });

  // ---------------------------------------------------------------------------
  // GET /:id — Client detail (org-scoped WHERE; FIRST_PARTY → 404)
  // ---------------------------------------------------------------------------

  fastify.get('/:id', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER')],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const client = await service.getClient(id, request.user!.orgId);
    if (!client) return notFound(reply);
    return reply.send(client);
  });

  // ---------------------------------------------------------------------------
  // PATCH /:id — Update mutable fields
  // ---------------------------------------------------------------------------

  fastify.patch('/:id', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
    preValidation: zodValidator({ body: updateOidcClientSchema }),
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const result = await service.updateClient(id, request.user!.orgId, request.body as UpdateOidcClientBody);
    if (result.outcome === 'not_found') return notFound(reply);
    if (result.outcome === 'sector_host_mismatch') return sectorHostMismatch(reply);
    return reply.send(result.client);
  });

  // ---------------------------------------------------------------------------
  // POST /:id/rotate-secret — Confidential clients only
  // ---------------------------------------------------------------------------

  fastify.post('/:id/rotate-secret', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const result = await service.rotateSecret(id, request.user!.orgId);

    if (result.outcome === 'not_found') return notFound(reply);
    if (result.outcome === 'public_client') {
      return reply.status(400).send({
        statusCode: 400,
        error: 'Bad Request',
        message: 'Public clients have no secret to rotate (PKCE-only).',
      });
    }

    await auditService.log({
      organizationId: request.user!.orgId,
      userId: request.user!.id,
      action: 'oidcClient.rotateSecret',
      resource: 'OidcClient',
      resourceId: id,
    });

    // Single-secret model: the old secret is already invalid at this point.
    return reply.send({ clientSecret: result.clientSecret, message: SECRET_NOTICE });
  });

  // ---------------------------------------------------------------------------
  // DELETE /:id — Hard delete; dependent codes/consents/tokens go via DB cascade
  // ---------------------------------------------------------------------------

  fastify.delete('/:id', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const deleted = await service.deleteClient(id, request.user!.orgId);
    if (!deleted) return notFound(reply);

    await auditService.log({
      organizationId: request.user!.orgId,
      userId: request.user!.id,
      action: 'oidcClient.delete',
      resource: 'OidcClient',
      resourceId: id,
    });

    return reply.status(204).send();
  });
}
