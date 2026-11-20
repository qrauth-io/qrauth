/**
 * Security-webhook registration endpoint (Audit-2 M-13 / SECURITY.md §5).
 *
 * Owners and admins register the HTTPS endpoint their organization
 * operates to receive signing-key lifecycle events. On registration
 * we generate a fresh 32-byte secret, persist the URL + secret on the
 * Organization row, and return the plaintext secret exactly once so
 * the caller can stash it on their verifier side. Re-posting to this
 * endpoint re-mints the secret; there is no "read my secret" GET.
 *
 * Route path is registered by the server under `/api/v1/organizations`,
 * so the full public URL is
 *   POST /api/v1/organizations/:id/security-webhook
 * matching the plan spec.
 */
import { createHash } from 'node:crypto';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { zodValidator } from '../../middleware/validate.js';
import { authorize } from '../../middleware/authorize.js';
import { rateLimitAuth } from '../../middleware/rateLimit.js';
import { generateSecurityWebhookSecret } from '../../services/security-webhook.js';
import { auditContext, recordAudit } from '../../services/audit.js';

const registerSecurityWebhookSchema = z.object({
  url: z
    .string()
    .url()
    .refine((u) => {
      let parsed: URL;
      try {
        parsed = new URL(u);
      } catch {
        return false;
      }
      if (parsed.protocol === 'https:') return true;
      // Narrow dev/test bypass: allow http:// on loopback literals
      // outside production so the E2E suite can register a local
      // capture server. Production still requires https://.
      if (process.env.NODE_ENV !== 'production' && parsed.protocol === 'http:') {
        const host = parsed.hostname.toLowerCase();
        if (host === '127.0.0.1' || host === 'localhost' || host === '::1') {
          return true;
        }
      }
      return false;
    }, 'Security webhook URL must use https:// (http://localhost allowed in dev/test only)'),
});

/** Hex characters of the URL's SHA-256 kept in audit entries, enough to tell two endpoints apart. */
export const WEBHOOK_URL_HASH_LENGTH = 12;

/**
 * How an endpoint appears in the audit log: its host and a short hash of
 * the full URL, never the URL (paths and query strings can carry tokens).
 */
export function webhookAuditRef(url: string | null | undefined): { host: string; urlHash: string } | null {
  if (!url) return null;
  let host: string;
  try {
    host = new URL(url).host;
  } catch {
    host = 'invalid';
  }
  return { host, urlHash: createHash('sha256').update(url).digest('hex').slice(0, WEBHOOK_URL_HASH_LENGTH) };
}

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

export default async function securityWebhookRoutes(fastify: FastifyInstance): Promise<void> {
  const authenticate = fastify.authenticate;

  // -------------------------------------------------------------------------
  // POST /:id/security-webhook — Register or rotate the security webhook
  // -------------------------------------------------------------------------

  fastify.post('/:id/security-webhook', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
    preValidation: zodValidator({ body: registerSecurityWebhookSchema }),
  }, async (request, reply) => {
    checkOrgAccess(request);

    const { id } = request.params as { id: string };
    const { url } = request.body as { url: string };

    const secret = generateSecurityWebhookSecret();

    // The secret is never written to the audit log.
    const org = await fastify.prisma.$transaction(async (tx) => {
      const before = await tx.organization.findUnique({ where: { id }, select: { securityWebhookUrl: true } });
      const updated = await tx.organization.update({
        where: { id },
        data: {
          securityWebhookUrl: url,
          securityWebhookSecret: secret,
        },
        select: {
          id: true,
          securityWebhookUrl: true,
          updatedAt: true,
        },
      });
      await recordAudit(tx, auditContext(request), {
        organizationId: id,
        action: 'securityWebhook.update',
        resource: 'Organization',
        resourceId: id,
        metadata: { endpoint: { before: webhookAuditRef(before?.securityWebhookUrl), after: webhookAuditRef(url) }, secretRotated: true },
      });
      return updated;
    });

    return reply.status(201).send({
      organizationId: org.id,
      url: org.securityWebhookUrl,
      // Returned exactly once. Integrators must persist this value on
      // their side — we never echo it again.
      secret,
      updatedAt: org.updatedAt,
    });
  });

  // -------------------------------------------------------------------------
  // DELETE /:id/security-webhook — Unregister the endpoint
  // -------------------------------------------------------------------------

  fastify.delete('/:id/security-webhook', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
  }, async (request, reply) => {
    checkOrgAccess(request);

    const { id } = request.params as { id: string };

    await fastify.prisma.$transaction(async (tx) => {
      const before = await tx.organization.findUnique({ where: { id }, select: { securityWebhookUrl: true } });
      await tx.organization.update({
        where: { id },
        data: {
          securityWebhookUrl: null,
          securityWebhookSecret: null,
        },
      });
      // Nothing was registered: no change, no entry.
      if (!before?.securityWebhookUrl) return;
      await recordAudit(tx, auditContext(request), {
        organizationId: id,
        action: 'securityWebhook.delete',
        resource: 'Organization',
        resourceId: id,
        metadata: { endpoint: webhookAuditRef(before.securityWebhookUrl) },
      });
    });

    return reply.status(204).send();
  });
}
