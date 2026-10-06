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
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { zodValidator } from '../../middleware/validate.js';
import { authorize } from '../../middleware/authorize.js';
import { rateLimitAuth } from '../../middleware/rateLimit.js';
import { generateSecurityWebhookSecret } from '../../services/security-webhook.js';

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

    const org = await fastify.prisma.organization.update({
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

    await fastify.prisma.organization.update({
      where: { id },
      data: {
        securityWebhookUrl: null,
        securityWebhookSecret: null,
      },
    });

    return reply.status(204).send();
  });
}
