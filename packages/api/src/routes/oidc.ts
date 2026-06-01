import type { FastifyInstance } from 'fastify';
import { config } from '../lib/config.js';
import {
  QRAUTH_PLATFORM_ORG_SLUG,
  buildDiscoveryDocument,
  signingKeyToJwk,
} from '../lib/oidc-metadata.js';

/**
 * OIDC Provider well-known endpoints (ADR-0003, Phase 1 Slice 2).
 *
 * Registered under the `/.well-known` prefix. Both endpoints are PUBLIC
 * (no `fastify.authenticate` preHandler) per OIDC Discovery 1.0 — RPs fetch
 * them unauthenticated. No auth-flow logic here: /authorize, /token,
 * /userinfo, /register are advertised in discovery but implemented in later
 * slices, and the nginx vhost continues to 404 them until then.
 */
export default async function oidcRoutes(fastify: FastifyInstance): Promise<void> {
  // GET /.well-known/openid-configuration — OIDC Discovery 1.0 §3 metadata.
  fastify.get('/openid-configuration', async (_request, reply) => {
    reply.header('Cache-Control', 'public, max-age=3600');
    reply.type('application/json');
    return buildDiscoveryDocument(config.oidc.issuer);
  });

  // GET /.well-known/jwks.json — public key set for ID token verification.
  // Publishes every currently-valid (ACTIVE or recently-ROTATED, not REVOKED)
  // ES256 + RS256 key on the QRAuth Platform org (ADR-0003 Slice 7b: RS256 is
  // now the default ID-token alg; ES256 stays for opt-in clients), so RP
  // verification keeps working across both algs and rotation transitions.
  // RPs select the matching key by `kid` + `alg`. REVOKED keys are excluded.
  fastify.get('/jwks.json', async (_request, reply) => {
    const rows = await fastify.prisma.signingKey.findMany({
      where: {
        organization: { slug: QRAUTH_PLATFORM_ORG_SLUG },
        algorithm: { in: ['ES256', 'RS256'] },
        status: { in: ['ACTIVE', 'ROTATED'] },
      },
      orderBy: { createdAt: 'desc' },
      select: { keyId: true, publicKey: true, algorithm: true },
    });

    const keys = await Promise.all(
      rows.map((row) => signingKeyToJwk(row.publicKey, row.keyId, row.algorithm)),
    );

    reply.header('Cache-Control', 'public, max-age=300');
    reply.type('application/json');
    return { keys };
  });
}
