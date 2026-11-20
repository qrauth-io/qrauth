import type { FastifyReply, FastifyRequest } from 'fastify';

import { config } from './config.js';

/**
 * The verification URL a QR code encodes. Depends only on the token, so
 * printed codes keep scanning whatever their style (ADR-0005 D8).
 */
export function buildVerificationUrl(token: string): string {
  if (config.server.isDev) {
    return `http://localhost:${config.server.port}/v/${token}`;
  }
  // WEBAUTHN_ORIGIN, required in production; the local API otherwise.
  return `${config.webauthn.origin}/v/${token}`;
}

/**
 * Org-scope guard: the resource must belong to the caller's organization.
 * On mismatch it sends the canonical 403 envelope and returns false, so
 * handlers can `if (!assertOwnership(row, request, reply)) return;`.
 */
export function assertOwnership(
  resource: { organizationId: string },
  request: FastifyRequest,
  reply: FastifyReply,
): boolean {
  if (resource.organizationId !== request.user!.orgId) {
    reply.status(403).send({
      statusCode: 403,
      error: 'Forbidden',
      message: 'You do not own this QR code.',
    });
    return false;
  }
  return true;
}
