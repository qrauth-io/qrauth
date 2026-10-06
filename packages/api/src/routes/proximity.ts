import type { FastifyInstance } from 'fastify';
import { zodValidator } from '../middleware/validate.js';
import { rateLimitPublic } from '../middleware/rateLimit.js';
import { proximityAttestationRequestSchema, proximityVerifyRequestSchema } from '@qrauth/shared';
import { ProximityService } from '../services/proximity.js';

export default async function proximityRoutes(fastify: FastifyInstance): Promise<void> {
  const signingService = fastify.signingService;
  const proximityService = new ProximityService(fastify.prisma, signingService);

  // -------------------------------------------------------------------------
  // POST /:token — Create a proximity attestation
  // -------------------------------------------------------------------------
  fastify.post('/:token', {
    config: { rateLimit: rateLimitPublic },
    preValidation: zodValidator({ body: proximityAttestationRequestSchema }),
  }, async (request, reply) => {
    const { token } = request.params as { token: string };
    const body = request.body as {
      clientLat: number;
      clientLng: number;
      rpId: string;
      deviceFingerprint: string;
    };

    try {
      const result = await proximityService.createAttestation({
        token,
        // AUDIT-FINDING-006: location is client-reported; hardware attestation is a separate work stream.
        clientLat: body.clientLat,
        clientLng: body.clientLng,
        rpId: body.rpId,
        deviceFingerprint: body.deviceFingerprint,
      });
      return reply.send(result);
    } catch (err: unknown) {
      const statusCode = (err as { statusCode?: number }).statusCode ?? 500;
      const message = err instanceof Error ? err.message : 'Unknown error';
      return reply.status(statusCode).send({ statusCode, error: 'Error', message });
    }
  });

  // -------------------------------------------------------------------------
  // POST /verify — Verify a proximity attestation JWT
  // -------------------------------------------------------------------------
  fastify.post('/verify', {
    config: { rateLimit: rateLimitPublic },
    preValidation: zodValidator({ body: proximityVerifyRequestSchema }),
  }, async (request, reply) => {
    const { jwt, publicKey } = request.body as { jwt: string; publicKey?: string };

    const result = await proximityService.verifyAttestation(jwt, publicKey);

    // AUDIT-FINDING-026: collapse post-structural-parse failures to a
    // single opaque error string for external callers. Server-side log
    // the `debug` detail before dropping it from the response.
    if (!result.valid && result.debug) {
      request.log.warn(
        { jwt: jwt.slice(0, 40), debug: result.debug },
        'proximity verify rejected',
      );
    }
    return reply.send({
      valid: result.valid,
      claims: result.claims,
      error: result.error,
    });
  });
}
