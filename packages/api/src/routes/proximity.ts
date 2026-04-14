import type { FastifyInstance } from 'fastify';
import { zodValidator } from '../middleware/validate.js';
import { rateLimitPublic } from '../middleware/rateLimit.js';
import { proximityAttestationRequestSchema, proximityVerifyRequestSchema } from '@qrauth/shared';
import { ProximityService } from '../services/proximity.js';

export default async function proximityRoutes(fastify: FastifyInstance): Promise<void> {
  const proximityService = new ProximityService(fastify.prisma);

  // -------------------------------------------------------------------------
  // POST /:token — Create a proximity attestation
  // -------------------------------------------------------------------------
  fastify.post('/:token', {
    config: { rateLimit: rateLimitPublic },
    preValidation: zodValidator({ body: proximityAttestationRequestSchema }),
  }, async (request, reply) => {
    const { token } = request.params as { token: string };
    const { clientLat, clientLng } = request.body as { clientLat: number; clientLng: number };

    try {
      const result = await proximityService.createAttestation(token, clientLat, clientLng);
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
    return reply.send(result);
  });
}
