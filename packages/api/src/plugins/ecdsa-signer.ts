import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import { SigningService } from '../services/signing.js';
import {
  LocalEcdsaSigner,
  HttpEcdsaSigner,
  type EcdsaSigner,
} from '../services/ecdsa-signer/index.js';
import { config } from '../lib/config.js';

declare module 'fastify' {
  interface FastifyInstance {
    ecdsaSigner: EcdsaSigner;
    signingService: SigningService;
  }
}

/**
 * ADR-001 / N-10: process-wide ECDSA signer selection.
 *
 * Mirrors the SLH-DSA pattern in batch-signer.ts. Reads ECDSA_SIGNER
 * env var at boot and decorates the Fastify instance with:
 *   - ecdsaSigner: the selected EcdsaSigner backend
 *   - signingService: a SigningService wired to that backend
 *
 * All route plugins MUST use fastify.signingService instead of
 * constructing their own SigningService.
 */
async function ecdsaSignerPlugin(fastify: FastifyInstance): Promise<void> {
  let signer: EcdsaSigner;

  if (config.ecdsaSigner.backend === 'http') {
    if (!config.ecdsaSigner.url || !config.ecdsaSigner.token) {
      throw new Error(
        'ECDSA_SIGNER=http requires ECDSA_SIGNER_URL and ECDSA_SIGNER_TOKEN to be set',
      );
    }
    fastify.log.info(
      { signer: 'http', url: config.ecdsaSigner.url },
      'ECDSA signing delegated to remote signer service',
    );
    signer = new HttpEcdsaSigner(config.ecdsaSigner.url, config.ecdsaSigner.token);
  } else {
    fastify.log.warn(
      'ECDSA signing using LOCAL backend — private keys live on this host. ' +
        'Set ECDSA_SIGNER=http for production hardening (ADR-001).',
    );
    signer = new LocalEcdsaSigner();
  }

  fastify.decorate('ecdsaSigner', signer);
  fastify.decorate('signingService', new SigningService(fastify.prisma, signer));
}

export default fp(ecdsaSignerPlugin, {
  name: 'ecdsa-signer',
});
