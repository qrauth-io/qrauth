import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import { SigningService } from '../services/signing.js';
import {
  LocalEcdsaSigner,
  HttpEcdsaSigner,
  type EcdsaSigner,
} from '../services/ecdsa-signer/index.js';
import {
  LocalRsaSigner,
  HttpRsaSigner,
  type RsaSigner,
} from '../services/rsa-signer/index.js';
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
  // ADR-0003 Slice 7b: RSA signer for OIDC RS256 ID tokens. Reuses the ECDSA
  // backend decision — the /v1/sign-rsa-jws endpoint lives on the same signer
  // host, so there's no scenario where ECDSA is remote but RSA is local. This
  // avoids a separate boot-required env (no RSA_SIGNER var to forget to set).
  let rsaSigner: RsaSigner;

  if (config.ecdsaSigner.backend === 'http') {
    if (!config.ecdsaSigner.url || !config.ecdsaSigner.token) {
      throw new Error(
        'ECDSA_SIGNER=http requires ECDSA_SIGNER_URL and ECDSA_SIGNER_TOKEN to be set',
      );
    }
    fastify.log.info(
      { signer: 'http', url: config.ecdsaSigner.url },
      'ECDSA + RSA signing delegated to remote signer service',
    );
    signer = new HttpEcdsaSigner(config.ecdsaSigner.url, config.ecdsaSigner.token);
    rsaSigner = new HttpRsaSigner(config.ecdsaSigner.url, config.ecdsaSigner.token);
  } else {
    fastify.log.warn(
      'ECDSA + RSA signing using LOCAL backend — private keys live on this host. ' +
        'Set ECDSA_SIGNER=http for production hardening (ADR-001).',
    );
    signer = new LocalEcdsaSigner();
    rsaSigner = new LocalRsaSigner();
  }

  fastify.decorate('ecdsaSigner', signer);
  fastify.decorate('signingService', new SigningService(fastify.prisma, signer, rsaSigner));
}

export default fp(ecdsaSignerPlugin, {
  name: 'ecdsa-signer',
});
