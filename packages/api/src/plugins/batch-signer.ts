import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import { BatchSigner } from '../services/batch-signer.js';
import {
  LocalSlhDsaSigner,
  HttpSlhDsaSigner,
  type SlhDsaSigner,
} from '../services/slhdsa-signer/index.js';
import { config } from '../lib/config.js';

declare module 'fastify' {
  interface FastifyInstance {
    batchSigner: BatchSigner;
  }
}

/**
 * Registers a single process-wide BatchSigner.
 *
 * Multiple route plugins (qrcodes, verify, demo) need a HybridSigningService,
 * and they MUST share the same BatchSigner instance — otherwise concurrent
 * QR creations from different routes wouldn't accumulate into the same
 * Merkle batch and the whole amortization disappears.
 *
 * The SLH-DSA backend is chosen by `SLH_DSA_SIGNER` env var:
 *   - "local" (default): in-process signer, loads keys from disk. Dev only.
 *   - "http": remote signer service over HTTP, no key bytes on this host.
 *     Production deployments should set this and run the signer service
 *     on a separate machine — see ALGORITHM.md §13.1.
 *
 * The plugin also wires an onClose hook so SIGTERM drains pending items
 * before the process exits. Without this, in-flight QR creates would hang
 * waiting for a flush that never happens.
 */
async function batchSignerPlugin(fastify: FastifyInstance): Promise<void> {
  const signingService = fastify.signingService;

  let signer: SlhDsaSigner;
  if (config.slhdsaSigner.backend === 'http') {
    if (!config.slhdsaSigner.url || !config.slhdsaSigner.token) {
      throw new Error(
        'SLH_DSA_SIGNER=http requires SLH_DSA_SIGNER_URL and SLH_DSA_SIGNER_TOKEN to be set',
      );
    }
    fastify.log.info(
      { signer: 'http', url: config.slhdsaSigner.url },
      'SLH-DSA signing delegated to remote signer service',
    );
    signer = new HttpSlhDsaSigner(config.slhdsaSigner.url, config.slhdsaSigner.token);
  } else {
    fastify.log.warn(
      'SLH-DSA signing using LOCAL backend — private keys live on this host. ' +
        'Set SLH_DSA_SIGNER=http for production hardening (ALGORITHM.md §13.1).',
    );
    signer = new LocalSlhDsaSigner(signingService);
  }

  const batchSigner = new BatchSigner(fastify.prisma, signer, {
    maxBatchSize: 64,
    maxWaitMs: 200,
  });

  fastify.decorate('batchSigner', batchSigner);

  fastify.addHook('onClose', async () => {
    fastify.log.info('flushing BatchSigner pending queues…');
    await batchSigner.flushAll();
    fastify.log.info('BatchSigner drained');
  });
}

export default fp(batchSignerPlugin, { name: 'batch-signer', dependencies: ['ecdsa-signer'] });
