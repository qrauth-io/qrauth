import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import {
  HttpMacSignerClient,
  NoopMacSignerClient,
  createCircuitBreaker,
  createMacSignerStatsCollector,
  type CircuitBreaker,
  type MacSignerClient,
  type MacSignerStats,
  type MacSignerStatsCollector,
} from '../services/mac-signer/index.js';
import { config } from '../lib/config.js';

declare module 'fastify' {
  interface FastifyInstance {
    macSigner: MacSignerClient;
    macSignerBackend: 'local' | 'dual' | 'signer';
    macSignerStats: () => MacSignerStats;
    macSignerStatsCollector: MacSignerStatsCollector;
  }
}

/**
 * Exposed so unit tests can pin the log shape without spinning up the
 * full plugin + HTTP client + fetch mocks. The plugin's onOpen callback
 * emits this payload verbatim at `error` level.
 */
export function buildCircuitOpenLogRecord(args: {
  consecutiveFailures: number;
  windowMs: number;
}): { payload: Record<string, unknown>; message: string } {
  return {
    payload: {
      event: 'mac_signer_circuit_open',
      reason: 'consecutive_failures_exceeded_threshold',
      consecutive_failures: args.consecutiveFailures,
      window_ms: args.windowMs,
    },
    message: 'MAC signer circuit breaker opened — failing over to local-only derivation',
  };
}

/**
 * ADR-0001 A4-M2 Phase 1 — MAC signer plugin.
 *
 * Selects the signer client based on `MAC_BACKEND` and decorates the
 * Fastify instance with:
 *   - macSigner                — the selected client
 *   - macSignerBackend         — env value for observability / branching
 *   - macSignerStatsCollector  — used by the dual-derive comparator
 *   - macSignerStats()         — read-only snapshot for /internal/mac-stats
 *
 * Phase 1 is *observation only*: the animated-QR route still treats local
 * HKDF derivation as authoritative. This plugin just ensures a real
 * client exists when `MAC_BACKEND=dual|signer`, with the full resilience
 * envelope (deadline, retries, breaker) already wired.
 */
async function macSignerPlugin(fastify: FastifyInstance): Promise<void> {
  const backend = config.macSigner.backend;

  let client: MacSignerClient;
  let circuit: CircuitBreaker | null = null;

  if (backend === 'local') {
    fastify.log.info(
      { backend: 'local' },
      'MAC signer = LOCAL — animated-QR frame secrets derived in-process from ANIMATED_QR_SECRET',
    );
    client = new NoopMacSignerClient();
  } else {
    if (!config.macSigner.url || !config.macSigner.token) {
      throw new Error(
        `MAC_BACKEND=${backend} requires SIGNER_MAC_URL and SIGNER_MAC_TOKEN to be set`,
      );
    }
    if (backend === 'signer') {
      fastify.log.warn(
        'MAC_BACKEND=signer active — Phase 2 cutover posture. ' +
          'Ensure Phase 1 divergence window has closed cleanly.',
      );
    } else {
      fastify.log.info(
        { backend, url: config.macSigner.url },
        'MAC signer = DUAL — local derivation authoritative, shadow-calling signer',
      );
    }

    circuit = createCircuitBreaker({
      failureThreshold: config.macSigner.cbThreshold,
      windowMs: config.macSigner.cbWindowMs,
      halfOpenProbeIntervalMs: config.macSigner.cbHalfOpenMs,
      onOpen: () => {
        // Severity: `error`, not `fatal`. A tripped breaker with a live
        // fail-open fallback is a degraded state, not a process-death
        // signal. The structured `event` field is the discriminator
        // that the log-query alert rule will match on.
        //
        // TODO(phase-next): route this through a dedicated
        // `sendInfraAlert(reason, context)` helper once the alerts
        // worker gains an infra-alert channel. Tracked in the A4-M2
        // Phase 1 review fix-ups commit — until then the log-query
        // alert is the paging surface.
        const rec = buildCircuitOpenLogRecord({
          consecutiveFailures: config.macSigner.cbThreshold,
          windowMs: config.macSigner.cbWindowMs,
        });
        fastify.log.error(rec.payload, rec.message);
      },
    });

    const statsCollector = createMacSignerStatsCollector({ backend, circuit });
    client = new HttpMacSignerClient({
      baseUrl: config.macSigner.url,
      token: config.macSigner.token,
      tokenNext: config.macSigner.tokenNext,
      deadlineMsPerAttempt: config.macSigner.deadlineMs,
      maxRetries: config.macSigner.maxRetries,
      overallBudgetMs: config.macSigner.overallBudgetMs,
      circuit,
      stats: statsCollector,
      logger: {
        warn: (obj, msg) => fastify.log.warn(obj, msg),
        error: (obj, msg) => fastify.log.error(obj, msg),
      },
    });

    fastify.decorate('macSigner', client);
    fastify.decorate('macSignerBackend', backend);
    fastify.decorate('macSignerStatsCollector', statsCollector);
    fastify.decorate('macSignerStats', () => statsCollector.snapshot());
    fastify.addHook('onClose', async () => {
      circuit?.dispose();
    });
    return;
  }

  // Local path: still needs a stats collector so the /internal/mac-stats
  // route can return a consistent shape.
  const statsCollector = createMacSignerStatsCollector({ backend, circuit: null });
  fastify.decorate('macSigner', client);
  fastify.decorate('macSignerBackend', backend);
  fastify.decorate('macSignerStatsCollector', statsCollector);
  fastify.decorate('macSignerStats', () => statsCollector.snapshot());
}

export default fp(macSignerPlugin, {
  name: 'mac-signer',
});
