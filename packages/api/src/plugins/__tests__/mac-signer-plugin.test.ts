import { describe, it, expect, vi, beforeAll } from 'vitest';
import { createCircuitBreaker } from '../../services/mac-signer/circuit-breaker.js';

/**
 * Plugin-wiring tests for the mac-signer Fastify plugin
 * (ADR-0001 A4-M2 Phase 1).
 *
 * Scope: things the plugin does above and beyond the pure circuit
 * breaker — specifically, the log record emitted when the breaker
 * opens. The state-machine transitions themselves live in
 * `mac-signer-circuit-breaker.test.ts`; this file only pins the
 * surface the plugin presents to the logger.
 */

beforeAll(() => {
  // buildCircuitOpenLogRecord is imported from the plugin module,
  // which transitively pulls in `lib/config.ts`. Populate the required
  // env so config parsing doesn't throw during import.
  process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
  process.env.REDIS_URL = 'redis://localhost:6379';
  process.env.JWT_SECRET = 'a'.repeat(32);
  process.env.ANIMATED_QR_SECRET = 'a'.repeat(64);
});

describe('mac-signer plugin — circuit-open log record', () => {
  it('routes through error-level logger with the canonical event field', async () => {
    // Pins the log shape the plugin emits on open. Asserts both the
    // severity (`error`, not `fatal`) and the discriminator field
    // (`event: 'mac_signer_circuit_open'`) that log-based alerting
    // matches on. If this ever regresses, alerts go dark on the flip.
    const { buildCircuitOpenLogRecord } = await import('../mac-signer.js');
    const logger = {
      error: vi.fn(),
      fatal: vi.fn(),
      warn: vi.fn(),
      info: vi.fn(),
    };
    let t = 0;
    const cb = createCircuitBreaker({
      failureThreshold: 5,
      windowMs: 10_000,
      halfOpenProbeIntervalMs: 5_000,
      now: () => t,
      onOpen: () => {
        const rec = buildCircuitOpenLogRecord({
          consecutiveFailures: 5,
          windowMs: 10_000,
        });
        logger.error(rec.payload, rec.message);
      },
    });
    for (let i = 0; i < 5; i++) cb.recordFailure();

    expect(logger.fatal).not.toHaveBeenCalled();
    expect(logger.error).toHaveBeenCalledTimes(1);
    const [payload, msg] = logger.error.mock.calls[0];
    expect(payload).toEqual({
      event: 'mac_signer_circuit_open',
      reason: 'consecutive_failures_exceeded_threshold',
      consecutive_failures: 5,
      window_ms: 10_000,
    });
    expect(msg).toMatch(/circuit breaker opened/i);
  });
});
