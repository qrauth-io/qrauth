import type { CircuitBreaker } from './circuit-breaker.js';

/**
 * In-process MAC signer counters (ADR-0001 A4-M2 Phase 1).
 *
 * Exposed via `GET /internal/mac-stats` and read by the daily agent during
 * the Phase 1 observation window. Not Prometheus-exported — Phase 1 does
 * not introduce a new scrape surface. A bucketed histogram is used for
 * `rpc_duration_ms` so the snapshot can compute p50/p95/p99 on read
 * without holding per-sample state.
 */

export interface MacSignerStats {
  backend: 'local' | 'dual' | 'signer';
  register: {
    ok: number;
    failure_conflict: number;
    failure_full: number;
    failure_transport: number;
  };
  sign: {
    ok: number;
    session_not_found: number;
    transport_failure: number;
  };
  verify: {
    ok_valid: number;
    ok_invalid: number;
    session_expired: number;
    transport_failure: number;
  };
  circuit: {
    state: 'closed' | 'open' | 'half_open';
    opens: number;
    fallback_seconds: number;
  };
  dual: {
    frames_observed: number;
    divergence: number;
  };
  rpc_duration_ms: {
    count: number;
    sum: number;
    p50: number;
    p95: number;
    p99: number;
  };
}

export type RegisterOutcome = 'ok' | 'conflict' | 'full' | 'transport';
export type SignOutcome = 'ok' | 'session_not_found' | 'transport';
export type VerifyOutcome = 'ok_valid' | 'ok_invalid' | 'session_expired' | 'transport';

export interface MacSignerStatsCollector {
  recordRegister(outcome: RegisterOutcome): void;
  recordSign(outcome: SignOutcome): void;
  recordVerify(outcome: VerifyOutcome): void;
  recordDual(match: boolean): void;
  recordDivergence(): void;
  recordRpcDurationMs(ms: number): void;
  snapshot(): MacSignerStats;
}

const BUCKET_UPPER_BOUNDS_MS = [5, 10, 25, 50, 100, 150, 200, Number.POSITIVE_INFINITY];

export function createMacSignerStatsCollector(args: {
  backend: 'local' | 'dual' | 'signer';
  circuit: CircuitBreaker | null;
}): MacSignerStatsCollector {
  const register = { ok: 0, failure_conflict: 0, failure_full: 0, failure_transport: 0 };
  const sign = { ok: 0, session_not_found: 0, transport_failure: 0 };
  const verify = { ok_valid: 0, ok_invalid: 0, session_expired: 0, transport_failure: 0 };
  const dual = { frames_observed: 0, divergence: 0 };

  const buckets = new Array(BUCKET_UPPER_BOUNDS_MS.length).fill(0) as number[];
  let durationCount = 0;
  let durationSum = 0;

  function percentile(p: number): number {
    if (durationCount === 0) return 0;
    const target = Math.ceil(p * durationCount);
    let running = 0;
    for (let i = 0; i < buckets.length; i++) {
      running += buckets[i];
      if (running >= target) {
        const upper = BUCKET_UPPER_BOUNDS_MS[i];
        return Number.isFinite(upper) ? upper : BUCKET_UPPER_BOUNDS_MS[i - 1];
      }
    }
    return 0;
  }

  return {
    recordRegister(outcome): void {
      switch (outcome) {
        case 'ok':
          register.ok += 1;
          break;
        case 'conflict':
          register.failure_conflict += 1;
          break;
        case 'full':
          register.failure_full += 1;
          break;
        case 'transport':
          register.failure_transport += 1;
          break;
      }
    },

    recordSign(outcome): void {
      switch (outcome) {
        case 'ok':
          sign.ok += 1;
          break;
        case 'session_not_found':
          sign.session_not_found += 1;
          break;
        case 'transport':
          sign.transport_failure += 1;
          break;
      }
    },

    recordVerify(outcome): void {
      switch (outcome) {
        case 'ok_valid':
          verify.ok_valid += 1;
          break;
        case 'ok_invalid':
          verify.ok_invalid += 1;
          break;
        case 'session_expired':
          verify.session_expired += 1;
          break;
        case 'transport':
          verify.transport_failure += 1;
          break;
      }
    },

    recordDual(_match): void {
      dual.frames_observed += 1;
    },

    recordDivergence(): void {
      dual.divergence += 1;
    },

    recordRpcDurationMs(ms): void {
      durationCount += 1;
      durationSum += ms;
      for (let i = 0; i < BUCKET_UPPER_BOUNDS_MS.length; i++) {
        if (ms <= BUCKET_UPPER_BOUNDS_MS[i]) {
          buckets[i] += 1;
          return;
        }
      }
    },

    snapshot(): MacSignerStats {
      const cbStats = args.circuit?.stats() ?? {
        opens: 0,
        currentFailures: 0,
        lastOpenedAt: null,
        fallbackSeconds: 0,
      };
      return {
        backend: args.backend,
        register: { ...register },
        sign: { ...sign },
        verify: { ...verify },
        circuit: {
          state: args.circuit?.state() ?? 'closed',
          opens: cbStats.opens,
          fallback_seconds: cbStats.fallbackSeconds,
        },
        dual: { ...dual },
        rpc_duration_ms: {
          count: durationCount,
          sum: Math.round(durationSum),
          p50: percentile(0.5),
          p95: percentile(0.95),
          p99: percentile(0.99),
        },
      };
    },
  };
}
