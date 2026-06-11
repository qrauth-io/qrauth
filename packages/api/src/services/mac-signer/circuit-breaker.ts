/**
 * Circuit breaker for MAC signer RPC calls (ADR-0001 A4-M2 Phase 1).
 *
 * Generic on purpose — factored out from the HTTP client so future signer
 * MAC endpoints (batch, proximity) can reuse the same breaker without
 * re-deriving the rolling-window semantics.
 *
 * States:
 *   closed    — RPC allowed. Failures accumulate in a rolling window; if
 *               at least `failureThreshold` land within `windowMs` the
 *               breaker trips to `open`.
 *   open      — RPC short-circuited. `tryAcquire` returns false until
 *               `halfOpenProbeIntervalMs` has elapsed since the trip.
 *   half_open — exactly one probe is allowed through. Further `tryAcquire`
 *               calls return false until the probe resolves. On success
 *               the breaker closes and the failure deque is cleared. On
 *               failure it re-opens and the probe-interval timer resets.
 *
 * The rolling window uses a timestamp deque (not a running counter) so
 * successes that occur between failures don't artificially reset the
 * window — this matches the ADR's "honest rolling window" requirement.
 * Failures older than `windowMs` are evicted on every read of the deque.
 */

export type CircuitBreakerState = 'closed' | 'open' | 'half_open';

export interface CircuitBreaker {
  /** Reserve a slot to attempt the call. Returns false if the breaker is
   *  open, or if it is half-open and a probe is already in flight. */
  tryAcquire(): boolean;
  recordSuccess(): void;
  recordFailure(): void;
  state(): CircuitBreakerState;
  stats(): {
    opens: number;
    currentFailures: number;
    lastOpenedAt: number | null;
    /** Total wall-clock seconds spent in non-closed state since construction. */
    fallbackSeconds: number;
  };
  /** Release any internal resources (currently none — no timers are held). */
  dispose(): void;
}

export interface CircuitBreakerOptions {
  failureThreshold: number;
  windowMs: number;
  halfOpenProbeIntervalMs: number;
  now?: () => number;
  /** Fired exactly once per closed→open transition. */
  onOpen?: () => void;
}

export function createCircuitBreaker(opts: CircuitBreakerOptions): CircuitBreaker {
  const now = opts.now ?? (() => Date.now());

  let stateValue: CircuitBreakerState = 'closed';
  const failureTimestamps: number[] = [];
  let opens = 0;
  let lastOpenedAt: number | null = null;
  let probeInFlight = false;
  let fallbackAccumulatedMs = 0;
  let lastStateChangeAt: number = now();

  function prune(cutoff: number): void {
    while (failureTimestamps.length > 0 && failureTimestamps[0] < cutoff) {
      failureTimestamps.shift();
    }
  }

  function transitionTo(next: CircuitBreakerState): void {
    const t = now();
    if (stateValue !== 'closed') {
      fallbackAccumulatedMs += t - lastStateChangeAt;
    }
    stateValue = next;
    lastStateChangeAt = t;
  }

  function trip(): void {
    if (stateValue === 'open') return;
    transitionTo('open');
    opens += 1;
    lastOpenedAt = lastStateChangeAt;
    probeInFlight = false;
    opts.onOpen?.();
  }

  return {
    tryAcquire(): boolean {
      const t = now();
      if (stateValue === 'closed') return true;
      if (stateValue === 'open') {
        if (lastOpenedAt !== null && t - lastOpenedAt >= opts.halfOpenProbeIntervalMs) {
          transitionTo('half_open');
          probeInFlight = true;
          return true;
        }
        return false;
      }
      // half_open — allow exactly one probe at a time.
      if (probeInFlight) return false;
      probeInFlight = true;
      return true;
    },

    recordSuccess(): void {
      if (stateValue === 'half_open') {
        probeInFlight = false;
        failureTimestamps.length = 0;
        transitionTo('closed');
        return;
      }
      // In closed state, a success does not prune the window — only time
      // does. This is the "honest rolling window" behaviour: five failures
      // followed by a success still means five failures, and the sixth
      // (if it lands in-window) still opens the breaker.
    },

    recordFailure(): void {
      const t = now();
      if (stateValue === 'half_open') {
        probeInFlight = false;
        // Re-open and reset the probe clock.
        transitionTo('open');
        opens += 1;
        lastOpenedAt = lastStateChangeAt;
        opts.onOpen?.();
        return;
      }
      if (stateValue === 'open') {
        // Shouldn't happen — callers check tryAcquire first — but be
        // defensive: refresh the trip timestamp so the probe interval
        // measures from the latest failure.
        lastOpenedAt = t;
        return;
      }
      failureTimestamps.push(t);
      prune(t - opts.windowMs);
      if (failureTimestamps.length >= opts.failureThreshold) {
        trip();
      }
    },

    state(): CircuitBreakerState {
      return stateValue;
    },

    stats() {
      const t = now();
      prune(t - opts.windowMs);
      let fallbackMs = fallbackAccumulatedMs;
      if (stateValue !== 'closed') {
        fallbackMs += t - lastStateChangeAt;
      }
      return {
        opens,
        currentFailures: failureTimestamps.length,
        lastOpenedAt,
        fallbackSeconds: Math.floor(fallbackMs / 1000),
      };
    },

    dispose(): void {
      // No timers held — probe scheduling is lazy via tryAcquire. Method
      // exists so the plugin onClose hook has a symmetric disposal surface.
    },
  };
}
