import { describe, it, expect, vi } from 'vitest';
import { createCircuitBreaker } from '../mac-signer/circuit-breaker.js';

/**
 * Unit tests for the generic CircuitBreaker (ADR-0001 A4-M2 Phase 1).
 *
 * All tests use an injected `now()` so transitions are deterministic —
 * we never touch `vi.useFakeTimers`, per
 * `reference_vitest_lru_cache_timers.md`.
 */
describe('createCircuitBreaker', () => {
  const OPTS = {
    failureThreshold: 5,
    windowMs: 10_000,
    halfOpenProbeIntervalMs: 5_000,
  };

  function makeClock(start = 0) {
    let t = start;
    return {
      now: () => t,
      advance: (ms: number) => {
        t += ms;
      },
      set: (ms: number) => {
        t = ms;
      },
    };
  }

  it('4 failures keep the breaker closed', () => {
    const clock = makeClock();
    const cb = createCircuitBreaker({ ...OPTS, now: clock.now });
    for (let i = 0; i < 4; i++) cb.recordFailure();
    expect(cb.state()).toBe('closed');
    expect(cb.tryAcquire()).toBe(true);
  });

  it('5 failures open the breaker and fire onOpen exactly once', () => {
    const clock = makeClock();
    const onOpen = vi.fn();
    const cb = createCircuitBreaker({ ...OPTS, now: clock.now, onOpen });
    for (let i = 0; i < 5; i++) cb.recordFailure();
    expect(cb.state()).toBe('open');
    expect(onOpen).toHaveBeenCalledTimes(1);
    // extra failures should not re-fire onOpen
    cb.recordFailure();
    expect(onOpen).toHaveBeenCalledTimes(1);
  });

  it('open → tryAcquire returns false before probe interval', () => {
    const clock = makeClock();
    const cb = createCircuitBreaker({ ...OPTS, now: clock.now });
    for (let i = 0; i < 5; i++) cb.recordFailure();
    expect(cb.tryAcquire()).toBe(false);
    clock.advance(4_999);
    expect(cb.tryAcquire()).toBe(false);
  });

  it('open → half-open after probe interval; success closes the breaker', () => {
    const clock = makeClock();
    const cb = createCircuitBreaker({ ...OPTS, now: clock.now });
    for (let i = 0; i < 5; i++) cb.recordFailure();
    clock.advance(5_000);
    expect(cb.tryAcquire()).toBe(true);
    expect(cb.state()).toBe('half_open');
    // second concurrent acquire blocked while probe in flight
    expect(cb.tryAcquire()).toBe(false);
    cb.recordSuccess();
    expect(cb.state()).toBe('closed');
    expect(cb.tryAcquire()).toBe(true);
  });

  it('half-open failure re-opens and resets probe clock', () => {
    const clock = makeClock();
    const onOpen = vi.fn();
    const cb = createCircuitBreaker({ ...OPTS, now: clock.now, onOpen });
    for (let i = 0; i < 5; i++) cb.recordFailure();
    expect(onOpen).toHaveBeenCalledTimes(1);
    clock.advance(5_000);
    cb.tryAcquire(); // → half_open
    cb.recordFailure();
    expect(cb.state()).toBe('open');
    expect(onOpen).toHaveBeenCalledTimes(2);
    // Probe clock restarts: immediately after the re-open, still closed.
    expect(cb.tryAcquire()).toBe(false);
    clock.advance(4_999);
    expect(cb.tryAcquire()).toBe(false);
    clock.advance(1);
    expect(cb.tryAcquire()).toBe(true);
  });

  it('rolling window evicts failures older than windowMs', () => {
    const clock = makeClock();
    const cb = createCircuitBreaker({ ...OPTS, now: clock.now });
    // Two failures early.
    cb.recordFailure();
    cb.recordFailure();
    // Wait past the window.
    clock.advance(10_001);
    // Three more failures — old ones are outside the window now.
    cb.recordFailure();
    cb.recordFailure();
    cb.recordFailure();
    expect(cb.state()).toBe('closed');
    // The 4th in-window failure still doesn't trip.
    cb.recordFailure();
    expect(cb.state()).toBe('closed');
    // The 5th does.
    cb.recordFailure();
    expect(cb.state()).toBe('open');
  });

  it('stats() shape matches the interface', () => {
    const clock = makeClock();
    const cb = createCircuitBreaker({ ...OPTS, now: clock.now });
    cb.recordFailure();
    cb.recordFailure();
    const s = cb.stats();
    expect(s.opens).toBe(0);
    expect(s.currentFailures).toBe(2);
    expect(s.lastOpenedAt).toBeNull();
    expect(s.fallbackSeconds).toBe(0);

    for (let i = 0; i < 3; i++) cb.recordFailure();
    expect(cb.state()).toBe('open');
    clock.advance(3_000);
    const s2 = cb.stats();
    expect(s2.opens).toBe(1);
    expect(s2.lastOpenedAt).toBe(0);
    expect(s2.fallbackSeconds).toBe(3);
  });
});
