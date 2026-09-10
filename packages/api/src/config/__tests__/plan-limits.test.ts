import { describe, it, expect, expectTypeOf } from 'vitest';
import {
  PLAN_LIMITS,
  getPlanLimit,
  isUnlimited,
  serializeLimit,
  type Limit,
} from '../plan-limits.js';

describe('plan-limits config', () => {
  it('matches the operator-confirmed Q2 caps', () => {
    expect(PLAN_LIMITS.FREE).toEqual({
      verifications: 1000,
      qrcodes: 100,
      authSessions: 1000,
      ephemeralSessions: 1000,
    });
    expect(PLAN_LIMITS.PRO).toEqual({
      verifications: 50_000,
      qrcodes: 'unlimited',
      authSessions: 50_000,
      ephemeralSessions: 50_000,
    });
    expect(PLAN_LIMITS.ENTERPRISE).toEqual({
      verifications: 'unlimited',
      qrcodes: 'unlimited',
      authSessions: 'unlimited',
      ephemeralSessions: 'unlimited',
    });
  });

  it('falls back to FREE when the plan string is unknown (defensive default)', () => {
    expect(getPlanLimit('NONSENSE', 'verifications')).toBe(1000);
    expect(getPlanLimit('', 'qrcodes')).toBe(100);
  });

  it('isUnlimited returns true only for the literal sentinel', () => {
    expect(isUnlimited('ENTERPRISE', 'verifications')).toBe(true);
    expect(isUnlimited('PRO', 'qrcodes')).toBe(true);
    expect(isUnlimited('FREE', 'verifications')).toBe(false);
    expect(isUnlimited('FREE', 'qrcodes')).toBe(false);
  });
});

describe('serializeLimit (wire-compat shim)', () => {
  it('passes finite numeric limits through unchanged', () => {
    expect(serializeLimit(0)).toBe(0);
    expect(serializeLimit(100)).toBe(100);
    expect(serializeLimit(1000)).toBe(1000);
    expect(serializeLimit(50_000)).toBe(50_000);
    expect(serializeLimit(Number.MAX_SAFE_INTEGER)).toBe(Number.MAX_SAFE_INTEGER);
  });

  it("maps the 'unlimited' literal to the -1 sentinel", () => {
    expect(serializeLimit('unlimited')).toBe(-1);
  });

  it('always returns a number — typed return shape pins the wire contract', () => {
    // Compile-time: the return type must be `number`, not
    // `number | -1`. If a future refactor narrows it to `number | -1`
    // the dashboard's `meter.limit === -1` check still works, but
    // call sites elsewhere may need to widen — pin here so the
    // change shows up in CI.
    expectTypeOf(serializeLimit).returns.toEqualTypeOf<number>();

    // Runtime: every plan/metric pair survives JSON serialization as
    // a JavaScript number (no NaN, no string).
    for (const tier of ['FREE', 'PRO', 'ENTERPRISE'] as const) {
      for (const metric of ['verifications', 'qrcodes', 'authSessions', 'ephemeralSessions'] as const) {
        const lim: Limit = PLAN_LIMITS[tier][metric];
        const wire = serializeLimit(lim);
        expect(typeof wire).toBe('number');
        expect(Number.isFinite(wire)).toBe(true);
        expect(Number.isNaN(wire)).toBe(false);
      }
    }
  });
});
