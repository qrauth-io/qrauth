import { describe, it, expect, expectTypeOf } from 'vitest';
import {
  PLAN_LIMITS,
  getPlanLimit,
  isUnlimited,
  serializeLimit,
  contentTypeGateMessage,
  type Limit,
} from '../plan-limits.js';

describe('plan-limits config', () => {
  it('matches the 2026-10 pricing tiers exactly', () => {
    expect(PLAN_LIMITS.FREE).toEqual({
      verifications: 1000,
      qrcodes: 100,
      authSessions: 1000,
      ephemeralSessions: 1000,
      oidcClients: 2,
    });
    expect(PLAN_LIMITS.PRO).toEqual({
      verifications: 50_000,
      qrcodes: 'unlimited',
      authSessions: 50_000,
      ephemeralSessions: 50_000,
      oidcClients: 5,
    });
    expect(PLAN_LIMITS.BUSINESS).toEqual({
      verifications: 250_000,
      qrcodes: 'unlimited',
      authSessions: 250_000,
      ephemeralSessions: 250_000,
      oidcClients: 20,
    });
    expect(PLAN_LIMITS.ENTERPRISE).toEqual({
      verifications: 'unlimited',
      qrcodes: 'unlimited',
      authSessions: 'unlimited',
      ephemeralSessions: 'unlimited',
      oidcClients: 'unlimited',
    });
  });

  it('never gives a higher tier a lower quota than the tier below it', () => {
    const order = ['FREE', 'PRO', 'BUSINESS', 'ENTERPRISE'] as const;
    const asNumber = (l: Limit) => (l === 'unlimited' ? Infinity : l);
    for (let i = 1; i < order.length; i++) {
      for (const metric of Object.keys(PLAN_LIMITS.FREE) as Array<keyof typeof PLAN_LIMITS.FREE>) {
        expect(asNumber(PLAN_LIMITS[order[i]][metric])).toBeGreaterThanOrEqual(
          asNumber(PLAN_LIMITS[order[i - 1]][metric]),
        );
      }
    }
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
    for (const tier of ['FREE', 'PRO', 'BUSINESS', 'ENTERPRISE'] as const) {
      for (const metric of ['verifications', 'qrcodes', 'authSessions', 'ephemeralSessions', 'oidcClients'] as const) {
        const lim: Limit = PLAN_LIMITS[tier][metric];
        const wire = serializeLimit(lim);
        expect(typeof wire).toBe('number');
        expect(Number.isFinite(wire)).toBe(true);
        expect(Number.isNaN(wire)).toBe(false);
      }
    }
  });
});

describe('contentTypeGateMessage (server-side content-type gate)', () => {
  it('lets FREE create the free-tier types and treats an unset type as url', () => {
    expect(contentTypeGateMessage('FREE', 'url')).toBeNull();
    expect(contentTypeGateMessage('FREE', 'vcard')).toBeNull();
    expect(contentTypeGateMessage('FREE', undefined)).toBeNull();
  });

  it('refuses the paid types on FREE and on an unknown plan string', () => {
    for (const type of ['coupon', 'event', 'pdf', 'feedback']) {
      expect(contentTypeGateMessage('FREE', type)).toContain('not included in the Free plan');
      expect(contentTypeGateMessage('NONSENSE', type)).toContain('not included in the Free plan');
    }
  });

  it('allows every type on the paid tiers', () => {
    for (const plan of ['PRO', 'BUSINESS', 'ENTERPRISE']) {
      for (const type of ['url', 'vcard', 'coupon', 'event', 'pdf', 'feedback']) {
        expect(contentTypeGateMessage(plan, type)).toBeNull();
      }
    }
  });

  it('leaves unknown content types to generateQRCode', () => {
    expect(contentTypeGateMessage('FREE', 'hologram')).toBeNull();
  });
});
