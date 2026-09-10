import { describe, it, expect } from 'vitest';
import { buildUsageResponse } from '../usage.js';
import { PLAN_LIMITS } from '../../config/plan-limits.js';

// Issue #65 — wire-compat shim verification.
//
// The `/usage` route's JSON response is consumed by
// packages/web/src/pages/dashboard/usage.tsx, which checks
// `meter.limit === -1` (line 48) to switch into its "Unlimited"
// render branch. Internally PLAN_LIMITS uses the typed `'unlimited'`
// literal; the wire-format serializer maps it to `-1` at the
// response boundary. This test pins both ends:
//
//   - finite caps survive as integers
//   - 'unlimited' caps emit as -1 (NEVER as the string 'unlimited')
//   - the dashboard's `=== -1` predicate evaluates correctly

const ZERO_SNAPSHOT = {
  verifications: 0,
  qrcodes: 0,
  authSessions: 0,
  ephemeralSessions: 0,
};

const PERIOD = '2026-05';

describe('buildUsageResponse — wire shape', () => {
  it('emits all four metric keys (qrCodes — note camelCase — verifications, authSessions, ephemeralSessions)', () => {
    const out = buildUsageResponse('FREE', PERIOD, ZERO_SNAPSHOT, PLAN_LIMITS.FREE);
    expect(Object.keys(out.usage).sort()).toEqual(
      ['authSessions', 'ephemeralSessions', 'qrCodes', 'verifications'].sort(),
    );
  });

  it('FREE: finite integer caps survive as integers (1000 / 100 / 1000 / 1000)', () => {
    const out = buildUsageResponse('FREE', PERIOD, ZERO_SNAPSHOT, PLAN_LIMITS.FREE);
    expect(out.usage.qrCodes.limit).toBe(100);
    expect(out.usage.verifications.limit).toBe(1000);
    expect(out.usage.authSessions.limit).toBe(1000);
    expect(out.usage.ephemeralSessions.limit).toBe(1000);
  });

  it('PRO: qrcodes becomes -1 (unlimited), the rest survive as 50000', () => {
    const out = buildUsageResponse('PRO', PERIOD, ZERO_SNAPSHOT, PLAN_LIMITS.PRO);
    expect(out.usage.qrCodes.limit).toBe(-1);
    expect(out.usage.verifications.limit).toBe(50_000);
    expect(out.usage.authSessions.limit).toBe(50_000);
    expect(out.usage.ephemeralSessions.limit).toBe(50_000);
  });

  it('ENTERPRISE: every limit becomes -1', () => {
    const out = buildUsageResponse('ENTERPRISE', PERIOD, ZERO_SNAPSHOT, PLAN_LIMITS.ENTERPRISE);
    expect(out.usage.qrCodes.limit).toBe(-1);
    expect(out.usage.verifications.limit).toBe(-1);
    expect(out.usage.authSessions.limit).toBe(-1);
    expect(out.usage.ephemeralSessions.limit).toBe(-1);
  });

  it('No limit value is ever the literal string "unlimited" (post-serializer invariant)', () => {
    for (const tier of ['FREE', 'PRO', 'ENTERPRISE'] as const) {
      const out = buildUsageResponse(tier, PERIOD, ZERO_SNAPSHOT, PLAN_LIMITS[tier]);
      const limits = [
        out.usage.qrCodes.limit,
        out.usage.verifications.limit,
        out.usage.authSessions.limit,
        out.usage.ephemeralSessions.limit,
      ];
      for (const lim of limits) {
        expect(typeof lim).toBe('number');
        // A failure here would cause "X / unlimited (NaN%)" rendering
        // on the dashboard. The whole point of the shim.
        expect(lim).not.toBe('unlimited');
      }
    }
  });

  it("dashboard predicate `meter.limit === -1` matches every unlimited cap (cross-check with web/usage.tsx:48)", () => {
    const enterprise = buildUsageResponse('ENTERPRISE', PERIOD, ZERO_SNAPSHOT, PLAN_LIMITS.ENTERPRISE);
    expect(enterprise.usage.qrCodes.limit === -1).toBe(true);
    expect(enterprise.usage.verifications.limit === -1).toBe(true);
    expect(enterprise.usage.authSessions.limit === -1).toBe(true);
    expect(enterprise.usage.ephemeralSessions.limit === -1).toBe(true);

    const free = buildUsageResponse('FREE', PERIOD, ZERO_SNAPSHOT, PLAN_LIMITS.FREE);
    expect(free.usage.qrCodes.limit === -1).toBe(false);
    expect(free.usage.verifications.limit === -1).toBe(false);
  });

  it('current values pass through from the snapshot', () => {
    const snap = { verifications: 12, qrcodes: 7, authSessions: 3, ephemeralSessions: 5 };
    const out = buildUsageResponse('FREE', PERIOD, snap, PLAN_LIMITS.FREE);
    expect(out.usage.verifications.current).toBe(12);
    expect(out.usage.qrCodes.current).toBe(7);
    expect(out.usage.authSessions.current).toBe(3);
    expect(out.usage.ephemeralSessions.current).toBe(5);
  });

  it('plan and period flow into the top-level shape unchanged', () => {
    const out = buildUsageResponse('PRO', '2026-05', ZERO_SNAPSHOT, PLAN_LIMITS.PRO);
    expect(out.plan).toBe('PRO');
    expect(out.period).toBe('2026-05');
  });
});
