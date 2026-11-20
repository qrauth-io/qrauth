import { describe, it, expect, vi } from 'vitest';
import {
  attachQuotaHeaders,
  nextMonthResetIso,
  shouldMeterVerification,
} from '../verify-quota-headers.js';

// Issue #65. Pin the X-Quota-* response-header contract for the
// /verify route. The route's success path calls attachQuotaHeaders
// with the live UsageService and the org's plan; these tests cover
// the four documented behaviours:
//
//   - All four headers present on a limited plan (FREE / PRO).
//   - X-Quota-Limit ABSENT for ENTERPRISE (or any plan whose
//     verifications cap is 'unlimited'). Header absence is the
//     contract — the SDK and dashboard branch on it.
//   - X-Quota-Reset is the start-of-next-UTC-month instant.
//   - A throwing UsageService is absorbed silently — the verify
//     response is never blocked by a quota-header lookup.

function makeReply(): {
  reply: { header: (k: string, v: string) => void };
  headers: Map<string, string>;
} {
  const headers = new Map<string, string>();
  return {
    reply: {
      header: (k: string, v: string) => {
        headers.set(k, v);
      },
    },
    headers,
  };
}

describe('shouldMeterVerification (Issue #65, 5A)', () => {
  it('returns true when the signature was valid', () => {
    expect(shouldMeterVerification(true)).toBe(true);
  });

  it('returns false when the signature was invalid (failed verifies do not count)', () => {
    expect(shouldMeterVerification(false)).toBe(false);
  });

  it('integrates: a UsageService.increment spy fires only on success', async () => {
    // Mirror the verify.ts call-site to keep the test honest about
    // shape. If the route ever does anything beyond the simple guard,
    // this scenario will need to evolve too.
    const increment = vi.fn(async () => 1);
    const orgId = 'org_int';
    const usageService = { increment } as { increment: (orgId: string, m: 'verifications') => Promise<number> };

    // Successful verification → increment fires.
    if (shouldMeterVerification(true)) {
      await usageService.increment(orgId, 'verifications');
    }
    expect(increment).toHaveBeenCalledTimes(1);
    expect(increment).toHaveBeenCalledWith(orgId, 'verifications');

    // Failed-signature verification → increment must NOT fire.
    if (shouldMeterVerification(false)) {
      await usageService.increment(orgId, 'verifications');
    }
    expect(increment).toHaveBeenCalledTimes(1); // unchanged
  });
});

describe('nextMonthResetIso', () => {
  it('returns the first day of next month at 00:00:00.000Z (mid-month)', () => {
    const now = new Date('2026-05-15T13:42:11.123Z');
    expect(nextMonthResetIso(now)).toBe('2026-06-01T00:00:00.000Z');
  });

  it('rolls year over from December', () => {
    const now = new Date('2026-12-31T23:59:59.999Z');
    expect(nextMonthResetIso(now)).toBe('2027-01-01T00:00:00.000Z');
  });

  it('still returns the next month when called at exactly midnight UTC on day 1', () => {
    const now = new Date('2026-05-01T00:00:00.000Z');
    expect(nextMonthResetIso(now)).toBe('2026-06-01T00:00:00.000Z');
  });
});

describe('attachQuotaHeaders', () => {
  const NOW = new Date('2026-05-15T12:00:00.000Z');
  const ORG = 'org_test';

  it('emits all four headers for a FREE plan with a finite cap', async () => {
    const { reply, headers } = makeReply();
    const usageService = { current: vi.fn(async () => 7) };

    await attachQuotaHeaders(reply, usageService as never, ORG, 'FREE', NOW);

    expect(headers.get('X-Quota-Plan')).toBe('FREE');
    expect(headers.get('X-Quota-Used')).toBe('7');
    expect(headers.get('X-Quota-Limit')).toBe('1000');
    expect(headers.get('X-Quota-Reset')).toBe('2026-06-01T00:00:00.000Z');
    expect(usageService.current).toHaveBeenCalledWith(ORG, 'verifications');
  });

  it('emits the PRO cap of 50000', async () => {
    const { reply, headers } = makeReply();
    await attachQuotaHeaders(reply, { current: async () => 1234 } as never, ORG, 'PRO', NOW);
    expect(headers.get('X-Quota-Plan')).toBe('PRO');
    expect(headers.get('X-Quota-Limit')).toBe('50000');
    expect(headers.get('X-Quota-Used')).toBe('1234');
  });

  it('OMITS X-Quota-Limit for ENTERPRISE (unlimited contract)', async () => {
    const { reply, headers } = makeReply();
    await attachQuotaHeaders(reply, { current: async () => 9999 } as never, ORG, 'ENTERPRISE', NOW);
    expect(headers.has('X-Quota-Limit')).toBe(false);
    // The other three headers are still set so callers know what plan
    // they're on and when the meter rolls over.
    expect(headers.get('X-Quota-Plan')).toBe('ENTERPRISE');
    expect(headers.get('X-Quota-Used')).toBe('9999');
    expect(headers.get('X-Quota-Reset')).toBe('2026-06-01T00:00:00.000Z');
  });

  it('falls back to FREE when the plan string is unknown (defensive default)', async () => {
    const { reply, headers } = makeReply();
    await attachQuotaHeaders(reply, { current: async () => 0 } as never, ORG, 'NONSENSE', NOW);
    expect(headers.get('X-Quota-Limit')).toBe('1000');
    expect(headers.get('X-Quota-Plan')).toBe('NONSENSE');
  });

  it('absorbs errors from UsageService.current (verify response must not fail)', async () => {
    const { reply, headers } = makeReply();
    const usageService = {
      current: vi.fn(async () => {
        throw new Error('redis down');
      }),
    };
    // Promise must resolve, not reject.
    await expect(
      attachQuotaHeaders(reply, usageService as never, ORG, 'FREE', NOW),
    ).resolves.toBeUndefined();
    // Headers map is empty — better than a 500 on /verify.
    expect(headers.size).toBe(0);
  });
});
