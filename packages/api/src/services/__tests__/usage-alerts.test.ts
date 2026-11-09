import { describe, it, expect, vi, beforeEach } from 'vitest';

const { sendUsageThresholdEmail } = vi.hoisted(() => ({
  sendUsageThresholdEmail: vi.fn(async (..._args: unknown[]) => undefined),
}));
vi.mock('../../lib/email.js', () => ({ sendUsageThresholdEmail }));

import { crossedThreshold, notifyVerificationThreshold } from '../usage-alerts.js';

describe('crossedThreshold', () => {
  it('fires exactly on the 80% and 100% counts', () => {
    expect(crossedThreshold(40_000, 50_000)).toBe(80);
    expect(crossedThreshold(50_000, 50_000)).toBe(100);
    expect(crossedThreshold(800, 1_000)).toBe(80);
    expect(crossedThreshold(200_000, 250_000)).toBe(80);
  });

  it('stays quiet on every other count, including past the allowance', () => {
    for (const count of [1, 39_999, 40_001, 49_999, 50_001, 100_000]) {
      expect(crossedThreshold(count, 50_000)).toBeNull();
    }
  });

  it('rounds the threshold count up for limits that do not divide evenly', () => {
    expect(crossedThreshold(3, 3)).toBe(100);
    expect(crossedThreshold(3, 3, [80])).toBe(80); // ceil(2.4) = 3
  });

  it('never alerts on a 0 count (Redis failure) or a 0 limit', () => {
    expect(crossedThreshold(0, 50_000)).toBeNull();
    expect(crossedThreshold(10, 0)).toBeNull();
  });
});

describe('notifyVerificationThreshold', () => {
  const logger = { warn: vi.fn() };
  const findUnique = vi.fn(async () => ({ name: 'Acme', email: 'owner@acme.test', billingEmail: 'billing@acme.test' }));
  const prisma = { organization: { findUnique } } as never;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('emails the billing address when a PRO org reaches 80%', async () => {
    await notifyVerificationThreshold(prisma, logger, 'org1', 'PRO', 40_000);
    expect(sendUsageThresholdEmail).toHaveBeenCalledWith('billing@acme.test', 'Acme', {
      threshold: 80,
      used: 40_000,
      limit: 50_000,
      plan: 'PRO',
    });
  });

  it('does nothing between thresholds or on an unlimited plan', async () => {
    await notifyVerificationThreshold(prisma, logger, 'org1', 'PRO', 40_001);
    await notifyVerificationThreshold(prisma, logger, 'org1', 'ENTERPRISE', 40_000);
    expect(findUnique).not.toHaveBeenCalled();
    expect(sendUsageThresholdEmail).not.toHaveBeenCalled();
  });

  it('logs and swallows an email failure', async () => {
    sendUsageThresholdEmail.mockRejectedValueOnce(new Error('smtp down'));
    await expect(
      notifyVerificationThreshold(prisma, logger, 'org1', 'FREE', 1_000),
    ).resolves.toBeUndefined();
    expect(logger.warn).toHaveBeenCalledWith(
      expect.objectContaining({ orgId: 'org1', threshold: 100, err: 'smtp down' }),
      'usage: verification threshold email failed',
    );
  });
});
