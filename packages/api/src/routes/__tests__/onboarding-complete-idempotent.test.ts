import { describe, it, expect, vi } from 'vitest';

import {
  completeOnboarding,
  shouldApplyOnboarding,
  slugifyOrgName,
  type OnboardingPrisma,
} from '../../services/onboarding.js';

// P0 regression guard. POST /onboarding/complete used to overwrite
// organization name/slug on EVERY call (so an already-onboarded OWNER could
// re-run /onboarding and silently rename/re-slug their org — the slug feeds the
// PUBLIC verification page). Completion must apply once and a re-run must be a
// no-op.
//
// It also used to derive `trustLevel` from the use case, letting a new org
// self-assign an elevated trust level. Onboarding must no longer set
// `trustLevel` at all (it stays at the schema default INDIVIDUAL; elevation is
// KYC/admin-only). The declared use case is preserved in kycData instead.

function makePrisma(onboardedAt: Date | null): {
  prisma: OnboardingPrisma;
  orgUpdate: ReturnType<typeof vi.fn>;
  userUpdate: ReturnType<typeof vi.fn>;
} {
  const orgUpdate = vi.fn(async () => ({}));
  const userUpdate = vi.fn(async () => ({}));
  const prisma: OnboardingPrisma = {
    user: {
      findUnique: vi.fn(async () => ({ onboardedAt })),
      update: userUpdate,
    },
    organization: {
      findFirst: vi.fn(async () => null), // no slug clash
      update: orgUpdate,
    },
  };
  return { prisma, orgUpdate, userUpdate };
}

const PARAMS = {
  userId: 'user_1',
  orgId: 'org_1',
  organizationName: 'Attacker Renamed Org',
  useCase: 'MUNICIPALITY',
};

describe('completeOnboarding — idempotency (P0)', () => {
  it('does NOT touch the org on a re-run by an onboarded user', async () => {
    const { prisma, orgUpdate, userUpdate } = makePrisma(new Date('2026-01-01T00:00:00Z'));
    const ensureSigningKey = vi.fn(async () => {});

    const result = await completeOnboarding(prisma, PARAMS, ensureSigningKey);

    expect(result).toEqual({ applied: false });
    expect(orgUpdate).not.toHaveBeenCalled();
    expect(userUpdate).not.toHaveBeenCalled();
    expect(ensureSigningKey).not.toHaveBeenCalled();
  });

  it('applies org name/slug on the FIRST completion and records useCase in kycData', async () => {
    const { prisma, orgUpdate, userUpdate } = makePrisma(null);
    const ensureSigningKey = vi.fn(async () => {});

    const result = await completeOnboarding(prisma, PARAMS, ensureSigningKey);

    expect(result).toEqual({ applied: true });
    expect(orgUpdate).toHaveBeenCalledTimes(1);
    expect(orgUpdate).toHaveBeenCalledWith({
      where: { id: 'org_1' },
      data: {
        name: 'Attacker Renamed Org',
        slug: 'attacker-renamed-org',
        kycData: { onboardingUseCase: 'MUNICIPALITY' },
      },
    });
    expect(ensureSigningKey).toHaveBeenCalledWith('org_1');
    expect(userUpdate).toHaveBeenCalledTimes(1); // marks user onboarded
  });

  it('NEVER sets trustLevel — even for a GOVERNMENT-mapped use case (elevation is KYC-only)', async () => {
    const { prisma, orgUpdate } = makePrisma(null);

    await completeOnboarding(prisma, { ...PARAMS, useCase: 'MUNICIPALITY' }, vi.fn(async () => {}));

    const updateArg = orgUpdate.mock.calls[0][0];
    expect(updateArg.data).not.toHaveProperty('trustLevel');
  });
});

describe('onboarding helpers', () => {
  it('shouldApplyOnboarding is true only when never onboarded', () => {
    expect(shouldApplyOnboarding(null)).toBe(true);
    expect(shouldApplyOnboarding(undefined)).toBe(true);
    expect(shouldApplyOnboarding(new Date())).toBe(false);
  });

  it('slugifies org names', () => {
    expect(slugifyOrgName('Thessaloniki City')).toBe('thessaloniki-city');
    expect(slugifyOrgName('  Acme!! Inc.  ')).toBe('acme-inc');
  });
});
