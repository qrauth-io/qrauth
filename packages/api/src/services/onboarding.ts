import { randomBytes } from 'node:crypto';

// ----------------------------------------------------------------------
// Onboarding completion — first-run only.
//
// `POST /onboarding/complete` used to overwrite organization name/slug AND
// derive `trustLevel` from the user-chosen use case (MUNICIPALITY -> GOVERNMENT,
// FINANCE -> BUSINESS, ...). That let a brand-new org self-assign an elevated
// trust level — which is rendered on the PUBLIC verification page — by simply
// picking a use case. Trust level is meant to be granted only via KYC/admin
// review (validation.ts excludes it from self-update; pentest IDOR-001).
//
// Onboarding therefore no longer touches `trustLevel`: new orgs keep the schema
// default (INDIVIDUAL) and are elevated only through KYC. The declared use case
// is preserved as metadata in `kycData.onboardingUseCase` so a reviewer can see
// what the org claimed. The completion also stays idempotent — it applies once,
// and a re-run is a no-op (it never re-overwrites name/slug).
// ----------------------------------------------------------------------

/** Slugify an org name for the public verification URL. */
export function slugifyOrgName(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

/**
 * First onboarding only. When the user is already onboarded the org's
 * name/slug must NOT be overwritten — the re-run is idempotent.
 */
export function shouldApplyOnboarding(onboardedAt: Date | null | undefined): boolean {
  return !onboardedAt;
}

// Minimal structural slices of PrismaClient this module touches — keeps the
// logic unit-testable with a plain mock (no live DB).
export interface OnboardingPrisma {
  user: {
    findUnique(args: {
      where: { id: string };
      select: { onboardedAt: true };
    }): Promise<{ onboardedAt: Date | null } | null>;
    update(args: { where: { id: string }; data: { onboardedAt: Date } }): Promise<unknown>;
  };
  organization: {
    findFirst(args: {
      where: { slug: string; id: { not: string } };
    }): Promise<{ id: string } | null>;
    update(args: {
      where: { id: string };
      data: { name: string; slug: string; kycData: { onboardingUseCase: string } };
    }): Promise<unknown>;
  };
}

export interface CompleteOnboardingParams {
  userId: string;
  orgId: string;
  organizationName: string;
  useCase: string;
}

/**
 * Apply onboarding completion exactly once.
 *
 * Returns `{ applied: false }` without touching the organization when the
 * user is already onboarded (idempotent re-run). On first completion it sets
 * the org name/slug, records the declared use case in `kycData`, ensures a
 * signing key via `ensureSigningKey`, and marks the user onboarded. It does
 * NOT set `trustLevel` — that stays at the schema default (INDIVIDUAL) and is
 * elevated only via KYC/admin review.
 */
export async function completeOnboarding(
  prisma: OnboardingPrisma,
  params: CompleteOnboardingParams,
  ensureSigningKey: (orgId: string) => Promise<void>,
): Promise<{ applied: boolean }> {
  const existing = await prisma.user.findUnique({
    where: { id: params.userId },
    select: { onboardedAt: true },
  });

  if (!shouldApplyOnboarding(existing?.onboardedAt)) {
    // Already onboarded — do NOT overwrite org name/slug.
    return { applied: false };
  }

  const baseSlug = slugifyOrgName(params.organizationName);
  const slugClash = await prisma.organization.findFirst({
    where: { slug: baseSlug, id: { not: params.orgId } },
  });
  const slug = slugClash ? `${baseSlug}-${randomBytes(2).toString('hex')}` : baseSlug;

  await prisma.organization.update({
    where: { id: params.orgId },
    data: { name: params.organizationName, slug, kycData: { onboardingUseCase: params.useCase } },
  });

  await ensureSigningKey(params.orgId);

  await prisma.user.update({
    where: { id: params.userId },
    data: { onboardedAt: new Date() },
  });

  return { applied: true };
}
