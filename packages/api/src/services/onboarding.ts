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
//
// Audit 2026-10 FINDING-005: the name and slug are the organization's public
// identity, so only an OWNER may set them, and "once" is tracked on the
// ORGANIZATION (`organizations.onboardedAt`), not just on the user — a second
// user who has not onboarded cannot re-run it. Everyone else is only marked
// onboarded themselves. All writes share one transaction, and the use case
// is merged into `kycData` rather than replacing it.
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
export interface OnboardingTx {
  user: {
    findUnique(args: {
      where: { id: string };
      select: { onboardedAt: true };
    }): Promise<{ onboardedAt: Date | null } | null>;
    update(args: { where: { id: string }; data: { onboardedAt: Date } }): Promise<unknown>;
  };
  organization: {
    findUnique(args: {
      where: { id: string };
      select: { onboardedAt: true; kycData: true };
    }): Promise<{ onboardedAt: Date | null; kycData: unknown } | null>;
    findFirst(args: {
      where: { slug: string; id: { not: string } };
    }): Promise<{ id: string } | null>;
    updateMany(args: {
      where: { id: string; onboardedAt: null };
      data: { name: string; slug: string; kycData: Record<string, unknown>; onboardedAt: Date };
    }): Promise<{ count: number }>;
  };
}

export interface OnboardingPrisma extends OnboardingTx {
  $transaction<T>(fn: (tx: OnboardingTx) => Promise<T>): Promise<T>;
}

export interface CompleteOnboardingParams {
  userId: string;
  orgId: string;
  /** The caller's role in `orgId`; only an OWNER may set the org's identity. */
  actorRole: string;
  organizationName: string;
  useCase: string;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

/**
 * Apply onboarding completion exactly once per organization.
 *
 * `applied: true` only when an OWNER who has not onboarded completes it for
 * an organization that has not been onboarded: the org name/slug are set, the
 * declared use case is merged into `kycData`, the org and the user are marked
 * onboarded (one transaction), after a signing key is ensured via
 * `ensureSigningKey`. In every other case the organization is left untouched;
 * the user is still marked onboarded so the dashboard stops routing them to
 * the onboarding page. It does NOT set `trustLevel` — that stays at the schema
 * default (INDIVIDUAL) and is elevated only via KYC/admin review.
 */
/** Only an OWNER who has not onboarded, on an org that has not been onboarded. */
async function readMayApply(db: OnboardingTx, params: CompleteOnboardingParams) {
  const [user, org] = await Promise.all([
    db.user.findUnique({ where: { id: params.userId }, select: { onboardedAt: true } }),
    db.organization.findUnique({
      where: { id: params.orgId },
      select: { onboardedAt: true, kycData: true },
    }),
  ]);
  if (!user || !org) return null;

  const mayApply =
    params.actorRole === 'OWNER' && shouldApplyOnboarding(user.onboardedAt) && !org.onboardedAt;
  return { user, org, mayApply };
}

export async function completeOnboarding(
  prisma: OnboardingPrisma,
  params: CompleteOnboardingParams,
  ensureSigningKey: (orgId: string) => Promise<void>,
): Promise<{ applied: boolean }> {
  // Signing-key creation calls the signer, so it cannot join the DB
  // transaction. It runs FIRST: if it fails nothing is marked onboarded and
  // the caller can simply retry (it is idempotent — it only creates a key
  // when the org has none).
  const precheck = await readMayApply(prisma, params);
  if (precheck?.mayApply) await ensureSigningKey(params.orgId);

  const applied = await prisma.$transaction(async (tx) => {
    // Re-read inside the transaction: the precheck is only a hint.
    const state = await readMayApply(tx, params);
    if (!state) return false;
    const { user, org, mayApply } = state;

    const now = new Date();
    let orgApplied = false;
    if (mayApply) {
      const baseSlug = slugifyOrgName(params.organizationName);
      const slugClash = await tx.organization.findFirst({
        where: { slug: baseSlug, id: { not: params.orgId } },
      });
      const slug = slugClash ? `${baseSlug}-${randomBytes(2).toString('hex')}` : baseSlug;

      // `onboardedAt: null` in the WHERE makes "once per organization" hold
      // under concurrent requests: only one of them matches the row.
      const { count } = await tx.organization.updateMany({
        where: { id: params.orgId, onboardedAt: null },
        data: {
          name: params.organizationName,
          slug,
          kycData: { ...asRecord(org.kycData), onboardingUseCase: params.useCase },
          onboardedAt: now,
        },
      });
      orgApplied = count > 0;
    }

    if (shouldApplyOnboarding(user.onboardedAt)) {
      await tx.user.update({ where: { id: params.userId }, data: { onboardedAt: now } });
    }
    return orgApplied;
  });

  return { applied };
}
