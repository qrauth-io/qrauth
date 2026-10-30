-- Audit 2026-10 FINDING-005: onboarding is applied once per ORGANIZATION.
-- Nullable, no default: NULL means "not onboarded yet".
ALTER TABLE "organizations" ADD COLUMN "onboardedAt" TIMESTAMP(3);

-- Backfill: an organization whose OWNER has already completed onboarding is
-- onboarded. Without this, every existing organization would look
-- un-onboarded and a second OWNER who never onboarded could re-run it.
UPDATE "organizations" o
SET "onboardedAt" = owners."firstOnboardedAt"
FROM (
  SELECT m."organizationId", min(u."onboardedAt") AS "firstOnboardedAt"
  FROM "memberships" m
  JOIN "users" u ON u."id" = m."userId"
  WHERE m."role" = 'OWNER' AND u."onboardedAt" IS NOT NULL
  GROUP BY m."organizationId"
) owners
WHERE o."id" = owners."organizationId";
