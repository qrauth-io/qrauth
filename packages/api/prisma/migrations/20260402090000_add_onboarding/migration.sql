-- AlterTable
ALTER TABLE "users" ADD COLUMN "onboardedAt" TIMESTAMP(3);

-- Backfill existing users so they skip onboarding
UPDATE "users" SET "onboardedAt" = "createdAt" WHERE "onboardedAt" IS NULL;
