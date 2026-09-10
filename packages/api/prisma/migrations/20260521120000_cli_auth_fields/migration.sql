-- ADR-0002 (CLI QR login) — additive schema fields for the CLI auth flow.
-- All columns nullable; no backfill. Columns are inert until PR2 wires them up.
-- The api_keys.createdByUserId index supports the PR2 membership-revocation
-- cascade lookup (WHERE organizationId = ? AND createdByUserId = ? AND source = 'cli').

-- AlterTable
ALTER TABLE "api_keys" ADD COLUMN     "createdByUserId" TEXT,
ADD COLUMN     "source" TEXT;

-- AlterTable
ALTER TABLE "auth_sessions" ADD COLUMN     "exchangedAt" TIMESTAMP(3),
ADD COLUMN     "targetOrganizationId" TEXT;

-- CreateIndex
CREATE INDEX "api_keys_createdByUserId_idx" ON "api_keys"("createdByUserId");
