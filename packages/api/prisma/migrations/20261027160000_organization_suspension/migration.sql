-- Platform suspension of an organization (superadmin). Additive, nullable,
-- no backfill: existing rows read as not suspended.
ALTER TABLE "organizations" ADD COLUMN "suspendedAt" TIMESTAMP(3),
ADD COLUMN "suspendedReason" TEXT;
