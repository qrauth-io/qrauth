-- Organization audit log (Milestone 2, ADR-0008). Additive: new actor and
-- request columns, existing rows backfilled as USER actors, and append-only
-- triggers on audit_logs and qr_code_revisions.

-- CreateEnum
CREATE TYPE "AuditActorType" AS ENUM ('USER', 'API_KEY', 'SYSTEM', 'SUPERADMIN');

-- AlterTable: actor columns. userId becomes optional (API keys and system
-- jobs have no user) and loses its foreign key, as qr_code_revisions does:
-- the trail keeps the id after the user is deleted.
ALTER TABLE "audit_logs" DROP CONSTRAINT "audit_logs_userId_fkey";
ALTER TABLE "audit_logs" ALTER COLUMN "userId" DROP NOT NULL;
ALTER TABLE "audit_logs"
  ADD COLUMN "actorType" "AuditActorType" NOT NULL DEFAULT 'USER',
  ADD COLUMN "actorId" TEXT,
  ADD COLUMN "userAgent" VARCHAR(512),
  ADD COLUMN "requestId" VARCHAR(64);

-- Existing rows were all written with the acting user.
UPDATE "audit_logs" SET "actorId" = "userId";

-- CreateIndex
CREATE INDEX "audit_logs_organizationId_actorId_idx" ON "audit_logs"("organizationId", "actorId");

-- Append-only audit_logs. UPDATE and DELETE are refused, except:
--   * DELETE of rows past the 730-day retention, by the retention job, which
--     sets qrauth.audit_maintenance = 'retention' in its transaction;
--   * UPDATE that only clears ipAddress and userAgent (GDPR erasure of a
--     deleted account), under qrauth.audit_maintenance = 'erasure';
--   * DELETE when the organization itself is gone (ON DELETE CASCADE). The
--     cascade runs after the parent row is deleted, so NOT EXISTS sees it.
-- The flag guards against application bugs; it is not a privilege boundary.
CREATE FUNCTION "audit_logs_append_only"() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  flag text := current_setting('qrauth.audit_maintenance', true);
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF flag = 'erasure'
       AND NEW."ipAddress" IS NULL AND NEW."userAgent" IS NULL
       AND (to_jsonb(NEW) - 'ipAddress' - 'userAgent') = (to_jsonb(OLD) - 'ipAddress' - 'userAgent') THEN
      RETURN NEW;
    END IF;
    RAISE EXCEPTION 'audit_logs is append-only: rows are never updated';
  END IF;
  IF (flag = 'retention' AND OLD."createdAt" < now() - interval '730 days')
     OR NOT EXISTS (SELECT 1 FROM "organizations" WHERE "id" = OLD."organizationId") THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'audit_logs is append-only: rows are deleted only by the 730-day retention';
END;
$$;

CREATE TRIGGER "audit_logs_append_only"
  BEFORE UPDATE OR DELETE ON "audit_logs"
  FOR EACH ROW EXECUTE FUNCTION "audit_logs_append_only"();

-- qr_code_revisions (migration 20261102120000) now also needs the retention
-- flag for age-based deletes, as audit_logs does. The cascade when the code
-- is deleted is unchanged.
CREATE OR REPLACE FUNCTION "qr_code_revisions_append_only"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'qr_code_revisions is append-only: rows are never updated';
  END IF;
  IF (current_setting('qrauth.audit_maintenance', true) = 'retention'
      AND OLD."createdAt" < now() - interval '730 days')
     OR NOT EXISTS (SELECT 1 FROM "qr_codes" WHERE "id" = OLD."qrCodeId") THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'qr_code_revisions is append-only: rows are deleted only by the 730-day retention';
END;
$$;
