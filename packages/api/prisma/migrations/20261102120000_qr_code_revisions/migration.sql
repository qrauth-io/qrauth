-- QR code edit history (Milestone 1). Additive: a new append-only table, a
-- trigger that keeps it append-only, and one BASELINE revision per existing
-- code so every history starts from a known state.

-- CreateEnum
CREATE TYPE "RevisionActorType" AS ENUM ('USER', 'API_KEY', 'SYSTEM');

-- CreateTable
CREATE TABLE "qr_code_revisions" (
    "id" TEXT NOT NULL,
    "qrCodeId" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "revision" INTEGER NOT NULL,
    "kind" VARCHAR(16) NOT NULL,
    "changes" JSONB NOT NULL,
    "actorType" "RevisionActorType" NOT NULL,
    "actorUserId" TEXT,
    "actorApiKeyId" TEXT,
    "actorSystem" VARCHAR(32),
    "requestId" VARCHAR(64),
    "restoredFrom" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "qr_code_revisions_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "qr_code_revisions_organizationId_createdAt_idx" ON "qr_code_revisions"("organizationId", "createdAt");

-- CreateIndex
CREATE INDEX "qr_code_revisions_createdAt_idx" ON "qr_code_revisions"("createdAt");

-- CreateIndex
CREATE UNIQUE INDEX "qr_code_revisions_qrCodeId_revision_key" ON "qr_code_revisions"("qrCodeId", "revision");

-- AddForeignKey
ALTER TABLE "qr_code_revisions" ADD CONSTRAINT "qr_code_revisions_qrCodeId_fkey" FOREIGN KEY ("qrCodeId") REFERENCES "qr_codes"("id") ON DELETE CASCADE ON UPDATE CASCADE;


-- Append-only. UPDATE is refused. DELETE is allowed only for rows past the
-- 730-day retention (workers: purgeExpiredRevisions uses the same database
-- clock) or when the code itself is gone (ON DELETE CASCADE from qr_codes,
-- e.g. account deletion). The cascade runs after the parent row is deleted,
-- so the NOT EXISTS check sees it gone.
CREATE FUNCTION "qr_code_revisions_append_only"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'qr_code_revisions is append-only: rows are never updated';
  END IF;
  IF OLD."createdAt" < now() - interval '730 days'
     OR NOT EXISTS (SELECT 1 FROM "qr_codes" WHERE "id" = OLD."qrCodeId") THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'qr_code_revisions is append-only: rows are deleted only by the 730-day retention';
END;
$$;

CREATE TRIGGER "qr_code_revisions_append_only"
  BEFORE UPDATE OR DELETE ON "qr_code_revisions"
  FOR EACH ROW EXECUTE FUNCTION "qr_code_revisions_append_only"();

-- History starts here for codes issued before this migration: revision 1
-- holds their current tracked fields. Ids are derived from the code id so
-- the statement needs no extension for random ids.
INSERT INTO "qr_code_revisions" (
  "id", "qrCodeId", "organizationId", "revision", "kind", "changes",
  "actorType", "actorSystem", "createdAt"
)
SELECT
  'rb' || md5("id"),
  "id",
  "organizationId",
  1,
  'BASELINE',
  jsonb_build_object(
    'destinationUrl', jsonb_build_object('before', NULL, 'after', to_jsonb("destinationUrl")),
    'content',        jsonb_build_object('before', NULL, 'after', "content"),
    'style',          jsonb_build_object('before', NULL, 'after', "style"),
    'expiresAt',      jsonb_build_object('before', NULL, 'after',
                        CASE WHEN "expiresAt" IS NULL THEN 'null'::jsonb
                             ELSE to_jsonb(to_char("expiresAt", 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')) END),
    'scanMode',       jsonb_build_object('before', NULL, 'after', to_jsonb("scanMode"::text)),
    'status',         jsonb_build_object('before', NULL, 'after', to_jsonb("status"::text))
  ),
  'SYSTEM',
  'migration',
  now()
FROM "qr_codes";
