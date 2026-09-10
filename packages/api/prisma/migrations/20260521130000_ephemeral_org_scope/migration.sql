-- ADR-0002 step 8: org-scope EphemeralSession so an org-scoped credential
-- (API key / dashboard JWT) can manage ephemeral sessions — not just app
-- client-credentials. organizationId becomes authoritative (like QRCode);
-- appId becomes optional provenance (null for sessions created by an org
-- credential).

-- 1. Add organizationId nullable, backfill from the owning app, then enforce NOT NULL.
ALTER TABLE "ephemeral_sessions" ADD COLUMN "organizationId" TEXT;

UPDATE "ephemeral_sessions" e
SET "organizationId" = a."organizationId"
FROM "apps" a
WHERE e."appId" = a."id";

ALTER TABLE "ephemeral_sessions" ALTER COLUMN "organizationId" SET NOT NULL;

-- 2. appId becomes optional (sessions created by an org credential have none).
ALTER TABLE "ephemeral_sessions" ALTER COLUMN "appId" DROP NOT NULL;

-- 3. Index + FK for the new org scope.
CREATE INDEX "ephemeral_sessions_organizationId_idx" ON "ephemeral_sessions"("organizationId");

ALTER TABLE "ephemeral_sessions" ADD CONSTRAINT "ephemeral_sessions_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;
