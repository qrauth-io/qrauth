-- Bulk operations (ADR-0008 D9): CSV import and ZIP export jobs. Additive:
-- a new table; no existing row changes.

-- CreateEnum
CREATE TYPE "BulkJobKind" AS ENUM ('IMPORT', 'EXPORT');

-- CreateEnum
CREATE TYPE "BulkJobStatus" AS ENUM ('QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED');

-- CreateTable
CREATE TABLE "bulk_jobs" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "kind" "BulkJobKind" NOT NULL,
    "status" "BulkJobStatus" NOT NULL DEFAULT 'QUEUED',
    "actorType" VARCHAR(16) NOT NULL,
    "actorUserId" TEXT,
    "actorApiKeyId" TEXT,
    "requestId" VARCHAR(64),
    "ipAddress" TEXT,
    "userAgent" VARCHAR(512),
    "input" JSONB NOT NULL,
    "results" JSONB,
    "total" INTEGER NOT NULL,
    "processed" INTEGER NOT NULL DEFAULT 0,
    "succeeded" INTEGER NOT NULL DEFAULT 0,
    "failed" INTEGER NOT NULL DEFAULT 0,
    "skipped" INTEGER NOT NULL DEFAULT 0,
    "error" TEXT,
    "filePath" TEXT,
    "fileBytes" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "startedAt" TIMESTAMP(3),
    "finishedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3),

    CONSTRAINT "bulk_jobs_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "bulk_jobs_actor_check" CHECK (
        ("actorType" = 'USER' AND "actorUserId" IS NOT NULL AND "actorApiKeyId" IS NULL)
        OR ("actorType" = 'API_KEY' AND "actorApiKeyId" IS NOT NULL AND "actorUserId" IS NULL)
    )
);

-- CreateIndex
CREATE INDEX "bulk_jobs_organizationId_createdAt_idx" ON "bulk_jobs"("organizationId", "createdAt");

-- CreateIndex
CREATE INDEX "bulk_jobs_status_updatedAt_idx" ON "bulk_jobs"("status", "updatedAt");

-- One active job per organization and kind. Not expressible in the Prisma
-- schema; a second commit gets a unique violation (409 at the route).
CREATE UNIQUE INDEX "bulk_jobs_one_active_per_org_kind" ON "bulk_jobs"("organizationId", "kind")
    WHERE "status" IN ('QUEUED', 'RUNNING');

-- AddForeignKey
ALTER TABLE "bulk_jobs" ADD CONSTRAINT "bulk_jobs_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;
