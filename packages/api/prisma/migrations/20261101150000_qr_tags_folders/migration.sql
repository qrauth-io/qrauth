-- Organising QR codes (Milestone 1): search indexes, tags and folders.
-- Additive only. qr_codes is small in production (174 rows on 2026-11-01),
-- so indexes are built in the migration rather than CONCURRENTLY.
--
-- pg_trgm is a trusted extension (PostgreSQL 13+): the database owner can
-- create it without superuser.

-- CreateExtension
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- DropIndex
DROP INDEX "qr_codes_organizationId_idx";

-- AlterTable
ALTER TABLE "qr_codes" ADD COLUMN     "folderId" TEXT;

-- Lower-cased destination host for search, computed by Postgres on every
-- write (Prisma cannot declare generated columns; the schema lists it as a
-- plain nullable column the API never writes). NULL when the URL has no
-- scheme://host.
ALTER TABLE "qr_codes" ADD COLUMN "destinationHost" TEXT GENERATED ALWAYS AS (
  lower(substring("destinationUrl" from '^[A-Za-z][A-Za-z0-9+.-]*://(?:[^/?#@]*@)?([^/?#:]+)'))
) STORED;

-- CreateTable
CREATE TABLE "tags" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "name" VARCHAR(32) NOT NULL,
    "color" VARCHAR(16) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "tags_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "qr_code_tags" (
    "qrCodeId" TEXT NOT NULL,
    "tagId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "qr_code_tags_pkey" PRIMARY KEY ("qrCodeId","tagId")
);

-- CreateTable
CREATE TABLE "qr_folders" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "name" VARCHAR(64) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "qr_folders_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "tags_organizationId_name_key" ON "tags"("organizationId", "name");

-- CreateIndex
CREATE INDEX "qr_code_tags_tagId_idx" ON "qr_code_tags"("tagId");

-- CreateIndex
CREATE UNIQUE INDEX "qr_folders_organizationId_name_key" ON "qr_folders"("organizationId", "name");

-- CreateIndex
CREATE INDEX "qr_codes_organizationId_createdAt_idx" ON "qr_codes"("organizationId", "createdAt");

-- CreateIndex
CREATE INDEX "qr_codes_organizationId_folderId_idx" ON "qr_codes"("organizationId", "folderId");

-- CreateIndex
CREATE INDEX "qr_codes_label_trgm_idx" ON "qr_codes" USING GIN ("label" gin_trgm_ops);

-- AddForeignKey
ALTER TABLE "qr_codes" ADD CONSTRAINT "qr_codes_folderId_fkey" FOREIGN KEY ("folderId") REFERENCES "qr_folders"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "tags" ADD CONSTRAINT "tags_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "qr_code_tags" ADD CONSTRAINT "qr_code_tags_qrCodeId_fkey" FOREIGN KEY ("qrCodeId") REFERENCES "qr_codes"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "qr_code_tags" ADD CONSTRAINT "qr_code_tags_tagId_fkey" FOREIGN KEY ("tagId") REFERENCES "tags"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "qr_folders" ADD CONSTRAINT "qr_folders_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;


-- CreateIndex
CREATE INDEX "qr_codes_destination_host_trgm_idx" ON "qr_codes" USING GIN ("destinationHost" gin_trgm_ops);
