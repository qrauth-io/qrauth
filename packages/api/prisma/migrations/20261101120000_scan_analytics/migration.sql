-- Scan analytics (ADR-0006). Additive only: nullable enrichment columns on
-- scans, an index for per-code time ranges, and the daily rollup table.
-- scans is small in production (490 rows on 2026-11-01), so the index is
-- built in the migration rather than CONCURRENTLY.

-- AlterTable
ALTER TABLE "scans" ADD COLUMN     "browser" VARCHAR(64),
ADD COLUMN     "city" VARCHAR(128),
ADD COLUMN     "country" VARCHAR(2),
ADD COLUMN     "deviceType" VARCHAR(16),
ADD COLUMN     "os" VARCHAR(64),
ADD COLUMN     "region" VARCHAR(128);

-- CreateTable
CREATE TABLE "scan_daily_rollups" (
    "organizationId" TEXT NOT NULL,
    "qrCodeId" TEXT NOT NULL,
    "day" DATE NOT NULL,
    "total" INTEGER NOT NULL,
    "unique" INTEGER NOT NULL,
    "byCountry" JSONB NOT NULL,
    "byCity" JSONB NOT NULL,
    "byDeviceType" JSONB NOT NULL,
    "byOs" JSONB NOT NULL,
    "byBrowser" JSONB NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "scan_daily_rollups_pkey" PRIMARY KEY ("qrCodeId","day")
);

-- CreateIndex
CREATE INDEX "scan_daily_rollups_organizationId_day_idx" ON "scan_daily_rollups"("organizationId", "day");

-- CreateIndex
CREATE INDEX "scans_qrCodeId_createdAt_idx" ON "scans"("qrCodeId", "createdAt");

-- AddForeignKey
ALTER TABLE "scan_daily_rollups" ADD CONSTRAINT "scan_daily_rollups_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_daily_rollups" ADD CONSTRAINT "scan_daily_rollups_qrCodeId_fkey" FOREIGN KEY ("qrCodeId") REFERENCES "qr_codes"("id") ON DELETE CASCADE ON UPDATE CASCADE;

