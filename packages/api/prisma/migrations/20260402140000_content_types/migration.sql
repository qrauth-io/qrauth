ALTER TABLE "qr_codes" ADD COLUMN "contentType" TEXT NOT NULL DEFAULT 'url';
ALTER TABLE "qr_codes" ADD COLUMN "content" JSONB;
ALTER TABLE "qr_codes" ADD COLUMN "contentVersion" INTEGER NOT NULL DEFAULT 1;
ALTER TABLE "qr_codes" ADD COLUMN "publishedAt" TIMESTAMP(3);

CREATE TABLE "content_assets" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "qrCodeId" TEXT,
    "filename" TEXT NOT NULL,
    "mimeType" TEXT NOT NULL,
    "sizeBytes" INTEGER NOT NULL,
    "storagePath" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "content_assets_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "content_assets_organizationId_idx" ON "content_assets"("organizationId");
CREATE INDEX "content_assets_qrCodeId_idx" ON "content_assets"("qrCodeId");

ALTER TABLE "content_assets" ADD CONSTRAINT "content_assets_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "content_assets" ADD CONSTRAINT "content_assets_qrCodeId_fkey" FOREIGN KEY ("qrCodeId") REFERENCES "qr_codes"("id") ON DELETE SET NULL ON UPDATE CASCADE;
