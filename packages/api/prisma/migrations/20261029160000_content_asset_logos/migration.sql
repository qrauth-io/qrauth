-- Customer logos (ADR-0005 D6). Additive only: a kind on content_assets
-- (existing rows are content files), image metadata columns, an index for
-- the per-organization logo library, and a separate table for the bytes.
CREATE TYPE "ContentAssetKind" AS ENUM ('LOGO', 'CONTENT_FILE');

ALTER TABLE "content_assets" ADD COLUMN "kind" "ContentAssetKind" NOT NULL DEFAULT 'CONTENT_FILE';
ALTER TABLE "content_assets" ADD COLUMN "sha256" TEXT;
ALTER TABLE "content_assets" ADD COLUMN "width" INTEGER;
ALTER TABLE "content_assets" ADD COLUMN "height" INTEGER;

CREATE INDEX "content_assets_organizationId_kind_idx" ON "content_assets"("organizationId", "kind");

CREATE TABLE "content_asset_blobs" (
    "assetId" TEXT NOT NULL,
    "bytes" BYTEA NOT NULL,

    CONSTRAINT "content_asset_blobs_pkey" PRIMARY KEY ("assetId")
);

ALTER TABLE "content_asset_blobs" ADD CONSTRAINT "content_asset_blobs_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "content_assets"("id") ON DELETE CASCADE ON UPDATE CASCADE;
