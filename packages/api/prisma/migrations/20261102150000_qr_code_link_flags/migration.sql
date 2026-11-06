-- Smart link and link list content types: per-link Web Risk flags.
-- Additive; no existing table changes.
CREATE TABLE "qr_code_link_flags" (
    "id" TEXT NOT NULL,
    "qrCodeId" TEXT NOT NULL,
    "urlHash" CHAR(64) NOT NULL,
    "url" VARCHAR(2048) NOT NULL,
    "threatTypes" VARCHAR(255) NOT NULL,
    "flaggedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "qr_code_link_flags_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "qr_code_link_flags_qrCodeId_urlHash_key" ON "qr_code_link_flags"("qrCodeId", "urlHash");

ALTER TABLE "qr_code_link_flags" ADD CONSTRAINT "qr_code_link_flags_qrCodeId_fkey" FOREIGN KEY ("qrCodeId") REFERENCES "qr_codes"("id") ON DELETE CASCADE ON UPDATE CASCADE;
