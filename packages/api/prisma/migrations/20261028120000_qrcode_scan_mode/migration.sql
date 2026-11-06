-- Per-code browser scan behaviour. Additive, with a default: existing codes
-- read as FLASH, which only takes effect for VERIFIED https URL codes
-- without a location binding.
CREATE TYPE "ScanMode" AS ENUM ('FLASH', 'PAGE');

ALTER TABLE "qr_codes" ADD COLUMN "scanMode" "ScanMode" NOT NULL DEFAULT 'FLASH';
