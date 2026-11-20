-- Destination screening flag on QR codes. Additive, nullable, no backfill:
-- existing codes read as not flagged.
ALTER TABLE "qr_codes" ADD COLUMN "destinationFlaggedAt" TIMESTAMP(3),
ADD COLUMN "destinationFlagReason" TEXT;
