-- Audit-4 A4-L2: Add keyId (public signing key identifier) to QRCode for offline auditability.
-- The column is nullable to support existing rows during migration.
-- Backfill from the SigningKey join.

ALTER TABLE "qr_codes" ADD COLUMN "keyId" TEXT;

-- Backfill: copy keyId from the related SigningKey row
UPDATE "qr_codes" q
SET "keyId" = sk."keyId"
FROM "signing_keys" sk
WHERE q."signingKeyId" = sk.id;

-- Add index for audit queries by signing key version
CREATE INDEX "qr_codes_keyId_idx" ON "qr_codes"("keyId");
