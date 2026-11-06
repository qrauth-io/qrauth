-- One lookalike incident per code, URL and protected domain (ADR-0007 D6),
-- enforced by the database. Existing rows keep NULL (never conflicting).
ALTER TABLE "fraud_incidents" ADD COLUMN "dedupeKey" TEXT;

CREATE UNIQUE INDEX "fraud_incidents_qrCodeId_dedupeKey_key" ON "fraud_incidents"("qrCodeId", "dedupeKey");
