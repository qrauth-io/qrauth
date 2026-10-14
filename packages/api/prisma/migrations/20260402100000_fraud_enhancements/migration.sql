ALTER TABLE "fraud_incidents" ADD COLUMN "resolvedBy" TEXT;
ALTER TABLE "fraud_incidents" ADD COLUMN "resolutionNote" TEXT;
ALTER TABLE "fraud_incidents" ADD COLUMN "acknowledgedAt" TIMESTAMP(3);
