-- Shadow mode for dynamic fraud rules. Additive only: a status enum on
-- fraud_rules (default ACTIVE) and a shadow flag on fraud_incidents
-- (default false). The deprecated "enabled" column stays and is kept in
-- step with status (true exactly when ACTIVE).
CREATE TYPE "FraudRuleStatus" AS ENUM ('SHADOW', 'ACTIVE', 'DISABLED');

ALTER TABLE "fraud_rules" ADD COLUMN "status" "FraudRuleStatus" NOT NULL DEFAULT 'ACTIVE';

-- Backfill: enabled = true stays ACTIVE (the column default), enabled = false
-- becomes DISABLED.
UPDATE "fraud_rules" SET "status" = 'DISABLED' WHERE "enabled" = false;

CREATE INDEX "fraud_rules_status_priority_idx" ON "fraud_rules"("status", "priority");

ALTER TABLE "fraud_incidents" ADD COLUMN "shadow" BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX "fraud_incidents_shadow_createdAt_idx" ON "fraud_incidents"("shadow", "createdAt");
