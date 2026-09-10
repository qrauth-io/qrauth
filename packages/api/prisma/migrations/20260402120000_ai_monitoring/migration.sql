CREATE TABLE "analytics_snapshots" (
    "id" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "entityType" TEXT NOT NULL,
    "entityId" TEXT NOT NULL,
    "periodStart" TIMESTAMP(3) NOT NULL,
    "periodEnd" TIMESTAMP(3) NOT NULL,
    "data" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "analytics_snapshots_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "fraud_rules" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "priority" INTEGER NOT NULL DEFAULT 100,
    "conditions" JSONB NOT NULL,
    "action" JSONB NOT NULL,
    "source" TEXT NOT NULL DEFAULT 'system',
    "version" INTEGER NOT NULL DEFAULT 1,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "fraud_rules_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "agent_runs" (
    "id" TEXT NOT NULL,
    "runType" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "inputSummary" JSONB,
    "outputSummary" JSONB,
    "tokensUsed" INTEGER,
    "durationMs" INTEGER,
    "error" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),
    CONSTRAINT "agent_runs_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "fraud_rules_name_key" ON "fraud_rules"("name");
CREATE INDEX "analytics_snapshots_type_entityType_periodStart_idx" ON "analytics_snapshots"("type", "entityType", "periodStart");
CREATE INDEX "analytics_snapshots_entityId_type_idx" ON "analytics_snapshots"("entityId", "type");
CREATE INDEX "fraud_rules_enabled_priority_idx" ON "fraud_rules"("enabled", "priority");
CREATE INDEX "agent_runs_runType_createdAt_idx" ON "agent_runs"("runType", "createdAt");

-- Seed initial fraud rules from existing hardcoded signals
INSERT INTO "fraud_rules" ("id", "name", "description", "enabled", "priority", "conditions", "action", "source", "version", "createdAt", "updatedAt") VALUES
('rule_velocity', 'Scan Velocity', 'Flag QR codes with unusually high scan rate', true, 10, '[{"field":"scanVelocity5m","operator":"gt","value":30}]', '{"deductScore":20,"severity":"MEDIUM","type":"PATTERN_ANOMALY","reason":"scan_velocity_dynamic"}', 'system', 1, NOW(), NOW()),
('rule_bot', 'Bot Detection', 'Flag automated scanners', true, 20, '[{"field":"isBot","operator":"eq","value":true}]', '{"deductScore":15,"severity":"MEDIUM","type":"PATTERN_ANOMALY","reason":"bot_detected_dynamic"}', 'system', 1, NOW(), NOW()),
('rule_device_cluster', 'Device Clustering', 'Same IP scanning many different QR codes', true, 30, '[{"field":"ipDispersion1h","operator":"gt","value":8}]', '{"deductScore":25,"severity":"HIGH","type":"PATTERN_ANOMALY","reason":"device_clustering_dynamic"}', 'system', 1, NOW(), NOW()),
('rule_night_scan', 'Night Scan Anomaly', 'Unusual scanning activity between 1-5 AM local time', true, 50, '[{"field":"hourOfDay","operator":"between","value":[1,5]},{"field":"scanVelocity1h","operator":"gt","value":10}]', '{"deductScore":10,"severity":"LOW","type":"PATTERN_ANOMALY","reason":"night_scan_anomaly"}', 'system', 1, NOW(), NOW());
