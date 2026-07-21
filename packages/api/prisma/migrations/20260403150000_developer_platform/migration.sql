-- Add Stripe billing fields to organizations
ALTER TABLE "organizations" ADD COLUMN "stripeCustomerId" TEXT;
ALTER TABLE "organizations" ADD COLUMN "stripeSubscriptionId" TEXT;
CREATE UNIQUE INDEX "organizations_stripeCustomerId_key" ON "organizations"("stripeCustomerId");

-- Create webhook deliveries table
CREATE TABLE "webhook_deliveries" (
    "id" TEXT NOT NULL,
    "appId" TEXT NOT NULL,
    "event" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "payload" JSONB NOT NULL,
    "statusCode" INTEGER,
    "responseBody" TEXT,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "lastAttemptAt" TIMESTAMP(3),
    "deliveredAt" TIMESTAMP(3),
    "failedAt" TIMESTAMP(3),
    "error" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "webhook_deliveries_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "webhook_deliveries_appId_createdAt_idx" ON "webhook_deliveries"("appId", "createdAt");
CREATE INDEX "webhook_deliveries_event_createdAt_idx" ON "webhook_deliveries"("event", "createdAt");

ALTER TABLE "webhook_deliveries" ADD CONSTRAINT "webhook_deliveries_appId_fkey" FOREIGN KEY ("appId") REFERENCES "apps"("id") ON DELETE CASCADE ON UPDATE CASCADE;
