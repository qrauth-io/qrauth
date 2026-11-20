-- Issue #65. UsageSnapshot — periodic capture of the live Redis quota
-- counter into Postgres for billing audit and customer-dispute
-- resolution past the 35-day Redis TTL. This migration adds the table
-- only; the worker that populates it is filed as a separate follow-up
-- (#83). No data is written by this migration — every row will come
-- from the worker once it lands.

CREATE TABLE "usage_snapshots" (
    "id"             TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "metric"         TEXT NOT NULL,
    "period"         TEXT NOT NULL,
    "count"          INTEGER NOT NULL,
    "capturedAt"     TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "usage_snapshots_pkey" PRIMARY KEY ("id")
);

-- Idempotent upsert key for the worker: one snapshot per
-- (organization, metric, period). Workers running concurrently across
-- nodes can rely on this to produce the same final row regardless of
-- order.
CREATE UNIQUE INDEX "usage_snapshots_organizationId_metric_period_key"
  ON "usage_snapshots"("organizationId", "metric", "period");

-- Index for the dashboard query "show every metric for org X in period Y".
CREATE INDEX "usage_snapshots_organizationId_period_idx"
  ON "usage_snapshots"("organizationId", "period");

ALTER TABLE "usage_snapshots"
  ADD CONSTRAINT "usage_snapshots_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "organizations"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;
