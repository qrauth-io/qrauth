-- Abuse reports from the verify page. New enums and table only; nothing
-- existing changes.
CREATE TYPE "AbuseReportReason" AS ENUM ('PHISHING', 'MALWARE', 'IMPERSONATION', 'SPAM', 'OTHER');

CREATE TYPE "AbuseReportStatus" AS ENUM ('OPEN', 'RESOLVED', 'DISMISSED');

CREATE TABLE "abuse_reports" (
    "id" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "reason" "AbuseReportReason" NOT NULL,
    "comment" TEXT,
    "reporterEmail" TEXT,
    "ipHash" TEXT NOT NULL,
    "status" "AbuseReportStatus" NOT NULL DEFAULT 'OPEN',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "resolvedAt" TIMESTAMP(3),
    "resolvedBy" TEXT,
    "resolutionNote" TEXT,

    CONSTRAINT "abuse_reports_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "abuse_reports_status_createdAt_idx" ON "abuse_reports"("status", "createdAt");

CREATE INDEX "abuse_reports_token_idx" ON "abuse_reports"("token");

CREATE INDEX "abuse_reports_organizationId_idx" ON "abuse_reports"("organizationId");
