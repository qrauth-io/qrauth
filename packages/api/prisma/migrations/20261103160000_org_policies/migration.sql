-- Organization policies (ADR-0008 D8): destination allowlist and the
-- destination-edit role. Additive: a new table and a defaulted column; no
-- existing row changes meaning (no policy row reads as OFF / MEMBER).

-- CreateEnum
CREATE TYPE "AllowlistMode" AS ENUM ('OFF', 'ENFORCE');

-- AlterTable
ALTER TABLE "qr_codes" ADD COLUMN     "outsidePolicy" BOOLEAN NOT NULL DEFAULT false;

-- CreateTable
CREATE TABLE "org_policies" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "allowlistMode" "AllowlistMode" NOT NULL DEFAULT 'OFF',
    "allowlist" JSONB NOT NULL DEFAULT '[]',
    "destinationEditMinRole" "MembershipRole" NOT NULL DEFAULT 'MEMBER',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "org_policies_pkey" PRIMARY KEY ("id"),
    -- OWNER or VIEWER as a minimum is not offered: OWNER-only would lock
    -- admins out of every destination, VIEWER cannot write at all.
    CONSTRAINT "org_policies_destination_edit_min_role_check"
        CHECK ("destinationEditMinRole" IN ('MEMBER', 'MANAGER', 'ADMIN')),
    CONSTRAINT "org_policies_allowlist_check"
        CHECK (jsonb_typeof("allowlist") = 'array' AND jsonb_array_length("allowlist") <= 200)
);

-- CreateIndex
CREATE UNIQUE INDEX "org_policies_organizationId_key" ON "org_policies"("organizationId");

-- CreateIndex
CREATE INDEX "qr_codes_organizationId_outsidePolicy_idx" ON "qr_codes"("organizationId", "outsidePolicy");

-- AddForeignKey
ALTER TABLE "org_policies" ADD CONSTRAINT "org_policies_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;
