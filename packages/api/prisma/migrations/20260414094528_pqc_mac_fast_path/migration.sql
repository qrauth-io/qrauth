-- CreateEnum
CREATE TYPE "MacKeyStatus" AS ENUM ('ACTIVE', 'ROTATED', 'RETIRED');

-- AlterTable
ALTER TABLE "qr_codes" ADD COLUMN     "macKeyVersion" INTEGER,
ADD COLUMN     "macTokenMac" TEXT;

-- CreateTable
CREATE TABLE "org_mac_keys" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "version" INTEGER NOT NULL,
    "secret" TEXT NOT NULL,
    "algorithm" TEXT NOT NULL DEFAULT 'hmac-sha3-256',
    "status" "MacKeyStatus" NOT NULL DEFAULT 'ACTIVE',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "rotatedAt" TIMESTAMP(3),
    "retiredAt" TIMESTAMP(3),

    CONSTRAINT "org_mac_keys_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "org_mac_keys_organizationId_status_idx" ON "org_mac_keys"("organizationId", "status");

-- CreateIndex
CREATE UNIQUE INDEX "org_mac_keys_organizationId_version_key" ON "org_mac_keys"("organizationId", "version");

-- AddForeignKey
ALTER TABLE "org_mac_keys" ADD CONSTRAINT "org_mac_keys_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;
