-- AlterEnum: Add REVOKED to DeviceTrustLevel
ALTER TYPE "DeviceTrustLevel" ADD VALUE 'REVOKED';

-- CreateEnum
CREATE TYPE "EphemeralSessionStatus" AS ENUM ('PENDING', 'CLAIMED', 'EXPIRED', 'REVOKED');

-- CreateTable
CREATE TABLE "ephemeral_sessions" (
    "id" TEXT NOT NULL,
    "appId" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "status" "EphemeralSessionStatus" NOT NULL DEFAULT 'PENDING',
    "scopes" TEXT[],
    "ttlSeconds" INTEGER NOT NULL,
    "maxUses" INTEGER NOT NULL DEFAULT 1,
    "useCount" INTEGER NOT NULL DEFAULT 0,
    "deviceBinding" BOOLEAN NOT NULL DEFAULT false,
    "boundDeviceHash" TEXT,
    "metadata" JSONB,
    "claimUrl" TEXT,
    "claimedAt" TIMESTAMP(3),
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ephemeral_sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "device_policies" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "maxDevices" INTEGER NOT NULL DEFAULT 10,
    "requireBiometric" BOOLEAN NOT NULL DEFAULT false,
    "geoFenceLat" DOUBLE PRECISION,
    "geoFenceLng" DOUBLE PRECISION,
    "geoFenceRadiusKm" DOUBLE PRECISION,
    "autoRevokeAfterDays" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "device_policies_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "ephemeral_sessions_token_key" ON "ephemeral_sessions"("token");

-- CreateIndex
CREATE INDEX "ephemeral_sessions_appId_idx" ON "ephemeral_sessions"("appId");

-- CreateIndex
CREATE INDEX "ephemeral_sessions_token_idx" ON "ephemeral_sessions"("token");

-- CreateIndex
CREATE INDEX "ephemeral_sessions_status_expiresAt_idx" ON "ephemeral_sessions"("status", "expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "device_policies_organizationId_key" ON "device_policies"("organizationId");

-- AddForeignKey
ALTER TABLE "ephemeral_sessions" ADD CONSTRAINT "ephemeral_sessions_appId_fkey" FOREIGN KEY ("appId") REFERENCES "apps"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "device_policies" ADD CONSTRAINT "device_policies_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;
