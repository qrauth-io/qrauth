-- CreateEnum
CREATE TYPE "AppStatus" AS ENUM ('ACTIVE', 'SUSPENDED', 'DELETED');

-- CreateEnum
CREATE TYPE "AuthSessionStatus" AS ENUM ('PENDING', 'SCANNED', 'APPROVED', 'DENIED', 'EXPIRED');

-- CreateTable
CREATE TABLE "apps" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "clientSecretHash" TEXT NOT NULL,
    "redirectUrls" TEXT[],
    "webhookUrl" TEXT,
    "allowedScopes" TEXT[] DEFAULT ARRAY['identity']::TEXT[],
    "logoUrl" TEXT,
    "description" TEXT,
    "status" "AppStatus" NOT NULL DEFAULT 'ACTIVE',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "apps_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "auth_sessions" (
    "id" TEXT NOT NULL,
    "appId" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "status" "AuthSessionStatus" NOT NULL DEFAULT 'PENDING',
    "scopes" TEXT[] DEFAULT ARRAY['identity']::TEXT[],
    "userId" TEXT,
    "userAgent" TEXT,
    "clientIpHash" TEXT,
    "geoLat" DOUBLE PRECISION,
    "geoLng" DOUBLE PRECISION,
    "signature" TEXT,
    "redirectUrl" TEXT,
    "metadata" JSONB,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "scannedAt" TIMESTAMP(3),
    "resolvedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "auth_sessions_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "apps_slug_key" ON "apps"("slug");

-- CreateIndex
CREATE UNIQUE INDEX "apps_clientId_key" ON "apps"("clientId");

-- CreateIndex
CREATE INDEX "apps_organizationId_idx" ON "apps"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "auth_sessions_token_key" ON "auth_sessions"("token");

-- CreateIndex
CREATE INDEX "auth_sessions_appId_idx" ON "auth_sessions"("appId");

-- CreateIndex
CREATE INDEX "auth_sessions_token_idx" ON "auth_sessions"("token");

-- CreateIndex
CREATE INDEX "auth_sessions_status_expiresAt_idx" ON "auth_sessions"("status", "expiresAt");

-- AddForeignKey
ALTER TABLE "apps" ADD CONSTRAINT "apps_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "auth_sessions" ADD CONSTRAINT "auth_sessions_appId_fkey" FOREIGN KEY ("appId") REFERENCES "apps"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "auth_sessions" ADD CONSTRAINT "auth_sessions_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
