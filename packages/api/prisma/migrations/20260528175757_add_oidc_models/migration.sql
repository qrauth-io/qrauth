-- CreateEnum
CREATE TYPE "OidcClientTier" AS ENUM ('FIRST_PARTY', 'CUSTOMER', 'PUBLIC');

-- CreateEnum
CREATE TYPE "OidcCodeChallengeMethod" AS ENUM ('S256');

-- CreateTable
CREATE TABLE "oidc_clients" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "clientSecretHash" TEXT,
    "name" TEXT NOT NULL,
    "redirectUris" TEXT[],
    "allowedScopes" TEXT[] DEFAULT ARRAY['openid']::TEXT[],
    "tier" "OidcClientTier" NOT NULL DEFAULT 'FIRST_PARTY',
    "sectorIdentifierUri" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "oidc_clients_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "oidc_auth_codes" (
    "id" TEXT NOT NULL,
    "codeHash" TEXT NOT NULL,
    "oidcClientId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "redirectUri" TEXT NOT NULL,
    "scope" TEXT NOT NULL,
    "codeChallenge" TEXT NOT NULL,
    "codeChallengeMethod" "OidcCodeChallengeMethod" NOT NULL DEFAULT 'S256',
    "nonce" TEXT,
    "authTime" TIMESTAMP(3) NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "usedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "oidc_auth_codes_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "oidc_consents" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "oidcClientId" TEXT NOT NULL,
    "grantedScopes" TEXT[],
    "grantedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "revokedAt" TIMESTAMP(3),

    CONSTRAINT "oidc_consents_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "oidc_refresh_tokens" (
    "id" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "familyId" TEXT NOT NULL,
    "oidcClientId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "scope" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "rotatedAt" TIMESTAMP(3),
    "revokedAt" TIMESTAMP(3),
    "replacedById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "oidc_refresh_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "oidc_clients_clientId_key" ON "oidc_clients"("clientId");

-- CreateIndex
CREATE INDEX "oidc_clients_organizationId_idx" ON "oidc_clients"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "oidc_auth_codes_codeHash_key" ON "oidc_auth_codes"("codeHash");

-- CreateIndex
CREATE INDEX "oidc_auth_codes_oidcClientId_idx" ON "oidc_auth_codes"("oidcClientId");

-- CreateIndex
CREATE INDEX "oidc_auth_codes_userId_idx" ON "oidc_auth_codes"("userId");

-- CreateIndex
CREATE INDEX "oidc_auth_codes_expiresAt_idx" ON "oidc_auth_codes"("expiresAt");

-- CreateIndex
CREATE INDEX "oidc_consents_oidcClientId_idx" ON "oidc_consents"("oidcClientId");

-- CreateIndex
CREATE UNIQUE INDEX "oidc_consents_userId_oidcClientId_key" ON "oidc_consents"("userId", "oidcClientId");

-- CreateIndex
CREATE UNIQUE INDEX "oidc_refresh_tokens_tokenHash_key" ON "oidc_refresh_tokens"("tokenHash");

-- CreateIndex
CREATE UNIQUE INDEX "oidc_refresh_tokens_replacedById_key" ON "oidc_refresh_tokens"("replacedById");

-- CreateIndex
CREATE INDEX "oidc_refresh_tokens_familyId_idx" ON "oidc_refresh_tokens"("familyId");

-- CreateIndex
CREATE INDEX "oidc_refresh_tokens_oidcClientId_idx" ON "oidc_refresh_tokens"("oidcClientId");

-- CreateIndex
CREATE INDEX "oidc_refresh_tokens_userId_idx" ON "oidc_refresh_tokens"("userId");

-- CreateIndex
CREATE INDEX "oidc_refresh_tokens_expiresAt_idx" ON "oidc_refresh_tokens"("expiresAt");

-- AddForeignKey
ALTER TABLE "oidc_clients" ADD CONSTRAINT "oidc_clients_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "oidc_auth_codes" ADD CONSTRAINT "oidc_auth_codes_oidcClientId_fkey" FOREIGN KEY ("oidcClientId") REFERENCES "oidc_clients"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "oidc_auth_codes" ADD CONSTRAINT "oidc_auth_codes_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "oidc_consents" ADD CONSTRAINT "oidc_consents_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "oidc_consents" ADD CONSTRAINT "oidc_consents_oidcClientId_fkey" FOREIGN KEY ("oidcClientId") REFERENCES "oidc_clients"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "oidc_refresh_tokens" ADD CONSTRAINT "oidc_refresh_tokens_oidcClientId_fkey" FOREIGN KEY ("oidcClientId") REFERENCES "oidc_clients"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "oidc_refresh_tokens" ADD CONSTRAINT "oidc_refresh_tokens_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "oidc_refresh_tokens" ADD CONSTRAINT "oidc_refresh_tokens_replacedById_fkey" FOREIGN KEY ("replacedById") REFERENCES "oidc_refresh_tokens"("id") ON DELETE SET NULL ON UPDATE CASCADE;
