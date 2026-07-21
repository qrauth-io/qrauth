-- CreateTable
CREATE TABLE "oidc_sessions" (
    "id" TEXT NOT NULL,
    "sessionTokenHash" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),

    CONSTRAINT "oidc_sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "oidc_access_tokens" (
    "id" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "oidcClientId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "scope" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revokedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "oidc_access_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "oidc_sessions_sessionTokenHash_key" ON "oidc_sessions"("sessionTokenHash");

-- CreateIndex
CREATE INDEX "oidc_sessions_userId_idx" ON "oidc_sessions"("userId");

-- CreateIndex
CREATE INDEX "oidc_sessions_expiresAt_idx" ON "oidc_sessions"("expiresAt");

-- CreateIndex
CREATE UNIQUE INDEX "oidc_access_tokens_tokenHash_key" ON "oidc_access_tokens"("tokenHash");

-- CreateIndex
CREATE INDEX "oidc_access_tokens_oidcClientId_idx" ON "oidc_access_tokens"("oidcClientId");

-- CreateIndex
CREATE INDEX "oidc_access_tokens_userId_idx" ON "oidc_access_tokens"("userId");

-- CreateIndex
CREATE INDEX "oidc_access_tokens_expiresAt_idx" ON "oidc_access_tokens"("expiresAt");

-- AddForeignKey
ALTER TABLE "oidc_sessions" ADD CONSTRAINT "oidc_sessions_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "oidc_access_tokens" ADD CONSTRAINT "oidc_access_tokens_oidcClientId_fkey" FOREIGN KEY ("oidcClientId") REFERENCES "oidc_clients"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "oidc_access_tokens" ADD CONSTRAINT "oidc_access_tokens_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
