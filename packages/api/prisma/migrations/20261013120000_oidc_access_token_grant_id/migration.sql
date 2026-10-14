-- Audit 2026-10 FINDING-018: link access tokens to the grant they came from,
-- so a replayed authorization code or an invalidated refresh family can
-- revoke them. Nullable, no backfill: tokens issued before this live at most
-- one hour.
ALTER TABLE "oidc_access_tokens" ADD COLUMN "grantId" TEXT;

CREATE INDEX "oidc_access_tokens_grantId_idx" ON "oidc_access_tokens"("grantId");

-- Set when an already-used code is presented again, so a redemption that is
-- still issuing tokens at that moment can see it and revoke them.
ALTER TABLE "oidc_auth_codes" ADD COLUMN "replayedAt" TIMESTAMP(3);

-- The cleanup worker deletes refresh tokens by age (FINDING-020).
CREATE INDEX "oidc_refresh_tokens_createdAt_idx" ON "oidc_refresh_tokens"("createdAt");
