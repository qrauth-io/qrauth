-- Add original end-user auth event to refresh tokens (OIDC Core §12.2).
-- Refreshed ID tokens must echo the same auth_time as the original; this is
-- inherited across rotations. Nullable so existing rows need no backfill.
ALTER TABLE "oidc_refresh_tokens" ADD COLUMN "authTime" TIMESTAMP(3);
