-- ADR-0003 Slice 7b — per-client ID token signing algorithm preference.
--
-- OIDC Core §2 client metadata `id_token_signed_response_alg`. Default RS256,
-- the mandatory-to-implement baseline (OIDC Core §15.1). Additive column: the
-- NOT NULL DEFAULT 'RS256' backfills every existing row (today only
-- `phase1-test-client`) to RS256 per the locked decision. ES256 RPs opt in by
-- setting this column to 'ES256'. No existing column is altered.
ALTER TABLE "oidc_clients"
  ADD COLUMN "idTokenSignedResponseAlg" TEXT NOT NULL DEFAULT 'RS256';

-- Explicit backfill for clarity. Redundant with the DEFAULT above (Postgres
-- applies it to existing rows on ADD COLUMN), but the locked decision calls for
-- an explicit backfill of existing rows to RS256.
UPDATE "oidc_clients" SET "idTokenSignedResponseAlg" = 'RS256';
