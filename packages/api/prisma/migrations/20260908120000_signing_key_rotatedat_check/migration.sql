-- ROTATED requires rotatedAt (docs/ops/signing-key-rotation-loop.md,
-- 2026-09-08 design note: JWKS publication is now time-bounded on rotatedAt).
--
-- rotatedAt is nullable, and null is asymmetric across the two consumers of
-- the column: in the revocation filter (rotatedAt < cutoff) a null means
-- "never swept" — fail-safe; in the JWKS publication filter
-- (rotatedAt >= cutoff) the same null means "never published" — the key
-- silently disappears from JWKS and RPs fail verification with no error on
-- our side. Rather than defensively handling null in the publication query,
-- make the invalid state unrepresentable: a ROTATED row must carry its
-- rotation timestamp.
--
-- STEP 1 — make existing data satisfy the constraint BEFORE creating it
-- (same pattern as 20260907120000_signing_key_active_unique). No production
-- row violates this today (both the dedupe migration and
-- SigningService.rotateResolvedKey set rotatedAt on demotion), so this
-- UPDATE is expected to touch zero rows — it exists so the migration cannot
-- fail on a dev/staging database with historical hand-made rows. The
-- backfill uses COALESCE(revokedAt, createdAt): the earliest defensible
-- bound, which errs on the safe side for both consumers (treated as
-- long-rotated -> not published, and immediately eligible for the
-- grace-window sweep).
UPDATE "signing_keys"
SET "rotatedAt" = COALESCE("revokedAt", "createdAt")
WHERE "status" = 'ROTATED' AND "rotatedAt" IS NULL;

-- STEP 2 — enforce.
ALTER TABLE "signing_keys"
  ADD CONSTRAINT "signing_keys_rotated_requires_rotatedat"
  CHECK ("status" <> 'ROTATED' OR "rotatedAt" IS NOT NULL);
