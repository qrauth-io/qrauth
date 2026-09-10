-- One ACTIVE signing key per (organization, algorithm)
-- (docs/ops/signing-key-rotation-loop.md, fix 6).
--
-- The cleanup worker and every getActiveKey consumer already assume this
-- invariant; nothing enforced it, which let the platform org hold two ACTIVE
-- keys (the hourly rotation loop's ignition condition). Prisma cannot express
-- a partial unique index, so this is raw SQL — the index is documented on the
-- SigningKey model in schema.prisma; a future `prisma migrate dev` diff that
-- proposes dropping "signing_keys_org_algorithm_active_unique" must be
-- rejected.
--
-- STEP 1 — make existing data satisfy the invariant BEFORE creating the
-- index, or the migration fails on deploy: production currently holds two
-- ACTIVE ES256 keys on the platform org (the stale pre-loop key plus the
-- latest hourly mint). Demote every ACTIVE key that has a newer ACTIVE key of
-- the same (organization, algorithm) — keeping the newest matches the
-- getActiveKey ordering, so the key every signer is currently using stays
-- ACTIVE. Ties on "createdAt" (sub-millisecond double-mints) break by id.
UPDATE "signing_keys" sk
SET "status" = 'ROTATED', "rotatedAt" = NOW()
WHERE sk."status" = 'ACTIVE'
  AND EXISTS (
    SELECT 1 FROM "signing_keys" newer
    WHERE newer."organizationId" = sk."organizationId"
      AND newer."algorithm" = sk."algorithm"
      AND newer."status" = 'ACTIVE'
      AND (newer."createdAt" > sk."createdAt"
           OR (newer."createdAt" = sk."createdAt" AND newer."id" > sk."id"))
  );

-- STEP 2 — enforce the invariant. Any future code path that would mint a
-- second ACTIVE key for the same (organization, algorithm) now fails with a
-- unique-violation write error instead of silently drifting.
CREATE UNIQUE INDEX "signing_keys_org_algorithm_active_unique"
  ON "signing_keys" ("organizationId", "algorithm")
  WHERE "status" = 'ACTIVE';
