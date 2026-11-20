-- Issue #62 (62c). Add a `source` provenance column to QRCode so the
-- pending-reconciler can skip seed-planted rows when scanning for
-- orphaned-merkle auto-revokes. Default 'runtime' so every existing
-- and future row has a categorical value; explicit 'seed' is set by
-- the seed scripts (prisma/seed.ts, scripts/seed-preview-bench.ts).
-- Other values reserved for future use: 'import' for bulk admin
-- imports.

ALTER TABLE "qr_codes"
  ADD COLUMN "source" TEXT DEFAULT 'runtime';
