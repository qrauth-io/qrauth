-- Issue #62 (62a). Re-point the column-level DEFAULT for `algVersion` on
-- both QRCode and TransparencyLogEntry from the legacy
-- `ecdsa-p256-sha256-v1` (now REJECTED at verify, see
-- packages/shared/src/alg-versions.ts) to `hybrid-ecdsa-slhdsa-v1`.
--
-- Any future row inserted without an explicit override (seed scripts,
-- tests, ad-hoc admin paths) now lands on the accepted alg version.
-- Pre-migration verification on prod (2026-05-02) showed all 41 QRCode
-- rows and all 41 transparency_log rows already on hybrid — no
-- backfill needed. The two ALTER COLUMN statements below only change
-- the column default; existing rows are untouched.

ALTER TABLE "qr_codes"
  ALTER COLUMN "algVersion" SET DEFAULT 'hybrid-ecdsa-slhdsa-v1';

ALTER TABLE "transparency_log"
  ALTER COLUMN "algVersion" SET DEFAULT 'hybrid-ecdsa-slhdsa-v1';
