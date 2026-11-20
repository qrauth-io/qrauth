-- qr_codes."algVersion" becomes required with no default. Every insert must
-- state the algorithm version it signed; there is no implicit fallback.
--
-- SET NOT NULL fails (and the migration rolls back) if any row is NULL.
ALTER TABLE "qr_codes" ALTER COLUMN "algVersion" DROP DEFAULT;
ALTER TABLE "qr_codes" ALTER COLUMN "algVersion" SET NOT NULL;
