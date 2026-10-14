-- Geo-fence enforcement opt-out flag. When TRUE (default), a geo-bound QR
-- code fails closed at /v/:token unless the scanner is inside the fence.
-- When FALSE, the binding is advisory: distance is still computed and
-- returned in `location_match`, but never gates `verified`. Ignored when
-- latitude/longitude are NULL (the QR is not geo-bound).
--
-- DEFAULT TRUE so existing geo-bound rows hard-block on deploy.
ALTER TABLE "qr_codes" ADD COLUMN "requireProximity" BOOLEAN NOT NULL DEFAULT true;
