-- Audit 2026-10 FINDING-001 follow-up: email verification links expire.
-- Until now a verify token was valid for as long as the account stayed
-- unverified. New and re-sent links get 48 hours (routes/auth.ts).
ALTER TABLE "users" ADD COLUMN "emailVerifyExpires" TIMESTAMP(3);

-- Links already sent keep working for 48 hours from this deploy, then need
-- "resend verification" like any other expired link. Without this, every
-- outstanding link would be dead the moment the code that requires an expiry
-- starts running.
UPDATE "users"
SET "emailVerifyExpires" = NOW() + INTERVAL '48 hours'
WHERE "emailVerifyToken" IS NOT NULL AND "emailVerified" = false;
