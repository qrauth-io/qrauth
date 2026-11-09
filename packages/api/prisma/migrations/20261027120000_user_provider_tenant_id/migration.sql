-- Microsoft tenant id (`tid`) of a user's linked Microsoft identity.
-- Additive and nullable: existing rows stay NULL and are filled in by their
-- next Microsoft sign-in. No backfill here. Adding a nullable column with no
-- default does not rewrite the table.
ALTER TABLE "users" ADD COLUMN "providerTenantId" TEXT;
