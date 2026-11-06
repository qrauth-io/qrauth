-- ADR-0002 (CLI QR login) §1 — provision the platform system org + the
-- first-party `qrauth-cli` public-client app.
--
-- This is a DATA migration (no DDL). It lives in the migration history rather
-- than prisma/seed.ts because db:seed does NOT run on deploy — CI only runs
-- `prisma migrate deploy`. Both INSERTs are idempotent via ON CONFLICT (slug)
-- DO NOTHING, so re-running on an already-provisioned database is a no-op.

-- System organisation that owns first-party platform apps (qrauth-cli today,
-- future first-party clients later). Distinct from any customer tenant.
INSERT INTO "organizations" ("id", "name", "slug", "email", "updatedAt")
VALUES ('org_qrauth_platform', 'QRAuth Platform', 'qrauth-platform', 'platform@qrauth.io', CURRENT_TIMESTAMP)
ON CONFLICT ("slug") DO NOTHING;

-- First-party CLI app. PKCE-only public client: it authenticates with
-- X-Client-Id only (stable well-known id 'qrauth-cli' so the published CLI can
-- ship it). The clientSecretHash column is NOT NULL, but no secret is ever
-- issued for this app — we hash a freshly random, immediately-discarded UUID so
-- the column is satisfied with an unguessable value whose preimage exists
-- nowhere. redirectUrls is empty (the CLI polls, never redirects); the
-- dedicated 'cli' scope marks it as a first-party CLI client.
INSERT INTO "apps" ("id", "organizationId", "name", "slug", "clientId", "clientSecretHash", "redirectUrls", "allowedScopes", "updatedAt")
VALUES (
  'app_qrauth_cli',
  (SELECT "id" FROM "organizations" WHERE "slug" = 'qrauth-platform'),
  'QRAuth CLI',
  'qrauth-cli',
  'qrauth-cli',
  encode(sha256((gen_random_uuid()::text)::bytea), 'hex'),
  ARRAY[]::text[],
  ARRAY['cli']::text[],
  CURRENT_TIMESTAMP
)
ON CONFLICT ("slug") DO NOTHING;
