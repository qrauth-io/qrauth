-- ADR-0003 Slice 3b.2 — provision the first-party `qrauth-op` App on the
-- QRAuth Platform org. This is the App the OpenID Provider's /login page uses
-- to create auth-sessions scan-approval sessions (read-only consumer of the
-- auth-sessions mechanism). The user scans the QR on a device where they are
-- signed in and approves; the OP reads the resolved `userId` from the
-- approval to mint an OP session.
--
-- DATA migration (no DDL), idempotent via ON CONFLICT (slug) DO NOTHING, in
-- the migration history because CI runs `prisma migrate deploy` (not db:seed).
-- Mirrors 20260521120100_provision_qrauth_cli_app byte-style.
--
-- Approval signing is NORMAL (no skip): the Platform org has an ACTIVE ES256
-- signing key (provisioned Slice 1/3a), so `approveSession` signs the
-- approval with it. The OP ignores the signature value — it only reads the
-- resolved `userId`. The original "skip signing" plan mirrored qrauth-cli,
-- whose skip exists solely because its org was once keyless; that rationale
-- no longer applies, and skipping would require modifying the auth-sessions
-- service (out of scope). See ADR-0003 status log.
--
-- clientSecretHash is NOT NULL but no real secret is ever issued: the OP
-- calls AuthSessionService.createSession(appId, ...) in-process with this
-- App's id, never authenticating over HTTP. We hash a freshly random,
-- immediately-discarded UUID so the column holds an unguessable value whose
-- preimage exists nowhere — identical to the qrauth-cli pattern.

INSERT INTO "apps" ("id", "organizationId", "name", "slug", "clientId", "clientSecretHash", "redirectUrls", "allowedScopes", "updatedAt")
VALUES (
  'app_qrauth_op',
  (SELECT "id" FROM "organizations" WHERE "slug" = 'qrauth-platform'),
  'Sign in with QRAuth',
  'qrauth-op',
  'qrauth-op',
  encode(sha256((gen_random_uuid()::text)::bytea), 'hex'),
  ARRAY[]::text[],
  ARRAY['identity']::text[],
  CURRENT_TIMESTAMP
)
ON CONFLICT ("slug") DO NOTHING;
