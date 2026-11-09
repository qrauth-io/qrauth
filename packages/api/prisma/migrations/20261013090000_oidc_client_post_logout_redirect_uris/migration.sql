-- Audit 2026-10 FINDING-011: RP-initiated logout. A client may register the
-- URIs the OP is allowed to send the browser to after sign-out; the
-- end-session endpoint redirects only to an exact match. Empty by default, so
-- no existing client gains a redirect target.
ALTER TABLE "oidc_clients" ADD COLUMN "postLogoutRedirectUris" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];
