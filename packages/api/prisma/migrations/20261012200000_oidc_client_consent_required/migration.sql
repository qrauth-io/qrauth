-- Audit 2026-10 FINDING-002: consent is asked for self-serve clients, but an
-- operator may vet a client and let it skip the page. Every existing row
-- keeps consent required; only scripts/oidc-set-trusted.ts turns it off.
ALTER TABLE "oidc_clients" ADD COLUMN "consentRequired" BOOLEAN NOT NULL DEFAULT true;
