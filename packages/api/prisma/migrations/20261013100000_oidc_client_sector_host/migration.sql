-- Audit 2026-10 FINDING-004: the pairwise sector identifier becomes a stored
-- value instead of something recomputed from the registration on every token.
-- Until now it was the host of "sectorIdentifierUri" or, without one, of the
-- FIRST redirect URI, so reordering redirect URIs silently changed every
-- user's `sub` at that client, and a registrant could choose the sector by
-- choosing the order.
--
-- No existing `sub` may change. STEP 2 therefore stores, for every row,
-- exactly the host lib/oidc-sub.ts deriveSectorIdentifier returns today.

-- STEP 1 — the column.
ALTER TABLE "oidc_clients" ADD COLUMN "sectorHost" TEXT;

-- Host of an absolute URI exactly as WHATWG `new URL(uri).host` reports it,
-- for the PLAIN shapes only: http/https, an ASCII host of letters, digits,
-- dots and hyphens, an optional port without leading zeros. For those,
-- lowercasing and dropping the scheme's default port is all the URL parser
-- does, so the two agree.
--
-- Everything else returns NULL instead of a guess: the URL parser also
-- punycodes Unicode hosts, decodes percent-escapes, canonicalises numeric
-- IPv4 forms and IPv6, strips tabs and newlines and treats backslashes as
-- slashes, none of which is reproduced here. A wrong guess would change a
-- `sub`; NULL makes the caller stop.
CREATE FUNCTION "oidc_uri_host"(uri TEXT) RETURNS TEXT
LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN m IS NULL THEN NULL
    -- A host whose last label is numeric (decimal or 0x hex) is an IPv4
    -- address to the URL parser; only the canonical dotted quad is plain.
    WHEN lower(m[2]) ~ '(^|\.)(0x[0-9a-f]*|[0-9]+)$'
         AND lower(m[2]) !~ '^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$' THEN NULL
    WHEN m[3] IS NULL THEN lower(m[2])
    WHEN lower(m[1]) = 'https' AND m[3] = '443' THEN lower(m[2])
    WHEN lower(m[1]) = 'http'  AND m[3] = '80'  THEN lower(m[2])
    ELSE lower(m[2]) || ':' || m[3]
  END
  FROM (
    SELECT regexp_match(
      uri,
      '^(https?)://([A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)(?::([1-9][0-9]{0,4}))?(?:[/?#].*)?$',
      'i'
    ) AS m
  ) AS parsed
$$;

-- STEP 2 — backfill with today's derivation (Postgres arrays are 1-indexed),
-- and refuse to continue if any row has a shape the function will not vouch
-- for. Nothing is left half-done: the migration is one transaction, so an
-- abort leaves the table as it was. To resolve one, work out
-- `new URL(uri).host` for each listed client and add an explicit
-- `UPDATE "oidc_clients" SET "sectorHost" = '<that host>' WHERE "clientId" = '…'`
-- to this file directly above the check, then deploy again (after
-- `prisma migrate resolve --rolled-back`).
UPDATE "oidc_clients"
SET "sectorHost" = "oidc_uri_host"(COALESCE("sectorIdentifierUri", "redirectUris"[1]))
WHERE "sectorHost" IS NULL;

DO $$
DECLARE unresolved TEXT;
BEGIN
  SELECT string_agg("clientId", ', ' ORDER BY "clientId") INTO unresolved
  FROM "oidc_clients" WHERE "sectorHost" IS NULL;
  IF unresolved IS NOT NULL THEN
    RAISE EXCEPTION 'oidc_client_sector_host aborted: cannot derive the sector host in SQL for client(s) %', unresolved;
  END IF;
END $$;

-- STEP 3 — keep it true whoever writes the row. The API sets "sectorHost"
-- itself at creation; scripts, seeds and operators inserting a client without
-- one get today's derivation, or an error for a shape the function will not
-- vouch for. Once set it cannot be changed by an UPDATE:
-- changing it would change every user's `sub` at that client. An operator who
-- really means to must drop this trigger deliberately. Prisma cannot express
-- triggers, so a future `prisma migrate dev` diff will not mention it; it
-- must not be dropped as "drift".
CREATE FUNCTION "oidc_clients_sector_host_guard"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW."sectorHost" IS NULL THEN
      NEW."sectorHost" := "oidc_uri_host"(COALESCE(NEW."sectorIdentifierUri", NEW."redirectUris"[1]));
    END IF;
    IF NEW."sectorHost" IS NULL THEN
      RAISE EXCEPTION 'oidc_clients.sectorHost cannot be derived in SQL for client %: set it explicitly', NEW."clientId";
    END IF;
  ELSIF OLD."sectorHost" IS NULL THEN
    -- A row that predates the column and was missed: fix it from the values
    -- it had BEFORE this update, never from the incoming ones.
    NEW."sectorHost" := "oidc_uri_host"(COALESCE(OLD."sectorIdentifierUri", OLD."redirectUris"[1]));
    IF NEW."sectorHost" IS NULL THEN
      RAISE EXCEPTION 'oidc_clients.sectorHost cannot be derived in SQL for client %: set it explicitly', OLD."clientId";
    END IF;
  ELSIF NEW."sectorHost" IS DISTINCT FROM OLD."sectorHost" THEN
    RAISE EXCEPTION 'oidc_clients.sectorHost is immutable (client %): changing it would change every pairwise sub', OLD."clientId";
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER "oidc_clients_sector_host_guard"
BEFORE INSERT OR UPDATE ON "oidc_clients"
FOR EACH ROW EXECUTE FUNCTION "oidc_clients_sector_host_guard"();
