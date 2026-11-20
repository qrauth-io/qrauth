-- Audit 2026-10 FINDING-001: account emails are stored in canonical form
-- (trimmed, lowercased; lib/email-normalize.ts). New rows have been written
-- that way since the fix; this brings the rows created before it into line so
-- every lookup can use the canonical form only.
--
-- Data-only migration, no schema change. "users"."email" and
-- "organizations"."email" are both UNIQUE, so two rows that differ only in
-- case or surrounding whitespace cannot both be rewritten.
--
-- STEP 1 — refuse to run if any such pair exists. Nothing has been changed at
-- this point, so a failed deploy leaves the data exactly as it was. Resolve
-- the rows by hand (scripts/check-email-case-collisions.ts lists the user
-- ids), then re-run. The messages carry counts only, never an address.
DO $$
DECLARE
  user_collisions integer;
  org_collisions  integer;
BEGIN
  SELECT count(*) INTO user_collisions FROM (
    SELECT 1 FROM "users"
    GROUP BY lower(btrim("email", E' \t\n\r'))
    HAVING count(*) > 1
  ) AS groups;

  SELECT count(*) INTO org_collisions FROM (
    SELECT 1 FROM "organizations"
    GROUP BY lower(btrim("email", E' \t\n\r'))
    HAVING count(*) > 1
  ) AS groups;

  IF user_collisions > 0 OR org_collisions > 0 THEN
    RAISE EXCEPTION
      'normalize_account_emails aborted: % user and % organization email group(s) differ only in case or whitespace',
      user_collisions, org_collisions;
  END IF;
END $$;

-- STEP 2 — rewrite only the rows that are not already canonical.
UPDATE "users"
SET "email" = lower(btrim("email", E' \t\n\r'))
WHERE "email" <> lower(btrim("email", E' \t\n\r'));

UPDATE "organizations"
SET "email" = lower(btrim("email", E' \t\n\r'))
WHERE "email" <> lower(btrim("email", E' \t\n\r'));
