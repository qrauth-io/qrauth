-- GDPR erasure of an account (ADR-0008 D4), widened to exactly what erasure
-- needs and no more. Under qrauth.audit_maintenance = 'erasure' an UPDATE
-- of audit_logs may:
--   * clear ipAddress and/or userAgent (set them to NULL, never change them);
--   * replace, in metadata, every JSON string equal to the erased address
--     (qrauth.erasure_subject, set in the same transaction) with
--     "[redacted]", and remove the ipCountry key.
-- Every other column must stay as it was.

-- The redaction itself, shared by the trigger and services/audit.ts so both
-- compute the same value. JSON-text replace of the quoted string matches
-- whole string values only.
CREATE FUNCTION "audit_redact_subject"(meta jsonb, subject text) RETURNS jsonb
LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN meta IS NULL THEN NULL
    WHEN subject IS NULL OR subject = '' THEN meta - 'ipCountry'
    ELSE replace(meta::text, to_jsonb(subject)::text, '"[redacted]"')::jsonb - 'ipCountry'
  END
$$;

CREATE OR REPLACE FUNCTION "audit_logs_append_only"() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  flag text := current_setting('qrauth.audit_maintenance', true);
  subject text := current_setting('qrauth.erasure_subject', true);
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF flag = 'erasure'
       AND (NEW."ipAddress" IS NULL OR NEW."ipAddress" IS NOT DISTINCT FROM OLD."ipAddress")
       AND (NEW."userAgent" IS NULL OR NEW."userAgent" IS NOT DISTINCT FROM OLD."userAgent")
       AND (NEW."metadata" IS NOT DISTINCT FROM OLD."metadata"
            OR NEW."metadata" IS NOT DISTINCT FROM "audit_redact_subject"(OLD."metadata", subject))
       AND (to_jsonb(NEW) - 'ipAddress' - 'userAgent' - 'metadata') = (to_jsonb(OLD) - 'ipAddress' - 'userAgent' - 'metadata') THEN
      RETURN NEW;
    END IF;
    RAISE EXCEPTION 'audit_logs is append-only: rows are never updated';
  END IF;
  IF (flag = 'retention' AND OLD."createdAt" < now() - interval '730 days')
     OR NOT EXISTS (SELECT 1 FROM "organizations" WHERE "id" = OLD."organizationId") THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'audit_logs is append-only: rows are deleted only by the 730-day retention';
END;
$$;
