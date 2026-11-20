-- GDPR erasure (ADR-0008 D4): match the erased email address
-- case-insensitively. Email addresses are compared by lower() on both
-- sides, so an entry that stored the address as typed (e.g. older entries
-- with capitals) is redacted too. Whole JSON string values only, at any
-- depth; ipCountry is still dropped at the top level. The append-only
-- trigger calls audit_redact_subject by name, so it uses this version.

CREATE FUNCTION "audit_redact_value"(v jsonb, subject text) RETURNS jsonb
LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE jsonb_typeof(v)
    WHEN 'string' THEN
      CASE WHEN lower(v #>> '{}') = lower(subject) THEN to_jsonb('[redacted]'::text) ELSE v END
    WHEN 'object' THEN
      (SELECT coalesce(jsonb_object_agg(e.key, "audit_redact_value"(e.value, subject)), '{}'::jsonb)
       FROM jsonb_each(v) e)
    WHEN 'array' THEN
      (SELECT coalesce(jsonb_agg("audit_redact_value"(e.value, subject) ORDER BY e.ord), '[]'::jsonb)
       FROM jsonb_array_elements(v) WITH ORDINALITY e(value, ord))
    ELSE v
  END
$$;

CREATE OR REPLACE FUNCTION "audit_redact_subject"(meta jsonb, subject text) RETURNS jsonb
LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN meta IS NULL THEN NULL
    WHEN subject IS NULL OR subject = '' THEN meta - 'ipCountry'
    ELSE "audit_redact_value"(meta, subject) - 'ipCountry'
  END
$$;
