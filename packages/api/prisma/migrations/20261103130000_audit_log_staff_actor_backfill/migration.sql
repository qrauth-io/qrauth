-- Entries written by QRAuth staff before the actor model (ADR-0008 D1) were
-- stored as USER rows. Every staff-written action is named admin.* (the
-- superadmin routes in routes/admin.ts, admin-abuse.ts and fraud-rules.ts on
-- main before 20261103120000); mark them SUPERADMIN so the organization
-- sees "QRAuth" and no staff identity, IP or user agent.
-- The append-only trigger refuses UPDATE, so it is off for this statement.

-- BEGIN staff-actor-backfill
ALTER TABLE "audit_logs" DISABLE TRIGGER "audit_logs_append_only";
UPDATE "audit_logs" SET "actorType" = 'SUPERADMIN' WHERE "action" LIKE 'admin.%' AND "actorType" = 'USER';
ALTER TABLE "audit_logs" ENABLE TRIGGER "audit_logs_append_only";
-- END staff-actor-backfill
