-- Trust Records schema (ADR-0009 D2). Additive only: new enum types, five
-- new tables, foreign keys among them, CHECK constraints, the dense leaf
-- index guard and append-only triggers. No existing table is altered, so no
-- lock is taken on any existing table. The tables stay empty until the write
-- path ships (ADR-0009 TR-2).
--
-- No foreign key points from these tables to organizations or qr_codes: log
-- data outlives both, and trust_subjects.qrCodeId is left dangling when a code
-- is deleted (D4).

-- CreateEnum
CREATE TYPE "TrustSubjectKind" AS ENUM ('QR_CODE');

-- CreateEnum
CREATE TYPE "TrustEventType" AS ENUM ('ISSUED', 'UPDATED', 'REVOKED');

-- CreateEnum
CREATE TYPE "TrustActorType" AS ENUM ('USER', 'API_KEY', 'SYSTEM');

-- CreateEnum
CREATE TYPE "TrustLeafKind" AS ENUM ('EVENT', 'BATCH', 'KEYSET', 'LEGACY_SNAPSHOT');

-- CreateEnum
CREATE TYPE "TrustAnchorKind" AS ENUM ('OTS', 'RFC3161');

-- CreateEnum
CREATE TYPE "TrustAnchorStatus" AS ENUM ('PENDING', 'COMPLETE', 'FAILED');

-- CreateTable
CREATE TABLE "trust_subjects" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "kind" "TrustSubjectKind" NOT NULL,
    "qrCodeId" TEXT,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "trust_subjects_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "trust_events" (
    "id" TEXT NOT NULL,
    "subjectId" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "seq" INTEGER NOT NULL,
    "type" "TrustEventType" NOT NULL,
    "backfilled" BOOLEAN NOT NULL DEFAULT false,
    "actorType" "TrustActorType" NOT NULL,
    "actorId" TEXT,
    "state" JSONB NOT NULL,
    "payload" JSONB,
    "salt" BYTEA,
    "eventCommitment" BYTEA NOT NULL,
    "prevEventCommitment" BYTEA,
    "occurredAt" TIMESTAMPTZ(3) NOT NULL,
    "appendedAt" TIMESTAMPTZ(3) NOT NULL,
    "leafIndex" BIGINT NOT NULL,

    CONSTRAINT "trust_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "trust_log_leaves" (
    "leafIndex" BIGINT NOT NULL,
    "kind" "TrustLeafKind" NOT NULL,
    "organizationId" TEXT,
    "body" BYTEA NOT NULL,
    "leafHash" BYTEA NOT NULL,
    "appendedAt" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "trust_log_leaves_pkey" PRIMARY KEY ("leafIndex")
);

-- CreateTable
CREATE TABLE "trust_tree_heads" (
    "treeSize" BIGINT NOT NULL,
    "origin" TEXT NOT NULL,
    "rootHash" BYTEA NOT NULL,
    "signedAt" TIMESTAMPTZ(3) NOT NULL,
    "keyId" TEXT NOT NULL,
    "signature" BYTEA NOT NULL,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "trust_tree_heads_pkey" PRIMARY KEY ("treeSize")
);

-- CreateTable
CREATE TABLE "trust_anchor_proofs" (
    "id" TEXT NOT NULL,
    "treeSize" BIGINT NOT NULL,
    "kind" "TrustAnchorKind" NOT NULL,
    "status" "TrustAnchorStatus" NOT NULL DEFAULT 'PENDING',
    "endpoint" TEXT NOT NULL,
    "digest" BYTEA NOT NULL,
    "proof" BYTEA,
    "submittedAt" TIMESTAMPTZ(3) NOT NULL,
    "upgradedAt" TIMESTAMPTZ(3),
    "attestedTime" TIMESTAMPTZ(3),
    "attestation" TEXT,
    "error" TEXT,

    CONSTRAINT "trust_anchor_proofs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "trust_subjects_qrCodeId_key" ON "trust_subjects"("qrCodeId");

-- CreateIndex
CREATE INDEX "trust_subjects_organizationId_idx" ON "trust_subjects"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "trust_events_leafIndex_key" ON "trust_events"("leafIndex");

-- CreateIndex
CREATE INDEX "trust_events_organizationId_idx" ON "trust_events"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "trust_events_subjectId_seq_key" ON "trust_events"("subjectId", "seq");

-- CreateIndex
CREATE INDEX "trust_log_leaves_organizationId_leafIndex_idx" ON "trust_log_leaves"("organizationId", "leafIndex");

-- CreateIndex
CREATE INDEX "trust_anchor_proofs_treeSize_idx" ON "trust_anchor_proofs"("treeSize");

-- CreateIndex
CREATE INDEX "trust_anchor_proofs_status_idx" ON "trust_anchor_proofs"("status");

-- AddForeignKey
ALTER TABLE "trust_events" ADD CONSTRAINT "trust_events_subjectId_fkey" FOREIGN KEY ("subjectId") REFERENCES "trust_subjects"("id") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "trust_events" ADD CONSTRAINT "trust_events_leafIndex_fkey" FOREIGN KEY ("leafIndex") REFERENCES "trust_log_leaves"("leafIndex") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "trust_anchor_proofs" ADD CONSTRAINT "trust_anchor_proofs_treeSize_fkey" FOREIGN KEY ("treeSize") REFERENCES "trust_tree_heads"("treeSize") ON DELETE RESTRICT ON UPDATE RESTRICT;


-- ---------------------------------------------------------------------------
-- CHECK constraints. Hashes are SHA-256 (ADR-0009 D1): exactly 32 bytes.
-- ---------------------------------------------------------------------------

ALTER TABLE "trust_subjects"
  ADD CONSTRAINT "trust_subjects_qr_code_named" CHECK ("kind" <> 'QR_CODE' OR "qrCodeId" IS NOT NULL);

ALTER TABLE "trust_log_leaves"
  ADD CONSTRAINT "trust_log_leaves_index_nonnegative" CHECK ("leafIndex" >= 0),
  ADD CONSTRAINT "trust_log_leaves_hash_32" CHECK (octet_length("leafHash") = 32),
  ADD CONSTRAINT "trust_log_leaves_body_size" CHECK (octet_length("body") BETWEEN 1 AND 4096),
  -- EVENT and BATCH leaves belong to an organization; KEYSET and
  -- LEGACY_SNAPSHOT are platform leaves.
  ADD CONSTRAINT "trust_log_leaves_org_by_kind" CHECK (("kind" IN ('EVENT', 'BATCH')) = ("organizationId" IS NOT NULL));

ALTER TABLE "trust_events"
  ADD CONSTRAINT "trust_events_seq_positive" CHECK ("seq" >= 1),
  ADD CONSTRAINT "trust_events_commitment_32" CHECK (octet_length("eventCommitment") = 32),
  ADD CONSTRAINT "trust_events_prev_commitment_32" CHECK ("prevEventCommitment" IS NULL OR octet_length("prevEventCommitment") = 32),
  ADD CONSTRAINT "trust_events_prev_iff_not_first" CHECK (("seq" = 1) = ("prevEventCommitment" IS NULL)),
  ADD CONSTRAINT "trust_events_salt_32" CHECK ("salt" IS NULL OR octet_length("salt") = 32);

ALTER TABLE "trust_tree_heads"
  ADD CONSTRAINT "trust_tree_heads_size_nonnegative" CHECK ("treeSize" >= 0),
  ADD CONSTRAINT "trust_tree_heads_root_32" CHECK (octet_length("rootHash") = 32),
  ADD CONSTRAINT "trust_tree_heads_signature_present" CHECK (octet_length("signature") > 0),
  ADD CONSTRAINT "trust_tree_heads_origin_present" CHECK ("origin" <> '');

ALTER TABLE "trust_anchor_proofs"
  ADD CONSTRAINT "trust_anchor_proofs_digest_32" CHECK (octet_length("digest") = 32),
  ADD CONSTRAINT "trust_anchor_proofs_complete_has_proof" CHECK ("status" <> 'COMPLETE' OR ("proof" IS NOT NULL AND "attestedTime" IS NOT NULL)),
  ADD CONSTRAINT "trust_anchor_proofs_failed_has_error" CHECK ("status" <> 'FAILED' OR "error" IS NOT NULL);

-- ---------------------------------------------------------------------------
-- Dense leaf index. Every insert takes the same transaction-scoped advisory
-- lock and must use exactly max + 1 (0 for the first leaf), so appends are
-- serialized and leafIndex has no gap: a gap or a duplicate is always a
-- tamper signal. A rolled-back append releases its index for the next one.
-- Writers call trust_log_next_leaf_index() and insert in the same
-- transaction, at READ COMMITTED (the default); under a fixed snapshot the
-- guard refuses the insert rather than leave a gap.
-- ---------------------------------------------------------------------------

CREATE FUNCTION "trust_log_next_leaf_index"() RETURNS bigint
LANGUAGE plpgsql VOLATILE AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('qrauth:trust-log:append', 0));
  RETURN (SELECT COALESCE(MAX("leafIndex") + 1, 0) FROM "trust_log_leaves");
END;
$$;

CREATE FUNCTION "trust_log_leaves_dense"() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  expected bigint;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('qrauth:trust-log:append', 0));
  SELECT COALESCE(MAX("leafIndex") + 1, 0) INTO expected FROM "trust_log_leaves";
  IF NEW."leafIndex" IS DISTINCT FROM expected THEN
    RAISE EXCEPTION 'trust_log_leaves is dense: the next leafIndex is %, got %', expected, NEW."leafIndex";
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "trust_log_leaves_dense"
  BEFORE INSERT ON "trust_log_leaves"
  FOR EACH ROW EXECUTE FUNCTION "trust_log_leaves_dense"();

-- ---------------------------------------------------------------------------
-- Append-only. The guards protect against application bugs and against
-- anyone without the rights to disable triggers; they are not a privilege
-- boundary against the database owner. Tampering by the owner is what the
-- signed, anchored tree heads detect (ADR-0009 D7, D10).
-- ---------------------------------------------------------------------------

-- Subjects, leaves and tree heads: no UPDATE, no DELETE.
CREATE FUNCTION "trust_refuse_change"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: % is refused', TG_TABLE_NAME, TG_OP;
END;
$$;

CREATE TRIGGER "trust_subjects_append_only"
  BEFORE UPDATE OR DELETE ON "trust_subjects"
  FOR EACH ROW EXECUTE FUNCTION "trust_refuse_change"();

CREATE TRIGGER "trust_log_leaves_append_only"
  BEFORE UPDATE OR DELETE ON "trust_log_leaves"
  FOR EACH ROW EXECUTE FUNCTION "trust_refuse_change"();

CREATE TRIGGER "trust_tree_heads_append_only"
  BEFORE UPDATE OR DELETE ON "trust_tree_heads"
  FOR EACH ROW EXECUTE FUNCTION "trust_refuse_change"();

-- Events: no UPDATE, no DELETE, except the GDPR erasure (D11): an UPDATE that
-- only clears payload and salt, under qrauth.audit_maintenance = 'erasure'
-- (the flag the audit log uses, ADR-0008 D4). The commitment stays.
CREATE FUNCTION "trust_events_append_only"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE'
     AND current_setting('qrauth.audit_maintenance', true) = 'erasure'
     AND NEW."payload" IS NULL AND NEW."salt" IS NULL
     AND (to_jsonb(NEW) - 'payload' - 'salt') = (to_jsonb(OLD) - 'payload' - 'salt') THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'trust_events is append-only: % is refused (erasure may only clear payload and salt)', TG_OP;
END;
$$;

CREATE TRIGGER "trust_events_append_only"
  BEFORE UPDATE OR DELETE ON "trust_events"
  FOR EACH ROW EXECUTE FUNCTION "trust_events_append_only"();

-- Anchor proofs: the only change is PENDING -> COMPLETE or FAILED, once,
-- with the identifying columns unchanged. No DELETE.
CREATE FUNCTION "trust_anchor_proofs_transition"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE'
     AND OLD."status" = 'PENDING' AND NEW."status" IN ('COMPLETE', 'FAILED')
     AND NEW."id" = OLD."id"
     AND NEW."treeSize" = OLD."treeSize"
     AND NEW."kind" = OLD."kind"
     AND NEW."endpoint" = OLD."endpoint"
     AND NEW."digest" = OLD."digest"
     AND NEW."submittedAt" = OLD."submittedAt" THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'trust_anchor_proofs allows only PENDING -> COMPLETE or FAILED (% refused)', TG_OP;
END;
$$;

CREATE TRIGGER "trust_anchor_proofs_transition"
  BEFORE UPDATE OR DELETE ON "trust_anchor_proofs"
  FOR EACH ROW EXECUTE FUNCTION "trust_anchor_proofs_transition"();

-- Row triggers do not fire on TRUNCATE; refuse it on every table.
CREATE FUNCTION "trust_refuse_truncate"() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: TRUNCATE is refused', TG_TABLE_NAME;
END;
$$;

CREATE TRIGGER "trust_subjects_no_truncate" BEFORE TRUNCATE ON "trust_subjects"
  FOR EACH STATEMENT EXECUTE FUNCTION "trust_refuse_truncate"();
CREATE TRIGGER "trust_events_no_truncate" BEFORE TRUNCATE ON "trust_events"
  FOR EACH STATEMENT EXECUTE FUNCTION "trust_refuse_truncate"();
CREATE TRIGGER "trust_log_leaves_no_truncate" BEFORE TRUNCATE ON "trust_log_leaves"
  FOR EACH STATEMENT EXECUTE FUNCTION "trust_refuse_truncate"();
CREATE TRIGGER "trust_tree_heads_no_truncate" BEFORE TRUNCATE ON "trust_tree_heads"
  FOR EACH STATEMENT EXECUTE FUNCTION "trust_refuse_truncate"();
CREATE TRIGGER "trust_anchor_proofs_no_truncate" BEFORE TRUNCATE ON "trust_anchor_proofs"
  FOR EACH STATEMENT EXECUTE FUNCTION "trust_refuse_truncate"();
