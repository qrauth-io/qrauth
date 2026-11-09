import { Prisma, type PrismaClient, type QRCode } from '@prisma/client';
import type { FastifyRequest } from 'fastify';

import { stableStringify } from '../lib/crypto.js';
import { withAuditMaintenance } from './audit.js';

/**
 * QR code edit history (Milestone 1): one source of truth for changes to a
 * code's tracked fields. Every write path records its revision in the same
 * transaction as the change, through the helpers below:
 *
 *   create (single, bulk, demo)  → recordCreated
 *   PATCH, restore, revoke       → updateWithRevision
 *   bulk revoke, admin revoke    → revokeWithRevisions
 *
 * The table is append-only (trigger in migrations 20261102120000 and
 * 20261103120000). The
 * Milestone 2 audit log reads QR changes from here, by organization and
 * time (index organizationId, createdAt).
 */

export const TRACKED_FIELDS = ['destinationUrl', 'content', 'style', 'expiresAt', 'scanMode', 'status'] as const;
export type TrackedField = (typeof TRACKED_FIELDS)[number];
export type Snapshot = Record<TrackedField, Prisma.JsonValue>;
export type Changes = Partial<Record<TrackedField, { before: Prisma.JsonValue; after: Prisma.JsonValue }>>;

export type RevisionKind = 'BASELINE' | 'CREATED' | 'UPDATED' | 'RESTORED' | 'REVOKED';
export const REVISION_RETENTION_DAYS = 730;

export type RevisionActor =
  | { type: 'USER'; userId: string }
  | { type: 'API_KEY'; apiKeyId: string }
  | { type: 'SYSTEM'; system: string };

export type RevisionContext = { actor: RevisionActor; requestId: string | null };

type Tx = Prisma.TransactionClient;
type TrackedRow = Pick<QRCode, TrackedField>;

/** Who made a request: the API key when one authenticated it, else the user. */
export function revisionContext(request: FastifyRequest): RevisionContext {
  const user = request.user!;
  const actor: RevisionActor = user.apiKeyId
    ? { type: 'API_KEY', apiKeyId: user.apiKeyId }
    : { type: 'USER', userId: user.id };
  return { actor, requestId: request.id };
}

export function systemContext(system: string, requestId: string | null = null): RevisionContext {
  return { actor: { type: 'SYSTEM', system }, requestId };
}

/** The tracked fields of a row as JSON values (dates as ISO strings). */
export function snapshot(row: TrackedRow): Snapshot {
  return {
    destinationUrl: row.destinationUrl,
    content: row.content ?? null,
    style: row.style ?? null,
    expiresAt: row.expiresAt ? row.expiresAt.toISOString() : null,
    scanMode: row.scanMode,
    status: row.status,
  };
}

/** Fields whose value differs, compared as canonical JSON (key order ignored). */
export function diffSnapshots(before: Snapshot, after: Snapshot): Changes {
  return TRACKED_FIELDS.reduce<Changes>((changes, field) => {
    if (stableStringify(before[field]) === stableStringify(after[field])) return changes;
    return { ...changes, [field]: { before: before[field], after: after[field] } };
  }, {});
}

function actorColumns(actor: RevisionActor) {
  return {
    actorType: actor.type,
    actorUserId: actor.type === 'USER' ? actor.userId : null,
    actorApiKeyId: actor.type === 'API_KEY' ? actor.apiKeyId : null,
    actorSystem: actor.type === 'SYSTEM' ? actor.system : null,
  };
}

/** Next revision number per code. Callers hold the codes' row locks, so numbers cannot collide. */
async function nextRevisions(tx: Tx, qrCodeIds: string[]): Promise<Map<string, number>> {
  const rows = await tx.qRCodeRevision.groupBy({
    by: ['qrCodeId'],
    where: { qrCodeId: { in: qrCodeIds } },
    _max: { revision: true },
  });
  const max = new Map(rows.map((r) => [r.qrCodeId, r._max.revision ?? 0]));
  return new Map(qrCodeIds.map((id) => [id, (max.get(id) ?? 0) + 1]));
}

/** Revision 1 of a new code: every tracked field, before = null. Call in the create transaction. */
export async function recordCreated(tx: Tx, row: QRCode, ctx: RevisionContext): Promise<void> {
  const after = snapshot(row);
  const changes = TRACKED_FIELDS.reduce<Changes>((acc, f) => ({ ...acc, [f]: { before: null, after: after[f] } }), {});
  await tx.qRCodeRevision.create({
    data: {
      qrCodeId: row.id,
      organizationId: row.organizationId,
      revision: 1,
      kind: 'CREATED',
      changes: changes as Prisma.InputJsonValue,
      requestId: ctx.requestId,
      ...actorColumns(ctx.actor),
    },
  });
}

async function lockCodes(tx: Tx, ids: string[]): Promise<void> {
  if (ids.length === 0) return;
  await tx.$queryRaw`SELECT "id" FROM "qr_codes" WHERE "id" IN (${Prisma.join(ids)}) ORDER BY "id" FOR UPDATE`;
}

/**
 * Locks the code, reads its tracked fields, runs `write`, and records a
 * revision of what changed (nothing when no tracked field changed, e.g. a
 * label-only edit). Run inside the transaction that makes the change.
 */
export async function updateWithRevision<T extends QRCode>(
  tx: Tx,
  qrCodeId: string,
  ctx: RevisionContext,
  kind: Exclude<RevisionKind, 'BASELINE' | 'CREATED'>,
  write: (tx: Tx) => Promise<T>,
  restoredFrom?: number,
  /** Checks the locked row before writing; throw to abort (e.g. it changed since the caller read it). */
  assertBefore?: (before: QRCode) => void,
): Promise<T> {
  await lockCodes(tx, [qrCodeId]);
  const before = await tx.qRCode.findUnique({ where: { id: qrCodeId } });
  if (!before) throw new Error(`QR code ${qrCodeId} not found`);
  assertBefore?.(before);
  const after = await write(tx);
  const changes = diffSnapshots(snapshot(before), snapshot(after));
  if (Object.keys(changes).length === 0) return after;
  const revision = (await nextRevisions(tx, [qrCodeId])).get(qrCodeId)!;
  await tx.qRCodeRevision.create({
    data: {
      qrCodeId,
      organizationId: after.organizationId,
      revision,
      kind,
      changes: changes as Prisma.InputJsonValue,
      requestId: ctx.requestId,
      restoredFrom: restoredFrom ?? null,
      ...actorColumns(ctx.actor),
    },
  });
  return after;
}

/**
 * Revokes the org's codes among `tokens` that are not revoked yet, with one
 * REVOKED revision each, in one transaction. Returns the revoked tokens.
 */
export async function revokeWithRevisions(
  prisma: PrismaClient,
  organizationId: string,
  tokens: string[],
  ctx: RevisionContext,
): Promise<string[]> {
  if (tokens.length === 0) return [];
  return prisma.$transaction(async (tx) => {
    const candidates = await tx.qRCode.findMany({
      where: { organizationId, token: { in: tokens } },
      select: { id: true },
    });
    await lockCodes(tx, candidates.map((c) => c.id));
    // Re-read under the lock: a parallel revoke may have won.
    const rows = await tx.qRCode.findMany({
      where: { organizationId, token: { in: tokens }, status: { not: 'REVOKED' } },
      select: { id: true, token: true, status: true },
    });
    if (rows.length === 0) return [];
    const ids = rows.map((r) => r.id);
    await tx.qRCode.updateMany({ where: { id: { in: ids } }, data: { status: 'REVOKED', revokedAt: new Date() } });
    const next = await nextRevisions(tx, ids);
    await tx.qRCodeRevision.createMany({
      data: rows.map((r) => ({
        qrCodeId: r.id,
        organizationId,
        revision: next.get(r.id)!,
        kind: 'REVOKED',
        changes: { status: { before: r.status, after: 'REVOKED' } },
        requestId: ctx.requestId,
        ...actorColumns(ctx.actor),
      })),
    });
    return rows.map((r) => r.token);
  });
}

/**
 * Deletes revisions past retention, by the database clock (the trigger
 * checks the same clock). Each code's latest revision is kept whatever its
 * age, so numbering never restarts and the current state stays on record.
 */
export async function purgeExpiredRevisions(db: PrismaClient): Promise<number> {
  // The append-only trigger allows age-based deletes only under the retention flag.
  return withAuditMaintenance(db, 'retention', (tx) => tx.$executeRaw`
    DELETE FROM "qr_code_revisions" r
    WHERE r."createdAt" < now() - make_interval(days => ${REVISION_RETENTION_DAYS}::int)
      AND r."revision" < (SELECT max(l."revision") FROM "qr_code_revisions" l WHERE l."qrCodeId" = r."qrCodeId")`);
}

/** Thrown inside a restore transaction when the locked row is not what the restore was decided on. */
export class RestoreConflictError extends Error {
  constructor(readonly code: 'revoked' | 'concurrent-change', message: string) {
    super(message);
  }
}

// ---------------------------------------------------------------------------
// Reading history
// ---------------------------------------------------------------------------

export type RevisionActorView =
  | { type: 'USER'; id: string; name: string | null; email: string | null }
  | { type: 'API_KEY'; id: string; label: string | null; prefix: string | null }
  | { type: 'SYSTEM'; id: string };

export type RevisionView = {
  revision: number;
  kind: RevisionKind;
  createdAt: Date;
  changes: Changes;
  actor: RevisionActorView;
  requestId: string | null;
  restoredFrom: number | null;
};

/**
 * One page of a code's history, newest first, with actor names. Users and
 * keys that no longer exist read as name/label null; API keys are looked
 * up within the code's organization only.
 */
export async function listRevisions(
  prisma: PrismaClient,
  code: { id: string; organizationId: string },
  page: number,
  pageSize: number,
): Promise<{ data: RevisionView[]; total: number }> {
  const [rows, total] = await Promise.all([
    prisma.qRCodeRevision.findMany({
      where: { qrCodeId: code.id },
      orderBy: { revision: 'desc' },
      skip: (page - 1) * pageSize,
      take: pageSize,
    }),
    prisma.qRCodeRevision.count({ where: { qrCodeId: code.id } }),
  ]);
  const userIds = [...new Set(rows.flatMap((r) => (r.actorUserId ? [r.actorUserId] : [])))];
  const keyIds = [...new Set(rows.flatMap((r) => (r.actorApiKeyId ? [r.actorApiKeyId] : [])))];
  const [users, keys] = await Promise.all([
    userIds.length ? prisma.user.findMany({ where: { id: { in: userIds } }, select: { id: true, name: true, email: true } }) : [],
    keyIds.length
      ? prisma.apiKey.findMany({ where: { id: { in: keyIds }, organizationId: code.organizationId }, select: { id: true, label: true, prefix: true } })
      : [],
  ]);
  const userById = new Map(users.map((u) => [u.id, u]));
  const keyById = new Map(keys.map((k) => [k.id, k]));

  const actorOf = (r: (typeof rows)[number]): RevisionActorView => {
    if (r.actorType === 'USER' && r.actorUserId) {
      const u = userById.get(r.actorUserId);
      return { type: 'USER', id: r.actorUserId, name: u?.name ?? null, email: u?.email ?? null };
    }
    if (r.actorType === 'API_KEY' && r.actorApiKeyId) {
      const k = keyById.get(r.actorApiKeyId);
      return { type: 'API_KEY', id: r.actorApiKeyId, label: k?.label ?? null, prefix: k?.prefix ?? null };
    }
    return { type: 'SYSTEM', id: r.actorSystem ?? 'system' };
  };

  return {
    total,
    data: rows.map((r) => ({
      revision: r.revision,
      kind: r.kind as RevisionKind,
      createdAt: r.createdAt,
      changes: r.changes as Changes,
      actor: actorOf(r),
      requestId: r.requestId,
      restoredFrom: r.restoredFrom,
    })),
  };
}

export class RevisionNotFoundError extends Error {}
export class RevisionValueUnavailableError extends Error {}

/**
 * The value `field` had right after `revision`: the `after` of the latest
 * revision at or before it that changed the field. Throws
 * RevisionNotFoundError when the revision does not exist (or was removed by
 * retention), RevisionValueUnavailableError when no kept revision says.
 */
export async function valueAtRevision(
  prisma: PrismaClient,
  qrCodeId: string,
  revision: number,
  field: TrackedField,
): Promise<Prisma.JsonValue> {
  const rows = await prisma.qRCodeRevision.findMany({
    where: { qrCodeId, revision: { lte: revision } },
    orderBy: { revision: 'desc' },
    select: { revision: true, changes: true },
  });
  if (rows[0]?.revision !== revision) throw new RevisionNotFoundError(`Revision ${revision} not found.`);
  for (const row of rows) {
    const change = (row.changes as Changes)[field];
    if (change) return change.after;
  }
  throw new RevisionValueUnavailableError(`The ${field} at revision ${revision} is no longer in the history.`);
}
