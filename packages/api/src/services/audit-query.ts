import type { AuditLog, Prisma, PrismaClient, QRCodeRevision } from '@prisma/client';
import {
  AUDIT_ACTION_LABELS,
  QR_REVISION_ACTIONS,
  type AuditActorType,
  type AuditActorView,
  type AuditEntry,
  type AuditPage,
} from '@qrauth/shared';

import { csvLine } from '../lib/csv.js';

/**
 * The org-facing audit log (ADR-0008 D2): audit-table rows and QR code
 * revisions of one organization, merged newest first. Each source is read
 * by keyset over (createdAt, entry id), so a page costs two indexed range
 * reads whatever the depth. Entry ids carry their source prefix ("log:",
 * "qr:"), which also orders entries of the same millisecond.
 */

export const AUDIT_PAGE_MAX = 100;
export const AUDIT_PAGE_DEFAULT = 50;
export const AUDIT_CSV_BATCH = 500;
/** Most entries one CSV export may hold; a larger range is refused before streaming. */
export const AUDIT_CSV_MAX_ROWS = 100_000;

const LOG = 'log:';
const QR = 'qr:';

export interface AuditFilters {
  actorId?: string;
  actorType?: AuditActorType;
  action?: string;
  resourceType?: string;
  resourceId?: string;
  from?: Date;
  to?: Date;
}

interface Cursor {
  t: Date;
  id: string;
}

export class InvalidCursorError extends Error {}

export function encodeCursor(c: Cursor): string {
  return Buffer.from(JSON.stringify({ t: c.t.toISOString(), id: c.id })).toString('base64url');
}

export function decodeCursor(raw: string): Cursor {
  try {
    const parsed = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8')) as { t?: unknown; id?: unknown };
    const t = typeof parsed.t === 'string' ? new Date(parsed.t) : null;
    if (!t || Number.isNaN(t.getTime()) || typeof parsed.id !== 'string') throw new Error('shape');
    if (!parsed.id.startsWith(LOG) && !parsed.id.startsWith(QR)) throw new Error('source');
    return { t, id: parsed.id };
  } catch {
    throw new InvalidCursorError('Invalid cursor.');
  }
}

/** Revision kind for a qr.* action, e.g. qr.updated → UPDATED. */
function revisionKindOf(action: string): string | null {
  return Object.prototype.hasOwnProperty.call(QR_REVISION_ACTIONS, action) ? action.slice(3).toUpperCase() : null;
}

/**
 * Keyset condition for one source: strictly older than the cursor. At the
 * cursor's millisecond, rows of the same source compare by id; the other
 * source is wholly before or after it by prefix order ("log:" < "qr:").
 */
function beforeCursor(cursor: Cursor | undefined, prefix: string): Prisma.AuditLogWhereInput & Prisma.QRCodeRevisionWhereInput {
  if (!cursor) return {};
  const sameMs: Prisma.AuditLogWhereInput & Prisma.QRCodeRevisionWhereInput | null = cursor.id.startsWith(prefix)
    ? { createdAt: cursor.t, id: { lt: cursor.id.slice(prefix.length) } }
    : prefix < cursor.id
      ? { createdAt: cursor.t }
      : null;
  // The upper bound outside the OR lets Postgres bound the index range scan
  // on (organizationId, createdAt) instead of filtering every older row.
  return { createdAt: { lte: cursor.t }, OR: [{ createdAt: { lt: cursor.t } }, ...(sameMs ? [sameMs] : [])] };
}

function dateRange(filters: AuditFilters): { createdAt?: Prisma.DateTimeFilter } {
  if (!filters.from && !filters.to) return {};
  return { createdAt: { ...(filters.from ? { gte: filters.from } : {}), ...(filters.to ? { lte: filters.to } : {}) } };
}

/** Where clause for the audit table, or null when the filters exclude it. */
function logWhere(orgId: string, f: AuditFilters, cursor?: Cursor): Prisma.AuditLogWhereInput | null {
  if (f.action && revisionKindOf(f.action)) return null;
  return {
    AND: [
      { organizationId: orgId },
      f.actorType ? { actorType: f.actorType } : {},
      // Staff are never matched by id: their identity is not shown to the organization.
      f.actorId ? { actorId: f.actorId, actorType: { not: 'SUPERADMIN' } } : {},
      f.action ? { action: f.action } : {},
      f.resourceType ? { resource: f.resourceType } : {},
      f.resourceId ? { resourceId: f.resourceId } : {},
      dateRange(f),
      beforeCursor(cursor, LOG),
    ],
  };
}

/** Where clause for QR revisions, or null when the filters exclude them. */
function revisionWhere(orgId: string, f: AuditFilters, cursor?: Cursor): Prisma.QRCodeRevisionWhereInput | null {
  if (f.actorType === 'SUPERADMIN') return null;
  if (f.resourceType && f.resourceType !== 'QRCode') return null;
  const kind = f.action ? revisionKindOf(f.action) : undefined;
  if (kind === null) return null;
  return {
    AND: [
      { organizationId: orgId },
      f.actorType ? { actorType: f.actorType } : {},
      f.actorId ? { OR: [{ actorUserId: f.actorId }, { actorApiKeyId: f.actorId }, { actorSystem: f.actorId }] } : {},
      kind ? { kind } : {},
      f.resourceId ? { qrCodeId: f.resourceId } : {},
      dateRange(f),
      beforeCursor(cursor, QR),
    ],
  };
}

type Row =
  | { source: 'audit'; key: string; createdAt: Date; row: AuditLog }
  | { source: 'qr_revision'; key: string; createdAt: Date; row: QRCodeRevision };

/** Newest first; entries of the same millisecond by prefixed id, descending. */
function newestFirst(a: Row, b: Row): number {
  const dt = b.createdAt.getTime() - a.createdAt.getTime();
  if (dt !== 0) return dt;
  return a.key < b.key ? 1 : a.key > b.key ? -1 : 0;
}

const ORDER = [{ createdAt: 'desc' as const }, { id: 'desc' as const }];

/** One page of the merged log. */
export async function listAuditEntries(
  prisma: PrismaClient,
  organizationId: string,
  filters: AuditFilters,
  opts: { limit: number; cursor?: string },
): Promise<AuditPage> {
  const cursor = opts.cursor ? decodeCursor(opts.cursor) : undefined;
  const take = opts.limit + 1;
  const lw = logWhere(organizationId, filters, cursor);
  const rw = revisionWhere(organizationId, filters, cursor);
  const [logs, revisions] = await Promise.all([
    lw ? prisma.auditLog.findMany({ where: lw, orderBy: ORDER, take }) : [],
    rw ? prisma.qRCodeRevision.findMany({ where: rw, orderBy: ORDER, take }) : [],
  ]);
  const merged: Row[] = [
    ...logs.map((row): Row => ({ source: 'audit', key: LOG + row.id, createdAt: row.createdAt, row })),
    ...revisions.map((row): Row => ({ source: 'qr_revision', key: QR + row.id, createdAt: row.createdAt, row })),
  ].sort(newestFirst);
  const page = merged.slice(0, opts.limit);
  const last = page[page.length - 1];
  return {
    data: await toEntries(prisma, organizationId, page),
    nextCursor: merged.length > opts.limit && last ? encodeCursor({ t: last.createdAt, id: last.key }) : null,
  };
}

/** How many entries match the filters, across both sources (for the export cap). */
export async function countAuditEntries(prisma: PrismaClient, organizationId: string, filters: AuditFilters): Promise<number> {
  const lw = logWhere(organizationId, filters);
  const rw = revisionWhere(organizationId, filters);
  const [logs, revisions] = await Promise.all([
    lw ? prisma.auditLog.count({ where: lw }) : 0,
    rw ? prisma.qRCodeRevision.count({ where: rw }) : 0,
  ]);
  return logs + revisions;
}

// ---------------------------------------------------------------------------
// Presentation
// ---------------------------------------------------------------------------

const SUPERADMIN_VIEW: AuditActorView = { type: 'SUPERADMIN', id: null, name: 'QRAuth' };

async function toEntries(prisma: PrismaClient, organizationId: string, rows: Row[]): Promise<AuditEntry[]> {
  const userIds = new Set<string>();
  const keyIds = new Set<string>();
  const codeIds = new Set<string>();
  for (const r of rows) {
    if (r.source === 'audit') {
      if (r.row.actorType === 'USER' && r.row.actorId) userIds.add(r.row.actorId);
      if (r.row.actorType === 'API_KEY' && r.row.actorId) keyIds.add(r.row.actorId);
      if (r.row.resource === 'QRCode') codeIds.add(r.row.resourceId);
    } else {
      if (r.row.actorUserId) userIds.add(r.row.actorUserId);
      if (r.row.actorApiKeyId) keyIds.add(r.row.actorApiKeyId);
      codeIds.add(r.row.qrCodeId);
    }
  }
  // Names are looked up within the organization only: a user must be a
  // current or former actor here, a key and a code must belong to it.
  const [users, keys, codes] = await Promise.all([
    userIds.size ? prisma.user.findMany({ where: { id: { in: [...userIds] } }, select: { id: true, name: true, email: true } }) : [],
    keyIds.size
      ? prisma.apiKey.findMany({ where: { id: { in: [...keyIds] }, organizationId }, select: { id: true, label: true, prefix: true } })
      : [],
    codeIds.size
      ? prisma.qRCode.findMany({ where: { id: { in: [...codeIds] }, organizationId }, select: { id: true, token: true } })
      : [],
  ]);
  const userById = new Map(users.map((u) => [u.id, u]));
  const keyById = new Map(keys.map((k) => [k.id, k]));
  const tokenById = new Map(codes.map((c) => [c.id, c.token]));

  const userView = (id: string): AuditActorView => {
    const u = userById.get(id);
    return { type: 'USER', id, name: u?.name ?? null, email: u?.email ?? null };
  };
  const keyView = (id: string): AuditActorView => {
    const k = keyById.get(id);
    return { type: 'API_KEY', id, label: k?.label ?? null, prefix: k?.prefix ?? null };
  };

  return rows.map((r): AuditEntry => {
    if (r.source === 'audit') {
      const row = r.row;
      const isStaff = row.actorType === 'SUPERADMIN';
      const actor: AuditActorView = isStaff
        ? SUPERADMIN_VIEW
        : row.actorType === 'API_KEY'
          ? keyView(row.actorId ?? '')
          : row.actorType === 'SYSTEM'
            ? { type: 'SYSTEM', id: row.actorId ?? 'system' }
            : userView(row.actorId ?? row.userId ?? '');
      return {
        id: r.key,
        source: 'audit',
        action: row.action,
        label: AUDIT_ACTION_LABELS[row.action as keyof typeof AUDIT_ACTION_LABELS] ?? row.action,
        resourceType: row.resource,
        resourceId: row.resourceId,
        resourceName: row.resource === 'QRCode' ? tokenById.get(row.resourceId) ?? null : null,
        actor,
        createdAt: row.createdAt.toISOString(),
        requestId: row.requestId,
        // A staff member's address and browser are not the organization's data.
        ipAddress: isStaff ? null : row.ipAddress,
        userAgent: isStaff ? null : row.userAgent,
        metadata: (row.metadata as Record<string, unknown> | null) ?? null,
        changes: null,
      };
    }
    const row = r.row;
    const action = `qr.${row.kind.toLowerCase()}`;
    const actor: AuditActorView =
      row.actorType === 'USER' && row.actorUserId
        ? userView(row.actorUserId)
        : row.actorType === 'API_KEY' && row.actorApiKeyId
          ? keyView(row.actorApiKeyId)
          : { type: 'SYSTEM', id: row.actorSystem ?? 'system' };
    return {
      id: r.key,
      source: 'qr_revision',
      action,
      label: AUDIT_ACTION_LABELS[action as keyof typeof AUDIT_ACTION_LABELS] ?? action,
      resourceType: 'QRCode',
      resourceId: row.qrCodeId,
      resourceName: tokenById.get(row.qrCodeId) ?? null,
      actor,
      createdAt: row.createdAt.toISOString(),
      requestId: row.requestId,
      ipAddress: null,
      userAgent: null,
      metadata: { revision: row.revision, ...(row.restoredFrom !== null ? { restoredFrom: row.restoredFrom } : {}) },
      changes: row.changes as AuditEntry['changes'],
    };
  });
}

// ---------------------------------------------------------------------------
// CSV export
// ---------------------------------------------------------------------------

export const AUDIT_CSV_COLUMNS = [
  'time',
  'action',
  'description',
  'actor_type',
  'actor_id',
  'actor',
  'resource_type',
  'resource_id',
  'resource_name',
  'request_id',
  'ip_address',
  'user_agent',
  'details',
] as const;

function actorName(a: AuditActorView): string | null {
  switch (a.type) {
    case 'USER':
      return a.email ?? a.name;
    case 'API_KEY':
      return a.label ?? a.prefix;
    case 'SYSTEM':
      return a.id;
    case 'SUPERADMIN':
      return a.name;
  }
}

/** Header, then every matching entry, newest first, read in keyset batches. */
export async function* auditCsvLines(
  prisma: PrismaClient,
  organizationId: string,
  filters: AuditFilters,
  batchSize = AUDIT_CSV_BATCH,
): AsyncGenerator<string> {
  yield csvLine(AUDIT_CSV_COLUMNS);
  let cursor: string | undefined;
  do {
    const page = await listAuditEntries(prisma, organizationId, filters, { limit: batchSize, cursor });
    for (const e of page.data) {
      const details = e.changes ?? e.metadata;
      yield csvLine([
        e.createdAt,
        e.action,
        e.label,
        e.actor.type,
        e.actor.id,
        actorName(e.actor),
        e.resourceType,
        e.resourceId,
        e.resourceName,
        e.requestId,
        e.ipAddress,
        e.userAgent,
        details ? JSON.stringify(details) : null,
      ]);
    }
    cursor = page.nextCursor ?? undefined;
  } while (cursor);
}
