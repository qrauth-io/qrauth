import type { PrismaClient } from '@prisma/client';
import { BULK_EXPORT_MAX_CODES, UNFILED_FOLDER, type BulkExportRequest } from '@qrauth/shared';

import type { StoredImportResult } from './bulk-rows.js';
import { loadJobFor, type BulkActor } from './bulk-jobs.js';
import { assertFolderInOrg, assertTagsInOrg } from './qr-organize.js';
import { buildListWhere } from './qr-search.js';

/**
 * Which codes a ZIP export contains (ADR-0008 D9): listed tokens, the codes
 * an import job created, or the QR list's filters. Always within the
 * caller's organization; at most BULK_EXPORT_MAX_CODES.
 */

/** The selection was refused (422 at the route, with this code). */
export class ExportSelectionError extends Error {
  constructor(
    readonly code: 'export-empty' | 'export-too-many' | 'export-import-not-found',
    message: string,
  ) {
    super(message);
    this.name = 'ExportSelectionError';
  }
}

export interface ExportJobInput {
  codeIds: string[];
  formats: BulkExportRequest['formats'];
  png: BulkExportRequest['png'] | null;
}

const TOO_MANY = `An export can contain at most ${BULK_EXPORT_MAX_CODES.toLocaleString('en')} codes; narrow the selection.`;

/** Ids of the organization's codes with these tokens, in the tokens' order (other tokens are dropped). */
async function idsInOrder(prisma: PrismaClient, orgId: string, tokens: readonly string[]): Promise<string[]> {
  const unique = [...new Set(tokens)];
  const rows = await prisma.qRCode.findMany({ where: { organizationId: orgId, token: { in: unique } }, select: { id: true, token: true } });
  const byToken = new Map(rows.map((r) => [r.token, r.id]));
  return unique.flatMap((t) => byToken.get(t) ?? []);
}

/** Code ids of the selection: tokens in the order given, an import in file order, a filter newest first. */
export async function resolveExportSelection(
  prisma: PrismaClient,
  orgId: string,
  actor: BulkActor,
  selection: BulkExportRequest['selection'],
): Promise<string[]> {
  let ids: string[];
  if ('tokens' in selection) {
    ids = await idsInOrder(prisma, orgId, selection.tokens);
  } else if ('importJobId' in selection) {
    const job = await loadJobFor(prisma, selection.importJobId, orgId, actor, 'IMPORT');
    if (!job) throw new ExportSelectionError('export-import-not-found', 'Import job not found.');
    const results = [...((job.results ?? []) as unknown as StoredImportResult[])].sort((a, b) => a.row - b.row);
    ids = await idsInOrder(prisma, orgId, results.flatMap((r) => (r.token ? [r.token] : [])));
  } else {
    const filter = selection.filter;
    if (filter.tagIds) await assertTagsInOrg(prisma, orgId, filter.tagIds);
    if (filter.folderId && filter.folderId !== UNFILED_FOLDER) await assertFolderInOrg(prisma, orgId, filter.folderId);
    const where = buildListWhere(orgId, { ...filter, page: 1, pageSize: BULK_EXPORT_MAX_CODES });
    const rows = await prisma.$queryRaw<Array<{ id: string }>>`
      SELECT "id" FROM "qr_codes" WHERE ${where}
      ORDER BY "createdAt" DESC, "id" DESC
      LIMIT ${BULK_EXPORT_MAX_CODES + 1}`;
    ids = rows.map((r) => r.id);
  }
  if (ids.length === 0) throw new ExportSelectionError('export-empty', 'No QR codes match the selection.');
  if (ids.length > BULK_EXPORT_MAX_CODES) throw new ExportSelectionError('export-too-many', TOO_MANY);
  return ids;
}
