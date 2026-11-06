import { Prisma, type PrismaClient } from '@prisma/client';
import { UNFILED_FOLDER, type QrListFilter } from '@qrauth/shared';

import { assertFolderInOrg, assertTagsInOrg } from './qr-organize.js';

/**
 * The QR list query (GET /api/v1/qrcodes): status, content type, folder and
 * tag filters plus free-text search, newest first, paginated.
 *
 * Search `q` matches, case-insensitively:
 *   - the label (substring),
 *   - the destination host of URL codes (substring of the host only, not
 *     path or query; other content types point at their own verify page),
 *   - the token (prefix, case-sensitive like the token itself),
 *   - the content type (exact key, e.g. "vcard").
 *
 * The host is the generated column destinationHost, so it is computed once
 * per write rather than per search. Label and host substring matches have
 * pg_trgm GIN indexes (migration 20261101150000): a leading-wildcard ILIKE
 * cannot use a btree. Within one org the planner usually walks
 * (organizationId, createdAt) and filters, which is cheaper at 10k rows;
 * the trigram indexes take over when a term is selective across orgs.
 *
 * Ids are selected with one raw query (one statement for the OR across
 * columns and the tag EXISTS), then rows are loaded with Prisma in order.
 */

export type QrListQuery = QrListFilter & {
  page: number;
  pageSize: number;
  status?: 'ACTIVE' | 'EXPIRED' | 'REVOKED';
};

/** Escapes LIKE wildcards so user input matches literally. */
export function escapeLike(input: string): string {
  return input.replace(/[\\%_]/g, (c) => `\\${c}`);
}

function searchCondition(q: string): Prisma.Sql {
  const contains = `%${escapeLike(q.toLowerCase())}%`;
  const prefix = `${escapeLike(q)}%`;
  return Prisma.sql`(
    "label" ILIKE ${contains}
    OR ("contentType" = 'url' AND "destinationHost" LIKE ${contains})
    OR "token" LIKE ${prefix}
    OR "contentType" = ${q.toLowerCase()}
  )`;
}

export function buildListWhere(orgId: string, query: QrListQuery): Prisma.Sql {
  const conditions: Prisma.Sql[] = [Prisma.sql`"organizationId" = ${orgId}`];
  if (query.status) conditions.push(Prisma.sql`"status" = ${query.status}::"QRCodeStatus"`);
  if (query.contentType) conditions.push(Prisma.sql`"contentType" = ${query.contentType}`);
  if (query.folderId === UNFILED_FOLDER) conditions.push(Prisma.sql`"folderId" IS NULL`);
  else if (query.folderId) conditions.push(Prisma.sql`"folderId" = ${query.folderId}`);
  if (query.tagIds && query.tagIds.length > 0) {
    conditions.push(Prisma.sql`EXISTS (
      SELECT 1 FROM "qr_code_tags" t
      WHERE t."qrCodeId" = "qr_codes"."id" AND t."tagId" IN (${Prisma.join(query.tagIds)})
    )`);
  }
  if (query.outsidePolicy !== undefined) conditions.push(Prisma.sql`"outsidePolicy" = ${query.outsidePolicy}`);
  if (query.q) conditions.push(searchCondition(query.q));
  return Prisma.join(conditions, ' AND ');
}

const LIST_INCLUDE = {
  _count: { select: { scans: true } },
  folder: { select: { id: true, name: true } },
  tags: {
    select: { tag: { select: { id: true, name: true, color: true } } },
    orderBy: { tag: { name: 'asc' } },
  },
} satisfies Prisma.QRCodeInclude;

/**
 * One page of the org's codes. Tag and folder filter ids must belong to the
 * org (OrganizeNotFoundError otherwise, a 404 at the route).
 */
export async function listQRCodes(prisma: PrismaClient, orgId: string, query: QrListQuery) {
  if (query.tagIds) await assertTagsInOrg(prisma, orgId, query.tagIds);
  if (query.folderId && query.folderId !== UNFILED_FOLDER) await assertFolderInOrg(prisma, orgId, query.folderId);

  const where = buildListWhere(orgId, query);
  const offset = (query.page - 1) * query.pageSize;

  const [idRows, countRows] = await Promise.all([
    prisma.$queryRaw<Array<{ id: string }>>`
      SELECT "id" FROM "qr_codes" WHERE ${where}
      ORDER BY "createdAt" DESC, "id" DESC
      LIMIT ${query.pageSize} OFFSET ${offset}`,
    prisma.$queryRaw<Array<{ total: bigint }>>`SELECT count(*) AS total FROM "qr_codes" WHERE ${where}`,
  ]);

  const ids = idRows.map((r) => r.id);
  const rows = ids.length
    ? await prisma.qRCode.findMany({ where: { id: { in: ids } }, include: LIST_INCLUDE })
    : [];
  const byId = new Map(rows.map((r) => [r.id, r]));
  const data = ids
    .map((id) => byId.get(id))
    .filter((r): r is NonNullable<typeof r> => r !== undefined)
    .map(({ tags, ...row }) => ({ ...row, tags: tags.map((t) => t.tag) }));

  const total = Number(countRows[0]?.total ?? 0);
  return {
    data,
    total,
    page: query.page,
    pageSize: query.pageSize,
    totalPages: Math.ceil(total / query.pageSize),
  };
}
