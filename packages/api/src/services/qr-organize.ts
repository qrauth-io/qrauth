import { Prisma, type PrismaClient } from '@prisma/client';
import {
  MAX_FOLDERS_PER_ORG,
  MAX_TAGS_PER_ORG,
  type BulkMoveInput,
  type BulkTagInput,
  type CreateTagInput,
  type AuditLogAction,
  type UpdateTagInput,
} from '@qrauth/shared';

import { recordAudit, type AuditContext } from './audit.js';

/**
 * Tags and folders of an organization's QR codes (Milestone 1).
 *
 * Every lookup is scoped by organizationId: an id of another organization
 * reads as missing (OrganizeNotFoundError, a 404 at the route), never as
 * forbidden. Creates and renames run under a per-org advisory lock so the
 * per-org caps and the case-insensitive name uniqueness hold under
 * concurrent requests.
 */

type Tx = Prisma.TransactionClient;
type Kind = 'tag' | 'folder';

/**
 * Runs inside the transaction that makes an organise change, after the write
 * (an audit-log entry), so the record and the change commit together. Not
 * called when nothing changed.
 */
export type OrganizeAuditHook = (
  tx: Tx,
  event: { readonly resourceId: string; readonly metadata: Record<string, unknown> },
) => Promise<void>;

/** The hook that records an organise change as `action` on `resource` in the organization. */
export function organizeAudit(
  ctx: AuditContext,
  organizationId: string,
  action: AuditLogAction,
  resource: 'Tag' | 'Folder' | 'QRCode',
): OrganizeAuditHook {
  return (tx, { resourceId, metadata }) => recordAudit(tx, ctx, { organizationId, action, resource, resourceId, metadata });
}

/** At most this many tokens are listed in a bulk action's audit entry (the count is always given). */
export const AUDIT_TOKEN_LIST_MAX = 100;

const auditTokens = (tokens: readonly string[]) => ({
  tokens: tokens.slice(0, AUDIT_TOKEN_LIST_MAX),
  tokenCount: tokens.length,
});

/** The fields that differ, before and after. */
function changed<T extends Record<string, unknown>>(before: T, after: Partial<T>): Record<string, { from: unknown; to: unknown }> {
  const keys = Object.keys(after).filter((k) => after[k] !== undefined && after[k] !== before[k]);
  return Object.fromEntries(keys.map((k) => [k, { from: before[k], to: after[k] }]));
}

export class OrganizeNotFoundError extends Error {
  constructor(readonly resource: 'Tag' | 'Folder', readonly id: string) {
    super(`${resource} "${id}" not found.`);
  }
}

export class OrganizeLimitError extends Error {}
export class OrganizeNameTakenError extends Error {}

export type TagView = { id: string; name: string; color: string; codeCount: number; createdAt: Date };
export type FolderView = { id: string; name: string; codeCount: number; createdAt: Date };

const lockOrg = (tx: Tx, kind: Kind, orgId: string) =>
  tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${`qr-organize:${kind}:${orgId}`}, 0))`;

const tagView = (t: { id: string; name: string; color: string; createdAt: Date; _count: { codes: number } }): TagView => ({
  id: t.id,
  name: t.name,
  color: t.color,
  codeCount: t._count.codes,
  createdAt: t.createdAt,
});

const folderView = (f: { id: string; name: string; createdAt: Date; _count: { codes: number } }): FolderView => ({
  id: f.id,
  name: f.name,
  codeCount: f._count.codes,
  createdAt: f.createdAt,
});

const COUNT = { _count: { select: { codes: true } } } as const;

async function assertNameFree(tx: Tx, kind: Kind, orgId: string, name: string, exceptId?: string) {
  const where = {
    organizationId: orgId,
    name: { equals: name, mode: 'insensitive' as const },
    ...(exceptId ? { id: { not: exceptId } } : {}),
  };
  const clash = kind === 'tag' ? await tx.tag.findFirst({ where }) : await tx.qRFolder.findFirst({ where });
  if (clash) throw new OrganizeNameTakenError(`A ${kind} named "${clash.name}" already exists.`);
}

// ---------------------------------------------------------------------------
// Tags
// ---------------------------------------------------------------------------

export async function listTags(prisma: PrismaClient, orgId: string): Promise<TagView[]> {
  const rows = await prisma.tag.findMany({ where: { organizationId: orgId }, orderBy: { name: 'asc' }, include: COUNT });
  return rows.map(tagView);
}

export function createTag(prisma: PrismaClient, orgId: string, input: CreateTagInput, audit?: OrganizeAuditHook): Promise<TagView> {
  return prisma.$transaction(async (tx) => {
    await lockOrg(tx, 'tag', orgId);
    if ((await tx.tag.count({ where: { organizationId: orgId } })) >= MAX_TAGS_PER_ORG) {
      throw new OrganizeLimitError(`An organization can have at most ${MAX_TAGS_PER_ORG} tags.`);
    }
    await assertNameFree(tx, 'tag', orgId, input.name);
    const tag = await tx.tag.create({ data: { organizationId: orgId, name: input.name, color: input.color }, include: COUNT });
    if (audit) await audit(tx, { resourceId: tag.id, metadata: { name: tag.name, color: tag.color } });
    return tagView(tag);
  });
}

export function updateTag(
  prisma: PrismaClient,
  orgId: string,
  id: string,
  input: UpdateTagInput,
  audit?: OrganizeAuditHook,
): Promise<TagView> {
  return prisma.$transaction(async (tx) => {
    await lockOrg(tx, 'tag', orgId);
    const existing = await tx.tag.findFirst({ where: { id, organizationId: orgId } });
    if (!existing) throw new OrganizeNotFoundError('Tag', id);
    if (input.name !== undefined) await assertNameFree(tx, 'tag', orgId, input.name, id);
    const tag = await tx.tag.update({ where: { id }, data: { name: input.name, color: input.color }, include: COUNT });
    const changes = changed({ name: existing.name, color: existing.color }, { name: input.name, color: input.color });
    if (audit && Object.keys(changes).length > 0) await audit(tx, { resourceId: id, metadata: { changes } });
    return tagView(tag);
  });
}

export function deleteTag(prisma: PrismaClient, orgId: string, id: string, audit?: OrganizeAuditHook): Promise<void> {
  return prisma.$transaction(async (tx) => {
    const tag = await tx.tag.findFirst({ where: { id, organizationId: orgId }, include: COUNT });
    if (!tag) throw new OrganizeNotFoundError('Tag', id);
    const { count } = await tx.tag.deleteMany({ where: { id, organizationId: orgId } });
    if (count === 0) throw new OrganizeNotFoundError('Tag', id);
    if (audit) await audit(tx, { resourceId: id, metadata: { name: tag.name, color: tag.color, codeCount: tag._count.codes } });
  });
}

// ---------------------------------------------------------------------------
// Folders
// ---------------------------------------------------------------------------

export async function listFolders(
  prisma: PrismaClient,
  orgId: string,
): Promise<{ folders: FolderView[]; unfiledCount: number }> {
  const [rows, unfiledCount] = await Promise.all([
    prisma.qRFolder.findMany({ where: { organizationId: orgId }, orderBy: { name: 'asc' }, include: COUNT }),
    prisma.qRCode.count({ where: { organizationId: orgId, folderId: null } }),
  ]);
  return { folders: rows.map(folderView), unfiledCount };
}

export function createFolder(prisma: PrismaClient, orgId: string, name: string, audit?: OrganizeAuditHook): Promise<FolderView> {
  return prisma.$transaction(async (tx) => {
    await lockOrg(tx, 'folder', orgId);
    if ((await tx.qRFolder.count({ where: { organizationId: orgId } })) >= MAX_FOLDERS_PER_ORG) {
      throw new OrganizeLimitError(`An organization can have at most ${MAX_FOLDERS_PER_ORG} folders.`);
    }
    await assertNameFree(tx, 'folder', orgId, name);
    const folder = await tx.qRFolder.create({ data: { organizationId: orgId, name }, include: COUNT });
    if (audit) await audit(tx, { resourceId: folder.id, metadata: { name: folder.name } });
    return folderView(folder);
  });
}

export function renameFolder(
  prisma: PrismaClient,
  orgId: string,
  id: string,
  name: string,
  audit?: OrganizeAuditHook,
): Promise<FolderView> {
  return prisma.$transaction(async (tx) => {
    await lockOrg(tx, 'folder', orgId);
    const existing = await tx.qRFolder.findFirst({ where: { id, organizationId: orgId } });
    if (!existing) throw new OrganizeNotFoundError('Folder', id);
    await assertNameFree(tx, 'folder', orgId, name, id);
    const folder = await tx.qRFolder.update({ where: { id }, data: { name }, include: COUNT });
    const changes = changed({ name: existing.name }, { name });
    if (audit && Object.keys(changes).length > 0) await audit(tx, { resourceId: id, metadata: { changes } });
    return folderView(folder);
  });
}

/** Deletes the folder; its codes become unfiled (ON DELETE SET NULL). */
export function deleteFolder(prisma: PrismaClient, orgId: string, id: string, audit?: OrganizeAuditHook): Promise<void> {
  return prisma.$transaction(async (tx) => {
    const folder = await tx.qRFolder.findFirst({ where: { id, organizationId: orgId }, include: COUNT });
    if (!folder) throw new OrganizeNotFoundError('Folder', id);
    const { count } = await tx.qRFolder.deleteMany({ where: { id, organizationId: orgId } });
    if (count === 0) throw new OrganizeNotFoundError('Folder', id);
    if (audit) await audit(tx, { resourceId: id, metadata: { name: folder.name, unfiledCodes: folder._count.codes } });
  });
}

// ---------------------------------------------------------------------------
// Bulk actions
// ---------------------------------------------------------------------------

export type BulkOrganizeResult = { updated: string[]; notFound: string[] };

/** The org's codes among `tokens`; tokens of other orgs are reported as not found. */
async function resolveCodes(tx: Tx, orgId: string, tokens: string[]) {
  const unique = [...new Set(tokens)];
  const codes = await tx.qRCode.findMany({
    where: { organizationId: orgId, token: { in: unique } },
    select: { id: true, token: true },
  });
  const found = new Set(codes.map((c) => c.token));
  return { codes, result: { updated: [...found], notFound: unique.filter((t) => !found.has(t)) } };
}

type NamedRef = { id: string; name: string };

/** Every id must be a tag of the org, else OrganizeNotFoundError for the first missing one. Returns the tags. */
export async function assertTagsInOrg(db: Tx | PrismaClient, orgId: string, ids: string[]): Promise<NamedRef[]> {
  if (ids.length === 0) return [];
  const rows = await db.tag.findMany({ where: { organizationId: orgId, id: { in: ids } }, select: { id: true, name: true } });
  const known = new Set(rows.map((r) => r.id));
  const missing = ids.find((id) => !known.has(id));
  if (missing) throw new OrganizeNotFoundError('Tag', missing);
  return rows;
}

export async function assertFolderInOrg(db: Tx | PrismaClient, orgId: string, id: string): Promise<NamedRef> {
  const folder = await db.qRFolder.findFirst({ where: { id, organizationId: orgId }, select: { id: true, name: true } });
  if (!folder) throw new OrganizeNotFoundError('Folder', id);
  return folder;
}

/**
 * A tag or folder deleted between the org check and the write fails the
 * foreign key (P2003); report it as the 404 it would have been a moment
 * earlier instead of a 500.
 */
async function deletedMeanwhile<T>(resource: 'Tag' | 'Folder', id: string, write: () => Promise<T>): Promise<T> {
  try {
    return await write();
  } catch (err) {
    if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2003') {
      throw new OrganizeNotFoundError(resource, id);
    }
    throw err;
  }
}

const pick = (tags: readonly NamedRef[], ids: readonly string[]) => tags.filter((t) => ids.includes(t.id));

export function bulkTag(
  prisma: PrismaClient,
  orgId: string,
  input: BulkTagInput,
  audit?: OrganizeAuditHook,
): Promise<BulkOrganizeResult> {
  return deletedMeanwhile('Tag', input.add.join(','), () => prisma.$transaction(async (tx) => {
    const tags = await assertTagsInOrg(tx, orgId, [...input.add, ...input.remove]);
    const { codes, result } = await resolveCodes(tx, orgId, input.tokens);
    const codeIds = codes.map((c) => c.id);
    if (codeIds.length === 0) return result;
    if (input.add.length > 0) {
      await tx.qRCodeTag.createMany({
        data: codeIds.flatMap((qrCodeId) => input.add.map((tagId) => ({ qrCodeId, tagId }))),
        skipDuplicates: true,
      });
    }
    if (input.remove.length > 0) {
      await tx.qRCodeTag.deleteMany({ where: { qrCodeId: { in: codeIds }, tagId: { in: input.remove } } });
    }
    if (audit) {
      await audit(tx, {
        resourceId: 'bulk',
        metadata: {
          ...auditTokens(result.updated),
          notFoundCount: result.notFound.length,
          added: pick(tags, input.add),
          removed: pick(tags, input.remove),
        },
      });
    }
    return result;
  }));
}

export function bulkMove(
  prisma: PrismaClient,
  orgId: string,
  input: BulkMoveInput,
  audit?: OrganizeAuditHook,
): Promise<BulkOrganizeResult> {
  return deletedMeanwhile('Folder', input.folderId ?? '', () => prisma.$transaction(async (tx) => {
    const folder = input.folderId === null ? null : await assertFolderInOrg(tx, orgId, input.folderId);
    const { codes, result } = await resolveCodes(tx, orgId, input.tokens);
    if (codes.length === 0) return result;
    await tx.qRCode.updateMany({
      where: { organizationId: orgId, id: { in: codes.map((c) => c.id) } },
      data: { folderId: input.folderId },
    });
    if (audit) {
      await audit(tx, {
        resourceId: 'bulk',
        metadata: { ...auditTokens(result.updated), notFoundCount: result.notFound.length, folder },
      });
    }
    return result;
  }));
}

/** Maps the unique-violation backstop (two names equal byte for byte) to the friendly error. */
export function isUniqueViolation(err: unknown): boolean {
  return err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002';
}
