import { Prisma, type PrismaClient } from '@prisma/client';

import { PostgresAssetStore, type AssetStore } from './asset-store.js';
import type { NormalisedLogo } from './logo-normalise.js';

/**
 * The organization logo library (ADR-0005 D6): normalised PNGs stored as
 * ContentAsset rows of kind LOGO. Every read and write is scoped to one
 * organization; an id from another organization behaves as a missing one.
 */

/** Logos per organization (D6). Uploading the next one is 409. */
export const LOGO_MAX_PER_ORG = 50;
/** Longest stored display name. */
export const LOGO_NAME_MAX = 100;
export const DEFAULT_LOGO_NAME = 'logo.png';

export interface LogoView {
  readonly id: string;
  readonly name: string;
  readonly width: number;
  readonly height: number;
  readonly sizeBytes: number;
  readonly sha256: string;
  readonly createdAt: string;
}

export type CreateLogoResult =
  | { readonly outcome: 'created'; readonly logo: LogoView }
  | { readonly outcome: 'limit_reached'; readonly limit: number };

export type DeleteLogoResult =
  | { readonly outcome: 'deleted'; readonly sizeBytes: number }
  | { readonly outcome: 'not_found' }
  | { readonly outcome: 'in_use'; readonly count: number };

type Db = Pick<PrismaClient, 'contentAsset' | 'contentAssetBlob' | 'qRCode' | '$transaction'>;
/** A transaction that holds the logo row's lock (lockLogo). */
export type LogoTx = Prisma.TransactionClient;

/**
 * Runs inside the transaction that stores or deletes a logo, after the
 * write (an audit-log entry), so the record and the change commit together.
 */
export type LogoAuditHook = (tx: LogoTx, event: { readonly assetId: string; readonly sizeBytes: number }) => Promise<void>;
type BlobDb = Pick<PrismaClient, 'contentAssetBlob'>;

const LOGO_SELECT = {
  id: true,
  filename: true,
  width: true,
  height: true,
  sizeBytes: true,
  sha256: true,
  createdAt: true,
} as const;

type LogoRow = Prisma.ContentAssetGetPayload<{ select: typeof LOGO_SELECT }>;

function toView(row: LogoRow): LogoView {
  return {
    id: row.id,
    name: row.filename,
    width: row.width ?? 0,
    height: row.height ?? 0,
    sizeBytes: row.sizeBytes,
    sha256: row.sha256 ?? '',
    createdAt: row.createdAt.toISOString(),
  };
}

/**
 * Characters removed from display names: C0 and C1 controls, the Arabic
 * letter mark (U+061C), zero-width space, non-joiner and joiner
 * (U+200B-U+200D), the bidi marks, embeddings, overrides and isolates
 * (U+200E-U+200F, U+202A-U+202E, U+2066-U+2069), the line and paragraph
 * separators (U+2028-U+2029) and the byte-order mark (U+FEFF).
 */
const HIDDEN_NAME_CHARACTERS = /[\u0000-\u001F\u007F-\u009F\u061C\u200B-\u200F\u2028-\u202E\u2066-\u2069\uFEFF]/gu;

/** A display name without control, invisible or bidi characters, trimmed and bounded; the default when empty. */
export function cleanLogoName(raw: string | undefined): string {
  const cleaned = (raw ?? '')
    .replace(HIDDEN_NAME_CHARACTERS, '')
    .trim()
    .slice(0, LOGO_NAME_MAX)
    .trim();
  return cleaned || DEFAULT_LOGO_NAME;
}

/** The style names a logo that is not (or no longer) in the organization's library. */
export class LogoNotFoundError extends Error {
  constructor(readonly assetId: string) {
    super(`Logo ${assetId} is not in the organization's library`);
    this.name = 'LogoNotFoundError';
  }
}

/**
 * Locks the organization's logo row (SELECT ... FOR UPDATE) for the rest of
 * the transaction and returns its size; null when there is no such logo. Deleting a logo and
 * saving a style that draws it both take this lock first, so the reference
 * count a delete reads cannot miss a style written in parallel, and a style
 * write cannot name a logo deleted in parallel.
 */
async function lockLogo(tx: LogoTx, organizationId: string, assetId: string): Promise<{ sizeBytes: number } | null> {
  const rows = await tx.$queryRaw<{ id: string; sizeBytes: number }[]>`
    SELECT "id", "sizeBytes" FROM "content_assets"
    WHERE "id" = ${assetId} AND "organizationId" = ${organizationId} AND "kind" = 'LOGO'
    FOR UPDATE`;
  return rows[0] ? { sizeBytes: Number(rows[0].sizeBytes) } : null;
}

/** Prisma surfaces a serialization conflict (Postgres 40001) as P2034. */
function isSerializationFailure(err: unknown): boolean {
  return err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2034';
}

/** QR codes of the organization whose style draws this logo (a JSON path filter on style.logo.assetId). */
function referencingCodes(organizationId: string, assetId: string): Prisma.QRCodeWhereInput {
  return { organizationId, style: { path: ['logo', 'assetId'], equals: assetId } };
}

export class LogoLibrary {
  constructor(
    private readonly db: Db,
    private readonly storeFor: (db: BlobDb) => AssetStore = (blobDb) => new PostgresAssetStore(blobDb),
  ) {}

  /**
   * Stores a normalised logo. The cap is checked inside a serializable
   * transaction, so concurrent uploads cannot pass it together. `audit`
   * runs in that transaction once the logo is stored.
   */
  async create(organizationId: string, logo: NormalisedLogo, name: string, audit?: LogoAuditHook): Promise<CreateLogoResult> {
    const attempt = () =>
      this.db.$transaction(
        async (tx) => {
          const count = await tx.contentAsset.count({ where: { organizationId, kind: 'LOGO' } });
          if (count >= LOGO_MAX_PER_ORG) return null;
          const row = await tx.contentAsset.create({
            data: {
              organizationId,
              kind: 'LOGO',
              filename: name,
              mimeType: 'image/png',
              sizeBytes: logo.png.length,
              sha256: logo.sha256,
              width: logo.width,
              height: logo.height,
              storagePath: 'pending',
            },
            select: { id: true },
          });
          const storagePath = await this.storeFor(tx).put(row.id, logo.png);
          const stored = await tx.contentAsset.update({ where: { id: row.id }, data: { storagePath }, select: LOGO_SELECT });
          if (audit) await audit(tx, { assetId: stored.id, sizeBytes: stored.sizeBytes });
          return stored;
        },
        { isolationLevel: 'Serializable' },
      );

    let created: LogoRow | null;
    try {
      created = await attempt();
    } catch (first: unknown) {
      if (!isSerializationFailure(first)) throw first;
      try {
        created = await attempt();
      } catch (second: unknown) {
        if (!isSerializationFailure(second)) throw second;
        return { outcome: 'limit_reached', limit: LOGO_MAX_PER_ORG };
      }
    }
    if (!created) return { outcome: 'limit_reached', limit: LOGO_MAX_PER_ORG };
    return { outcome: 'created', logo: toView(created) };
  }

  /** The organization's logos, newest first. */
  async list(organizationId: string): Promise<LogoView[]> {
    const rows = await this.db.contentAsset.findMany({
      where: { organizationId, kind: 'LOGO' },
      orderBy: { createdAt: 'desc' },
      take: LOGO_MAX_PER_ORG,
      select: LOGO_SELECT,
    });
    return rows.map(toView);
  }

  /** True when the organization has a logo with this id. */
  async exists(organizationId: string, assetId: string): Promise<boolean> {
    const row = await this.db.contentAsset.findFirst({
      where: { id: assetId, organizationId, kind: 'LOGO' },
      select: { id: true },
    });
    return row !== null;
  }

  /** The logo's PNG bytes, or null when the organization has no logo with this id. */
  async bytes(organizationId: string, assetId: string): Promise<Uint8Array | null> {
    if (!(await this.exists(organizationId, assetId))) return null;
    return this.storeFor(this.db).get(assetId);
  }

  /**
   * Deletes a logo unless a code of the organization draws it: then
   * `in_use` with the number of codes, and nothing changes (D6). The count
   * and the delete run in one transaction holding the logo row's lock, the
   * lock a style write takes too (writeWithLogo). `audit` runs in that
   * transaction once the logo is deleted.
   */
  async delete(organizationId: string, assetId: string, audit?: LogoAuditHook): Promise<DeleteLogoResult> {
    return this.db.$transaction(async (tx) => {
      const locked = await lockLogo(tx, organizationId, assetId);
      if (!locked) return { outcome: 'not_found' } as const;
      const count = await tx.qRCode.count({ where: referencingCodes(organizationId, assetId) });
      if (count > 0) return { outcome: 'in_use', count } as const;
      // Only the asset row is deleted: its content_asset_blobs row goes with
      // it (ON DELETE CASCADE), in the same transaction.
      await tx.contentAsset.deleteMany({ where: { id: assetId, organizationId, kind: 'LOGO' } });
      if (audit) await audit(tx, { assetId, sizeBytes: locked.sizeBytes });
      return { outcome: 'deleted', sizeBytes: locked.sizeBytes } as const;
    });
  }

  /**
   * Runs `write` (the write of a style that draws the logo) in a transaction
   * holding the logo row's lock, after re-checking that the logo is still in
   * the library. Throws LogoNotFoundError, writing nothing, when it is not.
   * Keep slow work (the decode check) outside: the lock blocks deletion.
   */
  async writeWithLogo<T>(organizationId: string, assetId: string, write: (tx: LogoTx) => Promise<T>): Promise<T> {
    return this.db.$transaction(async (tx) => {
      if (!(await lockLogo(tx, organizationId, assetId))) throw new LogoNotFoundError(assetId);
      return write(tx);
    });
  }
}
