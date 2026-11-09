import type { PrismaClient } from '@prisma/client';

/**
 * Where asset bytes live (ADR-0005 D6). Callers go through this interface, so
 * a filesystem or object-store backend can replace Postgres (Milestone 2
 * bulk ZIPs, large PDF content files) without touching them.
 */
export interface AssetStore {
  /** Stores `bytes` for an asset row that already exists; returns its `storagePath`. */
  put(assetId: string, bytes: Uint8Array): Promise<string>;
  /** The bytes, or null when none are stored for the asset. */
  get(assetId: string): Promise<Uint8Array | null>;
  delete(assetId: string): Promise<void>;
}

type BlobClient = Pick<PrismaClient, 'contentAssetBlob'>;

/** `storagePath` of an asset whose bytes are in content_asset_blobs. */
export function dbStoragePath(assetId: string): string {
  return `db:${assetId}`;
}

/**
 * Phase 1 backend: bytes in content_asset_blobs (one row per asset, deleted
 * with the asset by cascade). Covered by the database backups.
 */
export class PostgresAssetStore implements AssetStore {
  constructor(private readonly db: BlobClient) {}

  async put(assetId: string, bytes: Uint8Array): Promise<string> {
    await this.db.contentAssetBlob.create({ data: { assetId, bytes: Buffer.from(bytes) } });
    return dbStoragePath(assetId);
  }

  async get(assetId: string): Promise<Uint8Array | null> {
    const row = await this.db.contentAssetBlob.findUnique({ where: { assetId }, select: { bytes: true } });
    return row ? new Uint8Array(row.bytes) : null;
  }

  async delete(assetId: string): Promise<void> {
    await this.db.contentAssetBlob.deleteMany({ where: { assetId } });
  }
}
