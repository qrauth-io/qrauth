import { describe, expect, it } from 'vitest';

import { dbStoragePath, PostgresAssetStore } from '../asset-store.js';

/** content_asset_blobs as an in-memory table. */
function fakeDb() {
  const rows = new Map<string, Buffer>();
  return {
    rows,
    contentAssetBlob: {
      create: async ({ data }: { data: { assetId: string; bytes: Buffer } }) => {
        if (rows.has(data.assetId)) throw new Error('unique constraint');
        rows.set(data.assetId, data.bytes);
        return data;
      },
      findUnique: async ({ where }: { where: { assetId: string } }) => {
        const bytes = rows.get(where.assetId);
        return bytes ? { bytes } : null;
      },
      deleteMany: async ({ where }: { where: { assetId: string } }) => {
        const count = rows.delete(where.assetId) ? 1 : 0;
        return { count };
      },
    },
  };
}

describe('PostgresAssetStore', () => {
  it('stores bytes and returns the db: storage path', async () => {
    const db = fakeDb();
    const store = new PostgresAssetStore(db as never);
    const path = await store.put('asset_1', new Uint8Array([1, 2, 3]));
    expect(path).toBe('db:asset_1');
    expect(dbStoragePath('asset_1')).toBe(path);
    expect(Array.from(db.rows.get('asset_1')!)).toEqual([1, 2, 3]);
  });

  it('returns the stored bytes, or null for an asset without bytes', async () => {
    const store = new PostgresAssetStore(fakeDb() as never);
    await store.put('asset_1', new Uint8Array([9, 8]));
    expect(Array.from((await store.get('asset_1'))!)).toEqual([9, 8]);
    expect(await store.get('missing')).toBeNull();
  });

  it('deletes bytes, and deleting twice is not an error', async () => {
    const db = fakeDb();
    const store = new PostgresAssetStore(db as never);
    await store.put('asset_1', new Uint8Array([1]));
    await store.delete('asset_1');
    await store.delete('asset_1');
    expect(db.rows.size).toBe(0);
  });
});
