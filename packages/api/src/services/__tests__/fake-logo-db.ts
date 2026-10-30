import { Prisma } from '@prisma/client';
import { vi } from 'vitest';

/**
 * In-memory content_assets, content_asset_blobs and the qRCode.count that
 * LogoLibrary uses, for the library and route suites. `references` is the
 * number of codes that draw any logo; `conflicts` makes the first N
 * serializable transactions fail with P2034. `$queryRaw` answers the logo
 * row lock (SELECT ... FOR UPDATE) and `calls` records the order of the
 * lock, the reference count and the writes; `audits` holds audit-log rows
 * written in a transaction. Deleting an asset deletes its
 * blob, as the foreign key's ON DELETE CASCADE does.
 */

export type FakeAsset = {
  id: string;
  organizationId: string;
  kind: string;
  filename: string;
  mimeType: string;
  sizeBytes: number;
  sha256: string;
  width: number;
  height: number;
  storagePath: string;
  createdAt: Date;
};

export function fakeLogoDb(opts: { references?: number; conflicts?: number } = {}) {
  const assets: FakeAsset[] = [];
  const blobs = new Map<string, Buffer>();
  const state = { references: opts.references ?? 0, conflicts: opts.conflicts ?? 0, seq: 0 };
  const calls: string[] = [];
  const matches = (a: FakeAsset, where: Record<string, unknown>) =>
    Object.entries(where).every(([k, v]) => a[k as keyof FakeAsset] === v);
  const pick = (a: FakeAsset, select?: Record<string, boolean>) =>
    select ? Object.fromEntries(Object.keys(select).map((k) => [k, a[k as keyof FakeAsset]])) : a;

  const contentAsset = {
    count: vi.fn(async ({ where }: { where: Record<string, unknown> }) => assets.filter((a) => matches(a, where)).length),
    create: vi.fn(async ({ data, select }: { data: Omit<FakeAsset, 'id' | 'createdAt'>; select?: Record<string, boolean> }) => {
      state.seq += 1;
      const row = { ...data, id: `asset_${state.seq}`, createdAt: new Date(Date.UTC(2026, 9, 29, 0, 0, state.seq)) } as FakeAsset;
      assets.push(row);
      return pick(row, select);
    }),
    update: vi.fn(async ({ where, data, select }: { where: { id: string }; data: Partial<FakeAsset>; select?: Record<string, boolean> }) => {
      const i = assets.findIndex((a) => a.id === where.id);
      assets[i] = { ...assets[i], ...data };
      return pick(assets[i], select);
    }),
    findMany: vi.fn(async ({ where, select }: { where: Record<string, unknown>; select?: Record<string, boolean> }) =>
      assets
        .filter((a) => matches(a, where))
        .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
        .map((a) => pick(a, select)),
    ),
    findFirst: vi.fn(async ({ where, select }: { where: Record<string, unknown>; select?: Record<string, boolean> }) => {
      const row = assets.find((a) => matches(a, where));
      return row ? pick(row, select) : null;
    }),
    deleteMany: vi.fn(async ({ where }: { where: Record<string, unknown> }) => {
      calls.push('contentAsset.deleteMany');
      const before = assets.length;
      for (let i = assets.length - 1; i >= 0; i--) {
        if (!matches(assets[i], where)) continue;
        // content_asset_blobs.assetId is ON DELETE CASCADE.
        blobs.delete(assets[i].id);
        assets.splice(i, 1);
      }
      return { count: before - assets.length };
    }),
  };
  const contentAssetBlob = {
    create: vi.fn(async ({ data }: { data: { assetId: string; bytes: Buffer } }) => {
      blobs.set(data.assetId, data.bytes);
      return data;
    }),
    findUnique: vi.fn(async ({ where }: { where: { assetId: string } }) => {
      const bytes = blobs.get(where.assetId);
      return bytes ? { bytes } : null;
    }),
    deleteMany: vi.fn(async ({ where }: { where: { assetId: string } }) => ({ count: blobs.delete(where.assetId) ? 1 : 0 })),
  };
  const qRCode = {
    count: vi.fn(async () => {
      calls.push('qRCode.count');
      return state.references;
    }),
  };
  // The logo row lock: `SELECT ... WHERE id = $1 AND organizationId = $2 ... FOR UPDATE`.
  const $queryRaw = vi.fn(async (strings: TemplateStringsArray, assetId: string, organizationId: string) => {
    if (!strings.join('?').includes('FOR UPDATE')) throw new Error('expected the logo row lock');
    calls.push('lock');
    return assets
      .filter((a) => a.id === assetId && a.organizationId === organizationId && a.kind === 'LOGO')
      .map((a) => ({ id: a.id, sizeBytes: a.sizeBytes }));
  });
  const audits: Array<Record<string, unknown>> = [];
  const auditLog = {
    create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => {
      calls.push('auditLog.create');
      audits.push(data);
      return data;
    }),
  };
  const tx = { contentAsset, contentAssetBlob, qRCode, $queryRaw, auditLog };
  /** Creates run serializable (the cap); lock transactions use the default level. */
  const $transaction = vi.fn(async (work: (t: typeof tx) => Promise<unknown>, options?: unknown) => {
    if (options !== undefined && JSON.stringify(options) !== JSON.stringify({ isolationLevel: 'Serializable' })) {
      throw new Error('unexpected transaction options');
    }
    if (state.conflicts > 0) {
      state.conflicts -= 1;
      throw new Prisma.PrismaClientKnownRequestError('serialization failure', { code: 'P2034', clientVersion: 'test' });
    }
    return work(tx);
  });
  return { db: { ...tx, $transaction }, assets, blobs, qRCode, $transaction, $queryRaw, state, calls, audits };
}
