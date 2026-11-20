import { randomBytes } from 'node:crypto';

import { PrismaClient } from '@prisma/client';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { LogoLibrary, LogoNotFoundError } from '../logo-library.js';
import { PostgresAssetStore } from '../asset-store.js';

/**
 * The logo library against a real Postgres (ADR-0005 D6): bytes in
 * content_asset_blobs, the style.logo.assetId JSON path filter that blocks
 * deletion, the row lock that orders a delete and a style write, and the
 * cascade from organization to asset to bytes.
 *
 * Skips when no migrated database is reachable (the API suite runs without
 * Postgres in CI). Run locally with DATABASE_URL pointing at a database
 * after `prisma migrate deploy`.
 */

const nonce = randomBytes(4).toString('hex');
let prisma: PrismaClient | null = null;
let dbAvailable = false;
const orgIds: string[] = [];

const LOGO = { png: new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 7]), width: 64, height: 64, sha256: 'cd'.repeat(32) };

async function makeOrg(suffix: string): Promise<{ orgId: string; keyId: string }> {
  const org = await prisma!.organization.create({
    data: { name: `logo-it-${suffix}`, slug: `logo-it-${nonce}-${suffix}`, email: `logo-it-${nonce}-${suffix}@example.test` },
  });
  orgIds.push(org.id);
  const key = await prisma!.signingKey.create({
    data: { organizationId: org.id, publicKey: 'test', keyId: `logo-it-${nonce}-${suffix}` },
  });
  return { orgId: org.id, keyId: key.id };
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function codeData(orgId: string, keyId: string, style: unknown) {
  return {
    token: `li${nonce}${randomBytes(3).toString('hex')}`,
    organizationId: orgId,
    signingKeyId: keyId,
    destinationUrl: 'https://example.com',
    signature: 'test',
    algVersion: 'test',
    style: style as object,
  };
}

async function makeCode(orgId: string, keyId: string, style: unknown): Promise<void> {
  await prisma!.qRCode.create({ data: codeData(orgId, keyId, style) });
}

beforeAll(async () => {
  try {
    prisma = new PrismaClient();
    await prisma.$queryRaw`SELECT 1 FROM content_asset_blobs LIMIT 1`;
    dbAvailable = true;
  } catch {
    dbAvailable = false;
  }
});

afterAll(async () => {
  if (prisma && dbAvailable) {
    await prisma.qRCode.deleteMany({ where: { organizationId: { in: orgIds } } });
    await prisma.organization.deleteMany({ where: { id: { in: orgIds } } });
  }
  await prisma?.$disconnect();
});

describe('LogoLibrary (Postgres)', () => {
  it('stores, lists, reads and deletes a logo; bytes live in content_asset_blobs', async (ctx) => {
    if (!dbAvailable) return ctx.skip();
    const { orgId } = await makeOrg('a');
    const library = new LogoLibrary(prisma!);
    const created = await library.create(orgId, LOGO, 'brand.png');
    expect(created.outcome).toBe('created');
    if (created.outcome !== 'created') return;
    const { id } = created.logo;

    const row = await prisma!.contentAsset.findUniqueOrThrow({ where: { id } });
    expect(row).toMatchObject({ kind: 'LOGO', storagePath: `db:${id}`, qrCodeId: null, sha256: LOGO.sha256 });
    expect(Array.from((await new PostgresAssetStore(prisma!).get(id))!)).toEqual(Array.from(LOGO.png));
    expect((await library.list(orgId)).map((l) => l.id)).toEqual([id]);

    expect(await library.delete(orgId, id)).toEqual({ outcome: 'deleted', sizeBytes: LOGO.png.length });
    expect(await prisma!.contentAssetBlob.count({ where: { assetId: id } })).toBe(0);
  });

  it('the bytes go with the asset row by the foreign key cascade', async (ctx) => {
    if (!dbAvailable) return ctx.skip();
    const { orgId } = await makeOrg('cascade');
    const created = await new LogoLibrary(prisma!).create(orgId, LOGO, 'x');
    if (created.outcome !== 'created') throw new Error('not created');
    const { id } = created.logo;
    // Deleting only the content_assets row, as LogoLibrary.delete does, removes the blob.
    await prisma!.contentAsset.delete({ where: { id } });
    expect(await prisma!.contentAssetBlob.count({ where: { assetId: id } })).toBe(0);
  });

  it('refuses deletion while a code of the organization draws the logo, counting only those codes', async (ctx) => {
    if (!dbAvailable) return ctx.skip();
    const a = await makeOrg('b');
    const b = await makeOrg('c');
    const library = new LogoLibrary(prisma!);
    const created = await library.create(a.orgId, LOGO, 'brand.png');
    if (created.outcome !== 'created') throw new Error('not created');
    const { id } = created.logo;
    const style = { version: 2, logo: { kind: 'asset', assetId: id, scale: 1 } };

    await makeCode(a.orgId, a.keyId, style);
    await makeCode(a.orgId, a.keyId, style);
    await makeCode(a.orgId, a.keyId, { version: 2, logo: { kind: 'qrauth' } });
    await makeCode(a.orgId, a.keyId, null);
    // A code of another organization naming the id does not count (and cannot block deletion).
    await makeCode(b.orgId, b.keyId, style);

    expect(await library.delete(a.orgId, id)).toEqual({ outcome: 'in_use', count: 2 });
    expect(await prisma!.contentAsset.count({ where: { id } })).toBe(1);
    expect(await library.delete(b.orgId, id)).toEqual({ outcome: 'not_found' });

    await prisma!.qRCode.deleteMany({ where: { organizationId: a.orgId, style: { path: ['logo', 'assetId'], equals: id } } });
    expect(await library.delete(a.orgId, id)).toEqual({ outcome: 'deleted', sizeBytes: LOGO.png.length });
  });

  it('a delete that starts while a style write holds the lock waits, then sees the new reference', async (ctx) => {
    if (!dbAvailable) return ctx.skip();
    const { orgId, keyId } = await makeOrg('race-a');
    const library = new LogoLibrary(prisma!);
    const created = await library.create(orgId, LOGO, 'brand.png');
    if (created.outcome !== 'created') throw new Error('not created');
    const { id } = created.logo;
    const style = { version: 2, logo: { kind: 'asset', assetId: id, scale: 1 } };

    let isLocked!: () => void;
    const locked = new Promise<void>((resolve) => { isLocked = resolve; });
    const write = library.writeWithLogo(orgId, id, async (tx) => {
      isLocked();
      await sleep(300); // the delete below starts while this transaction holds the lock
      return tx.qRCode.create({ data: codeData(orgId, keyId, style) });
    });
    await locked;
    const deletion = library.delete(orgId, id);

    await expect(write).resolves.toMatchObject({ organizationId: orgId });
    expect(await deletion).toEqual({ outcome: 'in_use', count: 1 });
    expect(await prisma!.contentAsset.count({ where: { id } })).toBe(1);
  });

  it('a style write that starts while a delete holds the lock waits, then finds the logo gone and writes nothing', async (ctx) => {
    if (!dbAvailable) return ctx.skip();
    const { orgId, keyId } = await makeOrg('race-b');
    const library = new LogoLibrary(prisma!);
    const created = await library.create(orgId, LOGO, 'brand.png');
    if (created.outcome !== 'created') throw new Error('not created');
    const { id } = created.logo;
    const style = { version: 2, logo: { kind: 'asset', assetId: id, scale: 1 } };

    // A delete in progress: the same lock, count and delete as LogoLibrary.delete, held open.
    let isLocked!: () => void;
    const locked = new Promise<void>((resolve) => { isLocked = resolve; });
    const deletion = prisma!.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT "id" FROM "content_assets" WHERE "id" = ${id} FOR UPDATE`;
      isLocked();
      await sleep(300);
      await tx.contentAsset.delete({ where: { id } });
    });
    await locked;
    const write = library.writeWithLogo(orgId, id, (tx) => tx.qRCode.create({ data: codeData(orgId, keyId, style) }));

    await deletion;
    await expect(write).rejects.toBeInstanceOf(LogoNotFoundError);
    expect(await prisma!.qRCode.count({ where: { organizationId: orgId } })).toBe(0);
  });

  it('deleting the organization removes its logos and their bytes', async (ctx) => {
    if (!dbAvailable) return ctx.skip();
    const { orgId } = await makeOrg('d');
    const created = await new LogoLibrary(prisma!).create(orgId, LOGO, 'x');
    if (created.outcome !== 'created') throw new Error('not created');
    await prisma!.organization.delete({ where: { id: orgId } });
    expect(await prisma!.contentAsset.count({ where: { id: created.logo.id } })).toBe(0);
    expect(await prisma!.contentAssetBlob.count({ where: { assetId: created.logo.id } })).toBe(0);
  });
});
