import { describe, expect, it, vi } from 'vitest';

import { cleanLogoName, DEFAULT_LOGO_NAME, LOGO_MAX_PER_ORG, LOGO_NAME_MAX, LogoLibrary, LogoNotFoundError } from '../logo-library.js';
import type { NormalisedLogo } from '../logo-normalise.js';
import { fakeLogoDb as fakeDb } from './fake-logo-db.js';

/**
 * The logo library with an in-memory database: the per-organization cap,
 * organization scoping (another organization's id is a missing one), and
 * delete refused while a code draws the logo. services/__tests__/
 * logo-library.integration.test.ts runs the same paths against Postgres.
 */

const LOGO: NormalisedLogo = { png: new Uint8Array([0x89, 0x50, 0x4e, 0x47, 1, 2]), width: 100, height: 50, sha256: 'ab'.repeat(32) };

describe('LogoLibrary.create', () => {
  it('stores the normalised PNG as a LOGO asset with its metadata and the db: path', async () => {
    const { db, assets, blobs } = fakeDb();
    const result = await new LogoLibrary(db as never).create('org_1', LOGO, 'brand.png');
    expect(result).toEqual({
      outcome: 'created',
      logo: { id: 'asset_1', name: 'brand.png', width: 100, height: 50, sizeBytes: 6, sha256: LOGO.sha256, createdAt: expect.any(String) },
    });
    expect(assets[0]).toMatchObject({ organizationId: 'org_1', kind: 'LOGO', mimeType: 'image/png', storagePath: 'db:asset_1' });
    expect(Array.from(blobs.get('asset_1')!)).toEqual(Array.from(LOGO.png));
  });

  it(`refuses the ${LOGO_MAX_PER_ORG + 1}st logo of an organization and stores nothing`, async () => {
    const { db, assets, blobs } = fakeDb();
    const library = new LogoLibrary(db as never);
    for (let i = 0; i < LOGO_MAX_PER_ORG; i++) {
      expect((await library.create('org_1', LOGO, `l${i}`)).outcome).toBe('created');
    }
    expect(await library.create('org_1', LOGO, 'one-more')).toEqual({ outcome: 'limit_reached', limit: LOGO_MAX_PER_ORG });
    expect(assets).toHaveLength(LOGO_MAX_PER_ORG);
    expect(blobs.size).toBe(LOGO_MAX_PER_ORG);
    // Another organization has its own cap.
    expect((await library.create('org_2', LOGO, 'x')).outcome).toBe('created');
  });

  it('runs the audit hook in the create transaction once the logo is stored', async () => {
    const { db } = fakeDb();
    const audit = vi.fn(async () => undefined);
    await new LogoLibrary(db as never).create('org_1', LOGO, 'x', audit);
    expect(audit).toHaveBeenCalledWith(expect.objectContaining({ auditLog: expect.anything() }), { assetId: 'asset_1', sizeBytes: LOGO.png.length });
  });

  it('does not run the audit hook when the cap refuses the upload', async () => {
    const { db } = fakeDb();
    const library = new LogoLibrary(db as never);
    for (let i = 0; i < LOGO_MAX_PER_ORG; i++) await library.create('org_1', LOGO, `l${i}`);
    const audit = vi.fn(async () => undefined);
    expect((await library.create('org_1', LOGO, 'one-more', audit)).outcome).toBe('limit_reached');
    expect(audit).not.toHaveBeenCalled();
  });

  it('retries once after a serialization conflict', async () => {
    const { db, $transaction } = fakeDb({ conflicts: 1 });
    expect((await new LogoLibrary(db as never).create('org_1', LOGO, 'x')).outcome).toBe('created');
    expect($transaction).toHaveBeenCalledTimes(2);
  });

  it('answers limit_reached after two conflicts in a row', async () => {
    const { db } = fakeDb({ conflicts: 2 });
    expect((await new LogoLibrary(db as never).create('org_1', LOGO, 'x')).outcome).toBe('limit_reached');
  });
});

describe('LogoLibrary reads are scoped to the organization', () => {
  it('lists only the organization’s logos, newest first', async () => {
    const { db } = fakeDb();
    const library = new LogoLibrary(db as never);
    await library.create('org_1', LOGO, 'first');
    await library.create('org_2', LOGO, 'other');
    await library.create('org_1', LOGO, 'second');
    expect((await library.list('org_1')).map((l) => l.name)).toEqual(['second', 'first']);
  });

  it('returns bytes for its own logo and null for another organization’s or a missing id', async () => {
    const { db } = fakeDb();
    const library = new LogoLibrary(db as never);
    await library.create('org_1', LOGO, 'mine');
    expect(Array.from((await library.bytes('org_1', 'asset_1'))!)).toEqual(Array.from(LOGO.png));
    expect(await library.bytes('org_2', 'asset_1')).toBeNull();
    expect(await library.bytes('org_1', 'asset_404')).toBeNull();
  });
});

describe('LogoLibrary.delete', () => {
  it('deletes an unused logo and its bytes', async () => {
    const { db, assets, blobs } = fakeDb();
    const library = new LogoLibrary(db as never);
    await library.create('org_1', LOGO, 'x');
    expect(await library.delete('org_1', 'asset_1')).toEqual({ outcome: 'deleted', sizeBytes: LOGO.png.length });
    expect(assets).toHaveLength(0);
    expect(blobs.size).toBe(0);
  });

  it('runs the audit hook in the delete transaction, after the delete, with the size', async () => {
    const { db, calls } = fakeDb();
    const library = new LogoLibrary(db as never);
    await library.create('org_1', LOGO, 'x');
    calls.length = 0;
    const audit = vi.fn(async (tx: { auditLog: { create: (a: unknown) => Promise<unknown> } }) => {
      await tx.auditLog.create({ data: {} });
    });
    await library.delete('org_1', 'asset_1', audit as never);
    expect(audit).toHaveBeenCalledWith(expect.anything(), { assetId: 'asset_1', sizeBytes: LOGO.png.length });
    expect(calls).toEqual(['lock', 'qRCode.count', 'contentAsset.deleteMany', 'auditLog.create']);
  });

  it('does not run the audit hook when nothing is deleted', async () => {
    const { db } = fakeDb({ references: 1 });
    const library = new LogoLibrary(db as never);
    await library.create('org_1', LOGO, 'x');
    const audit = vi.fn(async () => undefined);
    await library.delete('org_1', 'asset_1', audit);
    await library.delete('org_2', 'asset_1', audit);
    expect(audit).not.toHaveBeenCalled();
  });

  it('deletes only the asset row; the bytes go by the foreign key cascade', async () => {
    const { db } = fakeDb();
    const library = new LogoLibrary(db as never);
    await library.create('org_1', LOGO, 'x');
    await library.delete('org_1', 'asset_1');
    expect(db.contentAsset.deleteMany).toHaveBeenCalledWith({ where: { id: 'asset_1', organizationId: 'org_1', kind: 'LOGO' } });
    expect(db.contentAssetBlob.deleteMany).not.toHaveBeenCalled();
  });

  it('refuses while codes draw the logo, with their count, and changes nothing', async () => {
    const { db, assets, qRCode } = fakeDb({ references: 3 });
    const library = new LogoLibrary(db as never);
    await library.create('org_1', LOGO, 'x');
    expect(await library.delete('org_1', 'asset_1')).toEqual({ outcome: 'in_use', count: 3 });
    expect(assets).toHaveLength(1);
    expect(qRCode.count).toHaveBeenCalledWith({
      where: { organizationId: 'org_1', style: { path: ['logo', 'assetId'], equals: 'asset_1' } },
    });
  });

  it('treats another organization’s logo as missing', async () => {
    const { db, assets } = fakeDb();
    const library = new LogoLibrary(db as never);
    await library.create('org_1', LOGO, 'x');
    expect(await library.delete('org_2', 'asset_1')).toEqual({ outcome: 'not_found' });
    expect(assets).toHaveLength(1);
  });

  it('locks the logo row, then counts references, then deletes, in one transaction', async () => {
    const { db, calls, $transaction } = fakeDb();
    const library = new LogoLibrary(db as never);
    await library.create('org_1', LOGO, 'x');
    $transaction.mockClear();
    calls.length = 0;
    await library.delete('org_1', 'asset_1');
    expect($transaction).toHaveBeenCalledTimes(1);
    expect(calls).toEqual(['lock', 'qRCode.count', 'contentAsset.deleteMany']);
  });
});

describe('LogoLibrary.writeWithLogo', () => {
  it('locks the logo row before the write, in the same transaction', async () => {
    const { db, calls, $transaction } = fakeDb();
    const library = new LogoLibrary(db as never);
    await library.create('org_1', LOGO, 'x');
    $transaction.mockClear();
    calls.length = 0;
    const result = await library.writeWithLogo('org_1', 'asset_1', async () => {
      calls.push('write');
      return 'written';
    });
    expect(result).toBe('written');
    expect($transaction).toHaveBeenCalledTimes(1);
    expect(calls).toEqual(['lock', 'write']);
  });

  it('throws LogoNotFoundError and writes nothing when the logo is gone or another organization’s', async () => {
    const { db } = fakeDb();
    const library = new LogoLibrary(db as never);
    await library.create('org_1', LOGO, 'x');
    const write = vi.fn(async () => 'written');
    await expect(library.writeWithLogo('org_2', 'asset_1', write)).rejects.toBeInstanceOf(LogoNotFoundError);
    expect(await library.delete('org_1', 'asset_1')).toEqual({ outcome: 'deleted', sizeBytes: LOGO.png.length });
    await expect(library.writeWithLogo('org_1', 'asset_1', write)).rejects.toBeInstanceOf(LogoNotFoundError);
    expect(write).not.toHaveBeenCalled();
  });
});

describe('cleanLogoName', () => {
  it('drops control and bidi characters and trims', () => {
    expect(cleanLogoName('  brand‮\u0000.png \n')).toBe('brand.png');
  });

  it.each([
    ['zero-width space', '\u200B'],
    ['zero-width non-joiner', '\u200C'],
    ['zero-width joiner', '\u200D'],
    ['byte-order mark', '\uFEFF'],
    ['line separator', '\u2028'],
    ['paragraph separator', '\u2029'],
    ['Arabic letter mark', '\u061C'],
    ['left-to-right mark', '\u200E'],
    ['right-to-left mark', '\u200F'],
    ['right-to-left override', '\u202E'],
    ['first strong isolate', '\u2068'],
  ])('drops the %s', (_label, ch) => {
    expect(cleanLogoName(`br${ch}and${ch}.png`)).toBe('brand.png');
  });

  it('keeps ordinary non-Latin names', () => {
    expect(cleanLogoName('λογότυπο.png')).toBe('λογότυπο.png');
    expect(cleanLogoName('شعار.png')).toBe('شعار.png');
  });

  it('a name of only invisible characters falls back to the default', () => {
    expect(cleanLogoName('\u200B\uFEFF\u2028')).toBe(DEFAULT_LOGO_NAME);
  });

  it(`keeps at most ${LOGO_NAME_MAX} characters`, () => {
    expect(cleanLogoName('a'.repeat(300))).toHaveLength(LOGO_NAME_MAX);
  });

  it('falls back to the default name', () => {
    expect(cleanLogoName(undefined)).toBe(DEFAULT_LOGO_NAME);
    expect(cleanLogoName(' ‎ ')).toBe(DEFAULT_LOGO_NAME);
  });
});
