/**
 * Save-time decode round trip for customer logos (ADR-0005 PR 4): the code
 * is rendered with the logo, rasterised through the production path at the
 * real export widths (300, 512 and 1024 px, non-integer px/module), every
 * whole scale from 3 to 16 px/module and D5's blurred raster, and
 * decoded with zxing-wasm. A raster that does not read back the URL, and
 * only the URL, rejects the style. The WASM binary is loaded from
 * node_modules; `fetch` is disabled, so the check contacts no host.
 */
import sharp from 'sharp';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { DEFAULT_STYLE, renderQr, type QrStyleV2 } from '@qrauth/shared/qr-render';

process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

const { assertLogoScans, DECODE_EXPORT_WIDTHS, DECODE_RASTERS, LogoUnreadableError, rasterWidth } = await import('../../src/services/logo-decode.js');
const { normaliseLogo } = await import('../../src/services/logo-normalise.js');
const { effectivePx, IMAGE_PX_MAX, MIN_PX_PER_MODULE, QR_IMAGE_URL_PX } = await import('../../src/services/qr-render.js');

const URL = 'https://qrauth.io/v/aB3dE5gH';
const TIMEOUT_MS = 60_000;

const assetStyle = (scale: number, overrides: Partial<QrStyleV2> = {}): QrStyleV2 => ({
  ...DEFAULT_STYLE,
  ecLevel: 'auto',
  logo: { kind: 'asset', assetId: 'test-asset', scale },
  ...overrides,
});

/** A simple brand mark: a filled circle on transparency, normalised like an upload. */
async function brandMark(): Promise<Uint8Array> {
  const svg = '<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256"><circle cx="128" cy="128" r="110" fill="#1B5E20"/></svg>';
  const png = await sharp(Buffer.from(svg)).png().toBuffer();
  return (await normaliseLogo(png)).png;
}

/** A logo that is itself a QR code for another URL. */
async function qrLogo(): Promise<Uint8Array> {
  const { svg } = renderQr({ data: 'https://example.com/elsewhere', style: { ...DEFAULT_STYLE, quietZone: 4 }, size: { value: 512, unit: 'px' } });
  const png = await sharp(Buffer.from(svg)).png().toBuffer();
  return (await normaliseLogo(png)).png;
}

beforeAll(() => {
  vi.stubGlobal('fetch', () => {
    throw new Error('network access is not allowed in the logo decode check');
  });
});

afterAll(() => {
  vi.unstubAllGlobals();
});

describe('DECODE_RASTERS', () => {
  it('covers every whole scale from the minimum to 16 px/module, plus the blurred D5 raster', () => {
    const plain = DECODE_RASTERS.filter((r) => r.blur === 0 && r.pxPerModule !== undefined).map((r) => r.pxPerModule);
    expect(plain).toEqual(Array.from({ length: 16 - MIN_PX_PER_MODULE + 1 }, (_, i) => i + MIN_PX_PER_MODULE));
    expect(DECODE_RASTERS).toContainEqual({ name: '3 px per module, blurred', pxPerModule: 3, blur: 1 });
    // D5's 8 px/module raster is part of the sweep.
    expect(plain).toContain(8);
  });

  it('checks the real export widths first: qr_image_url, 512 px and the 1024 px maximum', () => {
    expect(DECODE_EXPORT_WIDTHS).toEqual([QR_IMAGE_URL_PX, 512, IMAGE_PX_MAX]);
    expect(DECODE_RASTERS.slice(0, 3)).toEqual([
      { name: '300 px wide', widthPx: 300, blur: 0 },
      { name: '512 px wide', widthPx: 512, blur: 0 },
      { name: '1024 px wide', widthPx: 1024, blur: 0 },
    ]);
  });
});

describe('rasterWidth', () => {
  const style = assetStyle(1);
  const qr = { token: 'aB3dE5gH' };

  it.each(DECODE_EXPORT_WIDTHS)('renders the %s px export at the width export would produce (effectivePx)', async (px) => {
    const { buildVerificationUrl } = await import('../../src/lib/qrcode-access.js');
    const { meta } = renderQr({ data: buildVerificationUrl(qr.token), style, logoPng: null });
    expect(rasterWidth({ name: 'x', widthPx: px, blur: 0 }, meta.width)).toBe(effectivePx(qr, style, { format: 'png', px }));
  });

  it('raises an export width below MIN_PX_PER_MODULE per module, as the server does', () => {
    // 100 modules: 300 px would be 3 px/module at most; 64 px is raised to 300.
    expect(rasterWidth({ name: 'x', widthPx: 64, blur: 0 }, 100)).toBe(MIN_PX_PER_MODULE * 100);
  });

  it('300 px is a non-integer scale for typical codes', () => {
    const { meta } = renderQr({ data: URL, style, logoPng: null });
    expect(Number.isInteger(300 / meta.width)).toBe(false);
  });

  it('skips a whole scale whose width cannot be exported', () => {
    expect(rasterWidth({ name: 'x', pxPerModule: 16, blur: 0 }, 100)).toBeNull();
    expect(rasterWidth({ name: 'x', pxPerModule: 10, blur: 0 }, 100)).toBe(1000);
  });
});

describe('assertLogoScans', () => {
  it.each([0.5, 0.75, 1])('accepts a simple brand mark at scale %s', async (scale) => {
    await expect(assertLogoScans(URL, assetStyle(scale), await brandMark())).resolves.toBeUndefined();
  }, TIMEOUT_MS);

  it('accepts a brand mark on light-on-dark colours at the 7:1 floor', async () => {
    const style = assetStyle(1, { fg: '#FFFFFF', bg: '#1B2A4A', inverted: true });
    await expect(assertLogoScans(URL, style, await brandMark())).resolves.toBeUndefined();
  }, TIMEOUT_MS);

  it('refuses a logo that holds a readable code for another URL', async () => {
    const err = await assertLogoScans(URL, assetStyle(1), await qrLogo()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(LogoUnreadableError);
    expect((err as InstanceType<typeof LogoUnreadableError>).raster).toMatch(/^\d+ px (wide|per module)/);
  }, TIMEOUT_MS);

  it('decodes at each export width as the server renders it', async () => {
    const logo = await brandMark();
    for (const widthPx of DECODE_EXPORT_WIDTHS) {
      await expect(assertLogoScans(URL, assetStyle(1), logo, [{ name: `${widthPx} px wide`, widthPx, blur: 0 }])).resolves.toBeUndefined();
    }
  }, TIMEOUT_MS);

  it('refuses when a raster does not read back, naming that raster', async () => {
    // A raster below the decodable size stands in for a logo that breaks the code.
    const tooSmall = [{ name: '1 px per module', pxPerModule: 1, blur: 3 }];
    const err = await assertLogoScans(URL, assetStyle(1), await brandMark(), tooSmall).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(LogoUnreadableError);
    expect((err as InstanceType<typeof LogoUnreadableError>).raster).toBe('1 px per module');
  }, TIMEOUT_MS);
});
