/**
 * Decode round trip for print exports (ADR-0005 D5, PR 6).
 *
 * Print PNG: the production path (renderExport, sharp) at 300 and 600 dpi,
 * at 20, 30, 50 and 100 mm, for representative styles: plain, stylised
 * shapes with the QRAuth logo, a frame with the logo, a customer logo, and a
 * light-on-dark code with the logo. zxing-wasm must read back exactly the
 * URL; jsQR also on the black-on-white rows.
 *
 * PDF: rasterised by pdfjs-dist (Apache-2.0) on @napi-rs/canvas (MIT),
 * devDependencies only, at 300 and 600 dpi, then decoded. As a geometry
 * check, each PDF raster is compared pixel by pixel with sharp's raster of
 * the same artwork's SVG at the same size: the PDF is the SVG's drawing.
 *
 * `fetch` is disabled; the zxing WASM binary is read from node_modules.
 */
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import sharp from 'sharp';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { prepareZXingModule, readBarcodes } from 'zxing-wasm/reader';
import type { QrStyleV2 } from '@qrauth/shared/qr-render';

process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

const { QRAUTH_LOGO_PNG, rasterisePng, renderExport, renderStyled } = await import('../../src/services/qr-render.js');
const { buildVerificationUrl } = await import('../../src/lib/qrcode-access.js');

const require = createRequire(import.meta.url);
const jsQR = require('jsqr') as typeof import('jsqr').default;

/** A customer logo as the upload normalisation stores it (the cross-package golden fixture). */
const CUSTOMER_LOGO_PNG = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), '../../../shared/src/qr-render/__tests__/fixtures/customer-logo.png'),
);

/** Production-length token (28-character verify URL, D4.4). */
const TOKEN = 'aB3dE5gH';
const VERIFY_URL = buildVerificationUrl(TOKEN);
const QR = { token: TOKEN, issuerVerified: true };

const SIZES_MM = [20, 30, 50, 100] as const;
const DPIS = [300, 600] as const;

interface Case {
  readonly name: string;
  readonly style: QrStyleV2;
  readonly logo: Uint8Array | null;
  /** jsQR only reads high-contrast, non-inverted codes reliably (D4.1). */
  readonly jsqr: boolean;
}

const BASE = {
  version: 2, presetId: 'test', fg: '#000000', bg: '#FFFFFF', inverted: false,
  modules: 'square', eyes: 'square', ecLevel: 'auto', quietZone: 4, logo: null,
} as const satisfies QrStyleV2;

const CASES: readonly Case[] = [
  { name: 'square, no logo', style: BASE, logo: null, jsqr: true },
  { name: 'dots/circle, QRAuth logo', style: { ...BASE, modules: 'dots', eyes: 'circle', logo: { kind: 'qrauth' } }, logo: QRAUTH_LOGO_PNG, jsqr: true },
  {
    name: 'classy/leaf, banner-bottom frame, QRAuth logo',
    style: {
      ...BASE, modules: 'classy', eyes: 'leaf', logo: { kind: 'qrauth' },
      frame: { template: 'banner-bottom', text: 'Σαρώστε με', color: '#000000', textColor: '#FFFFFF' },
    },
    logo: QRAUTH_LOGO_PNG,
    jsqr: true,
  },
  {
    name: 'rounded, badge frame, customer logo',
    style: {
      ...BASE, fg: '#003768', modules: 'rounded', eyes: 'rounded', logo: { kind: 'asset', assetId: 'fixture', scale: 1 },
      frame: { template: 'badge', text: 'Scan me', color: '#003768', textColor: '#FFFFFF' },
    },
    logo: CUSTOMER_LOGO_PNG,
    jsqr: false,
  },
  {
    name: 'light on dark (midnight), QRAuth logo',
    style: { ...BASE, fg: '#E0E0E0', bg: '#212121', inverted: true, logo: { kind: 'qrauth' } },
    logo: QRAUTH_LOGO_PNG,
    jsqr: false,
  },
];

async function decodeZxing(png: Buffer): Promise<string | null> {
  const results = await readBarcodes(new Uint8Array(png), { formats: ['QRCode'], tryHarder: true, tryInvert: true });
  return results.find((r) => r.isValid)?.text ?? null;
}

async function decodeJsQr(png: Buffer): Promise<string | null> {
  const { data, info } = await sharp(png).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const result = jsQR(new Uint8ClampedArray(data.buffer, data.byteOffset, data.byteLength), info.width, info.height, {
    inversionAttempts: 'attemptBoth',
  });
  return result?.data ?? null;
}

interface NodeCanvas {
  readonly canvas: { toBuffer(type: 'image/png'): Buffer };
  readonly context: unknown;
}

/** Rasterises page 1 of `pdf` at `dpi` with pdfjs-dist (white page background). */
async function rasterisePdf(pdf: Buffer, dpi: number): Promise<Buffer> {
  const pdfjs = await import('pdfjs-dist/legacy/build/pdf.mjs');
  const task = pdfjs.getDocument({ data: new Uint8Array(pdf), isEvalSupported: false, disableFontFace: true, useSystemFonts: false });
  const doc = await task.promise;
  try {
    const page = await doc.getPage(1);
    const viewport = page.getViewport({ scale: dpi / 72 });
    const factory = doc.canvasFactory as { create(width: number, height: number): NodeCanvas };
    const { canvas, context } = factory.create(Math.round(viewport.width), Math.round(viewport.height));
    await page.render({ canvasContext: context as never, canvas: canvas as never, viewport }).promise;
    return canvas.toBuffer('image/png');
  } finally {
    await task.destroy();
  }
}

/**
 * Share of pixels where two equal-size rasters disagree by more than one
 * pixel: both are binarised at mid grey, and a pixel counts only when its
 * value appears nowhere in the 3 x 3 neighbourhood of the same position in
 * the other raster. Edge anti-aliasing (pdfjs) against crisp edges (librsvg
 * with shape-rendering crispEdges) moves an edge by at most one pixel, so it
 * does not count; a missing, extra or misplaced shape does.
 */
async function geometryMismatchShare(a: Buffer, b: Buffer): Promise<number> {
  const binary = async (png: Buffer) => {
    const { data, info } = await sharp(png).flatten({ background: '#FFFFFF' }).greyscale().raw().toBuffer({ resolveWithObject: true });
    return { bits: Uint8Array.from(data, (v) => (v < 128 ? 1 : 0)), width: info.width, height: info.height };
  };
  const [ra, rb] = await Promise.all([binary(a), binary(b)]);
  expect([ra.width, ra.height]).toEqual([rb.width, rb.height]);
  const { width, height } = ra;
  const near = (other: Uint8Array, x: number, y: number, value: number): boolean => {
    for (let dy = -1; dy <= 1; dy++) {
      for (let dx = -1; dx <= 1; dx++) {
        const nx = x + dx;
        const ny = y + dy;
        if (nx >= 0 && ny >= 0 && nx < width && ny < height && other[ny * width + nx] === value) return true;
      }
    }
    return false;
  };
  let mismatches = 0;
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const i = y * width + x;
      if (ra.bits[i] === rb.bits[i]) continue;
      if (!near(rb.bits, x, y, ra.bits[i]) || !near(ra.bits, x, y, rb.bits[i])) mismatches++;
    }
  }
  return mismatches / (width * height);
}

const TIMEOUT_MS = 120_000;

/** At most this share of pixels may disagree by more than one pixel (geometryMismatchShare). */
const GEOMETRY_MAX_SHARE = 0.001;

beforeAll(async () => {
  vi.stubGlobal('fetch', () => {
    throw new Error('network access is not allowed in the decode suite');
  });
  const wasmBinary = readFileSync(require.resolve('zxing-wasm/reader/zxing_reader.wasm'));
  await prepareZXingModule({
    overrides: { wasmBinary: wasmBinary.buffer.slice(wasmBinary.byteOffset, wasmBinary.byteOffset + wasmBinary.byteLength) },
    fireImmediately: true,
  });
});

afterAll(() => {
  vi.unstubAllGlobals();
});

describe('print PNG decode round trip (sharp, 300 and 600 dpi)', () => {
  for (const c of CASES) {
    it(`${c.name}: ${SIZES_MM.join(', ')} mm at ${DPIS.join(' and ')} dpi [zxing${c.jsqr ? ', jsqr' : ''}]`, async () => {
      const failures: string[] = [];
      let decodes = 0;
      for (const sizeMm of SIZES_MM) {
        for (const dpi of DPIS) {
          const { body, px } = await renderExport(QR, c.style, c.logo, { format: 'png', print: { sizeMm, dpi } });
          expect((await sharp(body).metadata()).width).toBe(px);
          const results = [['zxing', await decodeZxing(body)], ...(c.jsqr ? [['jsqr', await decodeJsQr(body)]] : [])];
          for (const [decoder, text] of results) {
            decodes++;
            if (text !== VERIFY_URL) failures.push(`${sizeMm}mm/${dpi}dpi ${decoder}=${JSON.stringify(text)}`);
          }
        }
      }
      expect(decodes).toBe(SIZES_MM.length * DPIS.length * (c.jsqr ? 2 : 1));
      expect(failures).toEqual([]);
    }, TIMEOUT_MS);
  }
});

describe('PDF decode round trip (pdfjs-dist raster) and vector geometry', () => {
  for (const c of CASES) {
    it(`${c.name}: 20 and 50 mm PDFs decode at 300 and 600 dpi`, async () => {
      const failures: string[] = [];
      for (const sizeMm of [20, 50]) {
        const { body: pdf } = await renderExport(QR, c.style, c.logo, { format: 'pdf', print: { sizeMm } });
        for (const dpi of DPIS) {
          const text = await decodeZxing(await rasterisePdf(pdf, dpi));
          if (text !== VERIFY_URL) failures.push(`${sizeMm}mm/${dpi}dpi zxing=${JSON.stringify(text)}`);
        }
      }
      expect(failures).toEqual([]);
    }, TIMEOUT_MS);

    // Geometry: the PDF against sharp's raster of the same SVG at the same
    // pixel size. 25.4 and 50.8 mm are 300 and 600 px wide at 300 dpi, so
    // both rasters share one pixel grid.
    it(`${c.name}: the PDF draws the SVG's geometry (25.4 and 50.8 mm at 300 dpi)`, async () => {
      for (const sizeMm of [25.4, 50.8]) {
        const { body: pdf } = await renderExport(QR, c.style, c.logo, { format: 'pdf', print: { sizeMm } });
        const pdfPng = await rasterisePdf(pdf, 300);
        const { width, height } = await sharp(pdfPng).metadata();
        expect(width).toBe(Math.round((sizeMm / 25.4) * 300));
        const { svg } = renderStyled({ data: VERIFY_URL, style: c.style, logoPng: c.logo, issuerVerified: true, size: { value: width!, unit: 'px' } });
        const svgPng = await rasterisePng(svg);
        expect((await sharp(svgPng).metadata()).height).toBe(height);
        expect(await geometryMismatchShare(pdfPng, svgPng), `${sizeMm} mm`).toBeLessThan(GEOMETRY_MAX_SHARE);
      }
    }, TIMEOUT_MS);
  }

  it('the geometry check catches a different drawing (negative control)', async () => {
    const { body: pdf } = await renderExport(QR, BASE, null, { format: 'pdf', print: { sizeMm: 25.4 } });
    const pdfPng = await rasterisePdf(pdf, 300);
    const other = renderStyled({ data: buildVerificationUrl('zZ9yY8xX'), style: BASE, size: { value: 300, unit: 'px' } }).svg;
    expect(await geometryMismatchShare(pdfPng, await rasterisePng(other))).toBeGreaterThan(0.05);
  }, TIMEOUT_MS);
});
