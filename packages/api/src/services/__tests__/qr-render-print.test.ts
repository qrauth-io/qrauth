import { inflateSync } from 'node:zlib';

import sharp from 'sharp';
import { describe, expect, it, vi } from 'vitest';
import { DEFAULT_STYLE, type QrStyleV2 } from '@qrauth/shared/qr-render';

/**
 * Print sizes and the vector PDF in the render service (ADR-0005 D7, PR 6):
 * sizing rules, ETag inputs, the large-raster lane, and the PDF's content
 * (vector paths for the code, the logo as the only image).
 */

process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

const {
  artworkSize,
  effectivePx,
  exportEtag,
  LARGE_RASTER_PIXELS,
  largeRasterLimiter,
  pngLimiter,
  QRAUTH_LOGO_PNG,
  rasterisePng,
  renderExport,
  renderStyled,
} = await import('../qr-render.js');
const { PrintSizeError } = await import('../print-size.js');
const { buildVerificationUrl } = await import('../../lib/qrcode-access.js');

const QR = { token: 'aB3dE5gH', issuerVerified: false };
const LOGO_STYLE: QrStyleV2 = { ...DEFAULT_STYLE, logo: { kind: 'qrauth' } };
const FRAMED: QrStyleV2 = {
  ...DEFAULT_STYLE,
  modules: 'dots',
  eyes: 'leaf',
  logo: { kind: 'qrauth' },
  frame: { template: 'banner-bottom', text: 'Scan me', color: '#000000', textColor: '#FFFFFF' },
};

/** The decompressed content streams of a pdfkit PDF (FlateDecode). */
function contentStreams(pdf: Buffer): string[] {
  const out: string[] = [];
  const text = pdf.toString('latin1');
  const re = /\/Filter \/FlateDecode[^]*?>>\nstream\n/g;
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const start = m.index + m[0].length;
    const end = text.indexOf('\nendstream', start);
    try {
      out.push(inflateSync(pdf.subarray(start, end)).toString('latin1'));
    } catch {
      // image streams are deflated too; only text-like content streams matter here
    }
  }
  return out;
}

describe('effectivePx with a print size', () => {
  it('print PNG: round(size_mm / 25.4 x dpi), never raised', () => {
    expect(effectivePx(QR, DEFAULT_STYLE, { format: 'png', print: { sizeMm: 30, dpi: 300 } })).toBe(354);
    expect(effectivePx(QR, DEFAULT_STYLE, { format: 'png', print: { sizeMm: 50 } })).toBe(591);
  });

  it('print SVG and PDF have no pixel width', () => {
    expect(effectivePx(QR, DEFAULT_STYLE, { format: 'svg', print: { sizeMm: 30 } })).toBeUndefined();
    expect(effectivePx(QR, DEFAULT_STYLE, { format: 'pdf', print: { sizeMm: 30, marginMm: 2 } })).toBeUndefined();
  });

  it('refuses combinations the route also refuses', () => {
    expect(() => effectivePx(QR, DEFAULT_STYLE, { format: 'png', px: 300, print: { sizeMm: 30 } })).toThrow(RangeError);
    expect(() => effectivePx(QR, DEFAULT_STYLE, { format: 'pdf' })).toThrow(RangeError);
    expect(() => effectivePx(QR, DEFAULT_STYLE, { format: 'svg', print: { sizeMm: 30, dpi: 300 } })).toThrow(RangeError);
    expect(() => effectivePx(QR, DEFAULT_STYLE, { format: 'png', print: { sizeMm: 30, marginMm: 1 } })).toThrow(RangeError);
  });

  it('modules under 0.4 mm are refused for every format with a physical size', () => {
    for (const format of ['png', 'svg', 'pdf'] as const) {
      expect(() => effectivePx(QR, DEFAULT_STYLE, { format, print: { sizeMm: 12 } })).toThrow(PrintSizeError);
    }
  });

  it('the frame counts in the artwork size', () => {
    const plain = artworkSize(QR, DEFAULT_STYLE);
    const framed = artworkSize(QR, FRAMED);
    expect(plain.width).toBe(plain.height);
    expect(framed.width).toBeGreaterThan(plain.width);
    expect(framed.height).toBeGreaterThan(framed.width);
  });
});

describe('exportEtag with a print size', () => {
  const etag = (opts: Parameters<typeof exportEtag>[3]): string => exportEtag(QR, DEFAULT_STYLE, null, opts);

  it('includes format, size_mm, dpi and margin_mm', () => {
    const base = etag({ format: 'png', print: { sizeMm: 30, dpi: 300 } });
    expect(etag({ format: 'png', print: { sizeMm: 30, dpi: 300 } })).toBe(base);
    expect(etag({ format: 'png', print: { sizeMm: 30, dpi: 600 } })).not.toBe(base);
    expect(etag({ format: 'png', print: { sizeMm: 30.1, dpi: 300 } })).not.toBe(base);
    const pdf = etag({ format: 'pdf', print: { sizeMm: 30, marginMm: 0 } });
    expect(etag({ format: 'pdf', print: { sizeMm: 30, marginMm: 1 } })).not.toBe(pdf);
    expect(etag({ format: 'svg', print: { sizeMm: 30 } })).not.toBe(pdf);
  });

  it('a screen PNG\'s tag does not change with PR 6 (no print parts)', () => {
    expect(etag({ format: 'png', px: 354 })).not.toBe(etag({ format: 'png', print: { sizeMm: 30, dpi: 300 } }));
  });
});

describe('print SVG', () => {
  it('carries the size in mm; the drawing is the screen SVG\'s', async () => {
    const { body } = await renderExport(QR, FRAMED, QRAUTH_LOGO_PNG, { format: 'svg', print: { sizeMm: 40 } });
    const svg = body.toString('utf8');
    expect(svg).toMatch(/ width="40mm" height="[\d.]+mm"/);
    const plain = renderStyled({ data: buildVerificationUrl(QR.token), style: FRAMED, logoPng: QRAUTH_LOGO_PNG, issuerVerified: false }).svg;
    expect(svg.replace(/ width="[^"]+" height="[^"]+"/, '')).toBe(plain);
  });
});

describe('print PNG raster', () => {
  it('writes the dpi into pHYs and keeps the aspect ratio of a framed artwork', async () => {
    const result = await renderExport(QR, FRAMED, QRAUTH_LOGO_PNG, { format: 'png', print: { sizeMm: 50, dpi: 600 } });
    const meta = await sharp(result.body).metadata();
    const art = artworkSize(QR, FRAMED);
    expect(result.px).toBe(1181);
    expect([meta.width, meta.density]).toEqual([1181, 600]);
    expect(meta.height).toBe(Math.round((1181 * art.height) / art.width));
  });

  it('rasters above LARGE_RASTER_PIXELS wait for the single large slot first; smaller ones do not', async () => {
    const side = Math.ceil(Math.sqrt(LARGE_RASTER_PIXELS)) + 8;
    const large = renderStyled({ data: buildVerificationUrl(QR.token), style: DEFAULT_STYLE, size: { value: side, unit: 'px' } }).svg;
    const small = renderStyled({ data: buildVerificationUrl(QR.token), style: DEFAULT_STYLE, size: { value: 1000, unit: 'px' } }).svg;
    const spy = vi.spyOn(largeRasterLimiter, 'run');
    try {
      await rasterisePng(small, {}, 300);
      expect(spy).not.toHaveBeenCalled();
      const png = await rasterisePng(large, { lane: 'export' }, 300);
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy.mock.calls[0][1]).toMatchObject({ lane: 'export' });
      expect((await sharp(png).metadata()).width).toBe(side);
    } finally {
      spy.mockRestore();
    }
  });
});

describe('vector PDF', () => {
  it('the code is vector: no image without a logo, only the logo image with one', async () => {
    const plain = await renderExport(QR, DEFAULT_STYLE, null, { format: 'pdf', print: { sizeMm: 50 } });
    expect(plain.body.toString('latin1')).not.toContain('/Subtype /Image');

    const logo = await renderExport(QR, FRAMED, QRAUTH_LOGO_PNG, { format: 'pdf', print: { sizeMm: 50 } });
    const text = logo.body.toString('latin1');
    // The 512 x 512 logo and its soft mask (alpha) are the only images.
    const images = [...text.matchAll(/\/Subtype \/Image[^]*?\/Width (\d+)[^]*?\/Height (\d+)/g)].map((m) => `${m[1]}x${m[2]}`);
    expect(images.length).toBeGreaterThan(0);
    expect(new Set(images)).toEqual(new Set(['512x512']));
  });

  it('draws one filled path per draw-list path, in the draw list\'s colours, with no fonts', async () => {
    const { drawList } = renderStyled({ data: buildVerificationUrl(QR.token), style: FRAMED, logoPng: QRAUTH_LOGO_PNG, issuerVerified: false });
    const { body } = await renderExport(QR, FRAMED, QRAUTH_LOGO_PNG, { format: 'pdf', print: { sizeMm: 50 } });
    const content = contentStreams(body).join('\n');
    const paths = drawList.items.filter((it) => it.kind === 'path' && it.d !== '');
    const fills = content.match(/^f\*?$/gm) ?? [];
    expect(fills.length).toBe(paths.length);
    expect(body.toString('latin1')).not.toContain('/Font');
    // Black frame and modules, white text: both as DeviceRGB fills.
    expect(content).toMatch(/^0 0 0 scn$/m);
    expect(content).toMatch(/^1 1 1 scn$/m);
  });

  it('a PDF is rendered through the PNG queue', async () => {
    const spy = vi.spyOn(pngLimiter, 'run');
    try {
      await renderExport(QR, LOGO_STYLE, QRAUTH_LOGO_PNG, { format: 'pdf', print: { sizeMm: 50 } }, { lane: 'export' });
      expect(spy.mock.calls[0][1]).toMatchObject({ lane: 'export' });
    } finally {
      spy.mockRestore();
    }
  });

  it('is byte-identical for equal inputs and differs with the token', async () => {
    const opts = { format: 'pdf', print: { sizeMm: 30, marginMm: 3 } } as const;
    const a = await renderExport(QR, FRAMED, QRAUTH_LOGO_PNG, opts);
    const b = await renderExport(QR, FRAMED, QRAUTH_LOGO_PNG, opts);
    expect(a.body.equals(b.body)).toBe(true);
    const other = await renderExport({ ...QR, token: 'zZ9yY8xX' }, FRAMED, QRAUTH_LOGO_PNG, opts);
    expect(other.body.equals(a.body)).toBe(false);
  });
});
