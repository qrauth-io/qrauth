// SPDX-License-Identifier: MIT
import { describe, expect, it } from 'vitest';

import { artworkSize, DEFAULT_STYLE, renderQr, type QrStyleV2 } from '../index.js';
import {
  inchesToMm,
  maxPrintWidthMm,
  minPrintWidthMm,
  mmToPoints,
  moduleSizeRefusal,
  PRINT_RASTER_PIXELS_MAX,
  PRINT_RASTER_SIDE_MAX,
  printPxWidth,
  printRasterOrRefusal,
  roundMm,
  type ArtworkModules,
  type PrintSizeRefusal,
} from '../print.js';

/** A version 4 code with a 4-module quiet zone: 41 x 41 modules. */
const SQUARE: ArtworkModules = { width: 41, height: 41 };
/** A framed artwork, taller than wide. */
const FRAMED: ArtworkModules = { width: 43, height: 55 };

function refusal(result: ReturnType<typeof printRasterOrRefusal>): PrintSizeRefusal {
  if (!('refusal' in result)) throw new Error('expected a refusal');
  return result.refusal;
}

function raster(result: ReturnType<typeof printRasterOrRefusal>): { width: number; height: number } {
  if ('refusal' in result) throw new Error(result.refusal.message);
  return result;
}

describe('print size arithmetic', () => {
  it('px = round(size_mm / 25.4 x dpi) (ADR-0005 D7: 30 mm at 300 dpi is 354 px)', () => {
    expect(printPxWidth(30, 300)).toBe(354);
    expect(printPxWidth(50, 300)).toBe(591);
    expect(printPxWidth(100, 600)).toBe(2362);
  });

  it('mm are kept to 0.1 mm; inches convert through 25.4', () => {
    expect(roundMm(30.04)).toBe(30);
    expect(roundMm(30.05)).toBe(30.1);
    expect(inchesToMm(2)).toBe(50.8);
    expect(inchesToMm(1)).toBe(25.4);
  });

  it('PDF points are 1/72 in', () => {
    expect(mmToPoints(25.4)).toBe(72);
  });

  it('artworkSize is the renderer\'s artwork, frame included', () => {
    const data = 'https://qrauth.io/v/aB3dE5gH';
    const framed: QrStyleV2 = { ...DEFAULT_STYLE, frame: { template: 'badge', text: '', color: '#000000', textColor: '#FFFFFF' } };
    for (const style of [DEFAULT_STYLE, framed, { ...DEFAULT_STYLE, logo: { kind: 'qrauth' } } as QrStyleV2]) {
      const { meta } = renderQr({ data, style });
      expect(artworkSize(data, style)).toEqual({ width: meta.width, height: meta.height });
    }
  });
});

describe('minimum module size (0.4 mm)', () => {
  it('a 41-module artwork needs at least 16.4 mm', () => {
    expect(minPrintWidthMm(SQUARE)).toBe(16.4);
    expect(moduleSizeRefusal(16.4, SQUARE)).toBeNull();
    const r = moduleSizeRefusal(16.3, SQUARE)!;
    expect([r.status, r.code]).toEqual([422, 'print-size-too-small']);
    expect(r.message).toContain('needs at least 16.4 mm');
  });

  it('a print PNG under 3 px per module is refused with the dpi it needs', () => {
    const r = refusal(printRasterOrRefusal(20, 72, SQUARE));
    expect(r.status).toBe(422);
    expect(r.message).toMatch(/use at least 157 dpi/);
    expect(raster(printRasterOrRefusal(20, 157, SQUARE)).width).toBe(124);
  });
});

describe('raster caps', () => {
  it('12,000 px per side and 100 megapixels', () => {
    expect([PRINT_RASTER_SIDE_MAX, PRINT_RASTER_PIXELS_MAX]).toEqual([12_000, 100_000_000]);
  });

  it('the largest square render is within the caps; one more step is refused with the maximum', () => {
    const max = maxPrintWidthMm(SQUARE, 1200);
    const { width, height } = raster(printRasterOrRefusal(max, 1200, SQUARE));
    expect(width * height).toBeLessThanOrEqual(PRINT_RASTER_PIXELS_MAX);
    const r = refusal(printRasterOrRefusal(max + 0.1, 1200, SQUARE));
    expect([r.status, r.code]).toEqual([400, 'print-raster-too-large']);
    expect(r.message).toContain('the maximum is 12,000 px per side and 100 megapixels');
    expect(r.message).toContain(`at most ${max} mm wide`);
  });

  it('a framed artwork is checked on its height too', () => {
    const max = maxPrintWidthMm(FRAMED, 300);
    const { width, height } = raster(printRasterOrRefusal(max, 300, FRAMED));
    expect(height).toBeGreaterThan(width);
    expect(height).toBeLessThanOrEqual(PRINT_RASTER_SIDE_MAX);
    expect(width * height).toBeLessThanOrEqual(PRINT_RASTER_PIXELS_MAX);
    expect('refusal' in printRasterOrRefusal(max + 0.1, 300, FRAMED)).toBe(true);
  });

  it('1000 mm fits at 72 dpi; at 300 dpi the pixel cap allows 846.6 mm', () => {
    expect(maxPrintWidthMm(SQUARE, 72)).toBe(1000);
    expect(maxPrintWidthMm(SQUARE, 300)).toBe(846.6);
    expect(maxPrintWidthMm(SQUARE, 600)).toBe(423.3);
    expect(maxPrintWidthMm(SQUARE, 1200)).toBe(211.6);
  });
});
