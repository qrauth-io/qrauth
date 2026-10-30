// SPDX-License-Identifier: MIT
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'opentype.js/dist/opentype.mjs';
import { describe, expect, it } from 'vitest';

import { FRAME_FONT_ASSET, FRAME_FONT_MAX_BYTES, loadFrameFont } from '../font.js';
import { FRAME_FONT_COVERAGE, isFrameTextSupported, unsupportedFrameChars } from '../frames/coverage.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const SHARED = join(HERE, '..', '..', '..');
const FONT_BYTES = new Uint8Array(readFileSync(join(SHARED, FRAME_FONT_ASSET)));
const COVERAGE_FILE = join(HERE, '..', 'frames', 'coverage.ts');

/**
 * sha256 of the committed subset (scripts/subset-frame-font.sh prints it).
 * A change here is a font change: golden files and ETags change with it.
 */
const FONT_SHA256 = 'a7ccaa401841aeca0494433e2c3801786415e8e3b08f00f9feabfb0ac57bd64a';

function cmapRanges(): [number, number][] {
  const font = parse(FONT_BYTES.slice().buffer as ArrayBuffer) as unknown as {
    tables: { cmap: { glyphIndexMap: Record<string, number> } };
  };
  const points = Object.keys(font.tables.cmap.glyphIndexMap)
    .map(Number)
    .sort((a, b) => a - b);
  const ranges: [number, number][] = [];
  for (const cp of points) {
    const last = ranges[ranges.length - 1];
    if (last && last[1] === cp - 1) last[1] = cp;
    else ranges.push([cp, cp]);
  }
  return ranges;
}

const hex = (n: number): string => `0x${n.toString(16).padStart(4, '0')}`;

describe('bundled frame font', () => {
  it('is the committed subset', () => {
    expect(createHash('sha256').update(FONT_BYTES).digest('hex')).toBe(FONT_SHA256);
    expect(FONT_BYTES.length).toBeLessThan(FRAME_FONT_MAX_BYTES);
  });

  it('ships with its SIL OFL 1.1 licence', () => {
    const ofl = readFileSync(join(SHARED, 'assets', 'fonts', 'OFL.txt'), 'utf8');
    expect(ofl).toContain('SIL OPEN FONT LICENSE Version 1.1');
    expect(ofl).toContain('The Noto Project Authors');
  });

  it('FRAME_FONT_COVERAGE is the font cmap', () => {
    const ranges = cmapRanges();
    if (process.env.UPDATE_FONT_COVERAGE === '1') {
      const body = ranges.map(([a, z]) => `  [${hex(a)}, ${hex(z)}],`).join('\n');
      const src = readFileSync(COVERAGE_FILE, 'utf8').replace(
        /(\/\/ @generated-coverage-start\n)[\s\S]*?(\n\s*\/\/ @generated-coverage-end)/,
        `$1${body}$2`,
      );
      writeFileSync(COVERAGE_FILE, src);
      return;
    }
    expect(FRAME_FONT_COVERAGE.map(([a, z]) => [a, z])).toEqual(ranges);
  });

  it('covers Latin, Greek and Cyrillic and leaves out combining marks', () => {
    expect(isFrameTextSupported('Scan me! Ça coûte 5 € — “now”…')).toBe(true);
    expect(isFrameTextSupported('Σαρώστε με ΆΈΉΊΌΎΏ ϊΰ')).toBe(true);
    expect(isFrameTextSupported('Сканируйте меня ЁЇЄҐ')).toBe(true);
    expect(isFrameTextSupported('Łódź Šťastný Ğüçlü')).toBe(true);
    expect(unsupportedFrameChars('á')).toEqual(['́']);
    expect(unsupportedFrameChars('日本語 OK 日')).toEqual(['日', '本', '語']);
    expect(unsupportedFrameChars('emoji 🙂')).toEqual(['🙂']);
    expect(unsupportedFrameChars('مرحبا')).toHaveLength(5);
    expect(isFrameTextSupported('­')).toBe(false);
  });

  it('every covered code point has a real glyph and an advance', () => {
    const font = loadFrameFont(FONT_BYTES);
    let count = 0;
    for (const [a, z] of FRAME_FONT_COVERAGE) {
      for (let cp = a; cp <= z; cp++) {
        const g = font.glyph(cp);
        expect(g.advance, hex(cp)).toBeGreaterThan(0);
        if (cp !== 0x20 && cp !== 0xa0) expect(g.commands.length, hex(cp)).toBeGreaterThan(0);
        count++;
      }
    }
    expect(count).toBe(702);
  });
});

describe('loadFrameFont', () => {
  it('rejects anything that is not a TrueType font of bounded size', () => {
    expect(() => loadFrameFont(new Uint8Array(4))).toThrow(/TrueType/);
    const png = readFileSync(join(SHARED, 'assets', 'qrauth-logo.png'));
    expect(() => loadFrameFont(new Uint8Array(png))).toThrow(/TrueType/);
    const big = new Uint8Array(FRAME_FONT_MAX_BYTES + 1);
    big.set(FONT_BYTES.subarray(0, 4));
    expect(() => loadFrameFont(big)).toThrow(/at most/);
  });

  it('gives .notdef for a code point outside the font', () => {
    const font = loadFrameFont(FONT_BYTES);
    expect(font.glyph(0x65e5).commands.length).toBeGreaterThan(0);
    expect(font.glyph(0x65e5)).toEqual(font.glyph(0x672c));
    expect(font.unitsPerEm).toBe(1000);
    expect(font.capHeight).toBe(714);
  });
});
