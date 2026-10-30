// SPDX-License-Identifier: MIT
import { describe, expect, it } from 'vitest';
import ECCode from 'qrcode/lib/core/error-correction-code.js';
import ECLevel from 'qrcode/lib/core/error-correction-level.js';
import Utils from 'qrcode/lib/core/utils.js';

import { encode } from '../matrix.js';
import { blockLayout, codewordMap, logoExcavation, maxLogoModules } from '../logo.js';

/** A production-shaped verify URL of exactly `length` characters. */
function verifyUrl(length: number): string {
  const prefix = 'https://qrauth.io/v/';
  return prefix + 'aB3dE5gH9kLmNpQrStUvWxYz0123456789abcdefghijk'.slice(0, length - prefix.length);
}

describe('logo cap simulation (ADR-0005 D4.4)', () => {
  // The table in D4.4: URL length -> version, size, cap at budget 0.5 / 0.625 / 1.0.
  const table = [
    { length: 28, version: 4, size: 33, caps: [7, 10, 13] },
    { length: 40, version: 5, size: 37, caps: [10, 11, 15] },
    { length: 55, version: 6, size: 41, caps: [13, 13, 18] },
  ];

  for (const row of table) {
    it(`reproduces the ADR table for a ${row.length}-character URL`, () => {
      const matrix = encode(verifyUrl(row.length), 'H');
      expect(matrix.version).toBe(row.version);
      expect(matrix.size).toBe(row.size);
      expect([0.5, 0.625, 1].map((b) => maxLogoModules(matrix, b))).toEqual(row.caps);
    });
  }

  it('maps exactly 8 modules to every codeword', () => {
    for (const length of [28, 40, 55]) {
      const matrix = encode(verifyUrl(length), 'H');
      const map = codewordMap(matrix);
      const counts = new Map<number, number>();
      for (const cw of map) if (cw >= 0) counts.set(cw, (counts.get(cw) ?? 0) + 1);
      const total = Utils.getSymbolTotalCodewords(matrix.version);
      expect(counts.size).toBe(total);
      expect([...counts.values()].every((n) => n === 8)).toBe(true);
    }
  });

  /** Data and EC codewords per block, read back from the interleaved block map. */
  function splitPerBlock(matrix: ReturnType<typeof encode>): { data: number[]; ec: number[] } {
    const { blockOf, blocks } = blockLayout(matrix);
    const total = Utils.getSymbolTotalCodewords(matrix.version);
    const ecTotal = ECCode.getTotalCodewordsCount(matrix.version, ECLevel[matrix.ecLevel]);
    const data = new Array<number>(blocks).fill(0);
    const ec = new Array<number>(blocks).fill(0);
    blockOf.forEach((b, i) => {
      if (i < total - ecTotal) data[b]++;
      else ec[b]++;
    });
    return { data, ec };
  }

  // ISO/IEC 18004 Table 9 at EC level H for the versions in the D4.4 table:
  // data codewords per block (group 1 then group 2) and EC codewords per block.
  const ISO_H = [
    { length: 28, version: 4, data: [9, 9, 9, 9], ec: 16 },
    { length: 40, version: 5, data: [11, 11, 12, 12], ec: 22 },
    { length: 55, version: 6, data: [15, 15, 15, 15], ec: 28 },
  ];

  for (const row of ISO_H) {
    it(`splits version ${row.version}-H into the ISO 18004 data/EC blocks`, () => {
      const matrix = encode(verifyUrl(row.length), 'H');
      expect(matrix.version).toBe(row.version);
      const { data, ec } = splitPerBlock(matrix);
      expect(data).toEqual(row.data);
      expect(ec).toEqual(row.data.map(() => row.ec));
      expect(blockLayout(matrix).ecPerBlock).toBe(row.ec);
    });
  }

  it("matches qrcode's EC tables for every block at versions 1-6, levels M, Q and H", () => {
    // Grow the text one character at a time, so every version is reached.
    let tested = 0;
    for (const level of ['M', 'Q', 'H'] as const) {
      for (let version = 1; version <= 6; version++) {
        let length = 1;
        let matrix = encode('A'.repeat(length), level);
        while (matrix.version < version) matrix = encode('A'.repeat(++length), level);
        expect(matrix.version).toBe(version);
        tested++;
        const total = Utils.getSymbolTotalCodewords(version);
        const blocks = ECCode.getBlocksCount(version, ECLevel[level]);
        const ecTotal = ECCode.getTotalCodewordsCount(version, ECLevel[level]);
        const { data, ec } = splitPerBlock(matrix);
        const label = `${version}-${level}`;
        expect(data.length, label).toBe(blocks);
        expect(ec, label).toEqual(new Array<number>(blocks).fill(ecTotal / blocks));
        expect(data.reduce((a, b) => a + b, 0), label).toBe(total - ecTotal);
        // Two groups: group 2 blocks carry one data codeword more, and come last.
        const shortest = Math.min(...data);
        expect(data.every((d) => d === shortest || d === shortest + 1), label).toBe(true);
        expect([...data].sort((a, b) => a - b), label).toEqual(data);
      }
    }
    expect(tested).toBe(18);
  });

  it('allows no logo above version 6', () => {
    const matrix = encode(`https://qrauth.io/v/${'x'.repeat(80)}`, 'H');
    expect(matrix.version).toBeGreaterThan(6);
    expect(maxLogoModules(matrix)).toBe(0);
  });

  it('never lets the scale enlarge the excavation past the cap', () => {
    expect(logoExcavation(33, 10, 1)).toEqual({ start: 11, side: 10 });
    expect(logoExcavation(33, 10, 2)).toEqual({ start: 11, side: 10 });
    expect(logoExcavation(33, 10, 0.5)).toEqual({ start: 13, side: 6 });
    expect(logoExcavation(33, 0, 1)).toBeNull();
  });
});
