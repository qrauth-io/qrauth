// SPDX-License-Identifier: MIT
import ECCode from 'qrcode/lib/core/error-correction-code.js';
import ECLevel from 'qrcode/lib/core/error-correction-level.js';
import Utils from 'qrcode/lib/core/utils.js';

import type { QrMatrix } from './matrix.js';

/**
 * Share of each Reed–Solomon block's correction capacity a centred logo may
 * use (ADR-0005 D4.4). The rest is left for print, wear and camera defects.
 */
export const LOGO_EC_BUDGET = 0.625;

/** From version 7 on an alignment pattern sits at the symbol centre (D4.4). */
export const MAX_LOGO_VERSION = 6;

/** A centred square of whole modules: columns and rows [start, start + side). */
export interface CentredSquare {
  readonly start: number;
  readonly side: number;
}

/** The centred square of `side` modules in a symbol of `size` modules. */
export function centredSquare(size: number, side: number): CentredSquare {
  return { start: Math.floor((size - side) / 2), side };
}

/**
 * For every module, the index of the codeword whose bit it carries, or -1 for
 * function-pattern modules and remainder bits. Re-implements the ISO/IEC
 * 18004 placement order (two-column zigzag from the bottom-right, skipping
 * the vertical timing column) against the encoder's reserved-module mask.
 */
export function codewordMap(matrix: QrMatrix): Int32Array {
  const { size, fn } = matrix;
  const totalCodewords = Utils.getSymbolTotalCodewords(matrix.version);
  const map = new Int32Array(size * size).fill(-1);
  let bit = 0;
  let row = size - 1;
  let inc = -1;
  for (let col = size - 1; col > 0; col -= 2) {
    if (col === 6) col--;
    for (;;) {
      for (let c = 0; c < 2; c++) {
        const idx = row * size + (col - c);
        if (!fn[idx]) {
          const codeword = bit >> 3;
          if (codeword < totalCodewords) map[idx] = codeword;
          bit++;
        }
      }
      row += inc;
      if (row < 0 || row >= size) {
        row -= inc;
        inc = -inc;
        break;
      }
    }
  }
  return map;
}

export interface BlockLayout {
  /** Block index for each interleaved codeword position. */
  readonly blockOf: Int32Array;
  readonly blocks: number;
  readonly ecPerBlock: number;
}

/** Codeword-to-block map for the interleaving used by the encoder. */
export function blockLayout(matrix: QrMatrix): BlockLayout {
  const level = ECLevel[matrix.ecLevel];
  const total = Utils.getSymbolTotalCodewords(matrix.version);
  const ecTotal = ECCode.getTotalCodewordsCount(matrix.version, level);
  const blocks = ECCode.getBlocksCount(matrix.version, level);
  const dataTotal = total - ecTotal;
  const group2 = total % blocks;
  const group1 = blocks - group2;
  const dataG1 = Math.floor(dataTotal / blocks);
  const ecPerBlock = Math.floor(total / blocks) - dataG1;
  const dataLen = (b: number): number => (b < group1 ? dataG1 : dataG1 + 1);

  const blockOf = new Int32Array(total);
  let index = 0;
  for (let i = 0; i <= dataG1; i++) {
    for (let b = 0; b < blocks; b++) {
      if (i < dataLen(b)) blockOf[index++] = b;
    }
  }
  for (let i = 0; i < ecPerBlock; i++) {
    for (let b = 0; b < blocks; b++) blockOf[index++] = b;
  }
  return { blockOf, blocks, ecPerBlock };
}

/**
 * Largest side `s` (in modules, logo plus its one-module excavated border) of
 * a centred square that (a) covers no function-pattern module and (b) touches,
 * in every block, at most `budget x floor(ecPerBlock / 2)` codewords. Any
 * touched codeword is counted as an error, which is conservative. Returns 0
 * when no logo fits, which is always the case above MAX_LOGO_VERSION.
 */
export function maxLogoModules(matrix: QrMatrix, budget: number = LOGO_EC_BUDGET): number {
  if (matrix.version > MAX_LOGO_VERSION) return 0;
  if (!(budget > 0 && budget <= 1)) throw new Error('qr-render: budget must be in (0, 1]');
  const { size, fn } = matrix;
  const map = codewordMap(matrix);
  const { blockOf, blocks, ecPerBlock } = blockLayout(matrix);
  const limit = budget * Math.floor(ecPerBlock / 2);

  let best = 0;
  for (let side = 1; side <= size; side++) {
    const { start } = centredSquare(size, side);
    const touched = new Set<number>();
    let ok = true;
    for (let r = start; r < start + side && ok; r++) {
      for (let c = start; c < start + side; c++) {
        const idx = r * size + c;
        if (fn[idx]) {
          ok = false;
          break;
        }
        if (map[idx] >= 0) touched.add(map[idx]);
      }
    }
    if (!ok) break;
    const perBlock = new Array<number>(blocks).fill(0);
    for (const cw of touched) perBlock[blockOf[cw]]++;
    if (perBlock.some((n) => n > limit)) break;
    best = side;
  }
  // A logo needs at least one module inside its one-module border.
  return best >= 3 ? best : 0;
}

/** Excavated square for a logo at `scale` (0.5..1) of the cap `cap`. */
export function logoExcavation(size: number, cap: number, scale: number): CentredSquare | null {
  if (cap < 3) return null;
  const clamped = Math.min(1, Math.max(0.5, scale));
  const logoSide = (cap - 2) * clamped;
  const side = Math.min(cap, Math.ceil(logoSide - 1e-9) + 2);
  return centredSquare(size, side);
}

/** Largest logo the renderer embeds: 1 MiB (ADR-0005 D9 upload limit). */
export const LOGO_PNG_MAX_BYTES = 1024 * 1024;

const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] as const;

/** Throws unless `bytes` starts with the PNG signature and is at most LOGO_PNG_MAX_BYTES. */
export function assertLogoPng(bytes: unknown): asserts bytes is Uint8Array {
  // Tag check rather than instanceof, so typed arrays from another realm
  // (a test DOM, a worker) are accepted. Buffer reports Uint8Array too.
  if (Object.prototype.toString.call(bytes) !== '[object Uint8Array]') {
    throw new Error('qr-render: logoPng must be a Uint8Array');
  }
  const png = bytes as Uint8Array;
  if (png.length > LOGO_PNG_MAX_BYTES) {
    throw new Error(`qr-render: logoPng is larger than ${LOGO_PNG_MAX_BYTES} bytes`);
  }
  if (png.length < PNG_SIGNATURE.length || PNG_SIGNATURE.some((b, i) => png[i] !== b)) {
    throw new Error('qr-render: logoPng is not a PNG');
  }
}
