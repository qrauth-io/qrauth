// SPDX-License-Identifier: MIT
import AlignmentPattern from 'qrcode/lib/core/alignment-pattern.js';
import QRCodeCore from 'qrcode/lib/core/qrcode.js';

export type EcLevel = 'M' | 'Q' | 'H';

/** The EC levels the renderer draws. L is not offered (ADR-0005 D4.3). */
export const RENDER_EC_LEVELS: readonly EcLevel[] = ['M', 'Q', 'H'];

function isEcLevel(value: unknown): value is EcLevel {
  return typeof value === 'string' && (RENDER_EC_LEVELS as readonly string[]).includes(value);
}

export interface QrMatrix {
  /** Modules per side, without quiet zone. */
  readonly size: number;
  readonly version: number;
  readonly ecLevel: EcLevel;
  /** 1 = dark module. Index is `row * size + col`. */
  readonly dark: Uint8Array;
  /**
   * 1 = function-pattern module: finder, separator, timing, alignment,
   * format and version information, and the dark module. Index as `dark`.
   */
  readonly fn: Uint8Array;
  /** Alignment pattern centres as [col, row]. */
  readonly alignment: ReadonlyArray<readonly [number, number]>;
}

/**
 * Encode `text` with the qrcode@1.5.4 core encoder. This is the only place
 * the encoder is called, so replacing it is a one-file change gated by the
 * golden files. Throws for an EC level other than M, Q or H, and when the
 * text does not fit at the requested level.
 */
export function encode(text: string, ecLevel: EcLevel): QrMatrix {
  if (typeof text !== 'string' || text.length === 0) {
    throw new Error('qr-render: data must be a non-empty string');
  }
  if (!isEcLevel(ecLevel)) {
    throw new Error(`qr-render: ecLevel must be one of ${RENDER_EC_LEVELS.join(', ')}`);
  }
  const symbol = QRCodeCore.create(text, { errorCorrectionLevel: ecLevel });
  const { size, data, reservedBit } = symbol.modules;
  return {
    size,
    version: symbol.version,
    ecLevel,
    dark: Uint8Array.from(data, (v) => (v ? 1 : 0)),
    fn: Uint8Array.from(reservedBit, (v) => (v ? 1 : 0)),
    alignment: AlignmentPattern.getPositions(symbol.version).map(([row, col]) => [col, row] as const),
  };
}

/** Top-left corners of the three 7x7 finder patterns, as [col, row]. */
export function finderOrigins(size: number): ReadonlyArray<readonly [number, number]> {
  return [
    [0, 0],
    [size - 7, 0],
    [0, size - 7],
  ];
}

/** True when (col, row) lies inside one of the three 7x7 finder patterns. */
export function inFinder(size: number, col: number, row: number): boolean {
  const left = col < 7;
  const top = row < 7;
  return (left && top) || (col >= size - 7 && top) || (left && row >= size - 7);
}
