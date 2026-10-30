// SPDX-License-Identifier: MIT
// Minimal typings for the parts of opentype.js 2.0.0 (MIT) the frame font
// loader uses. The package ships no declarations; the ESM build is imported
// by path because the package has no `exports` map and its `main` is a UMD
// bundle without named exports.
declare module 'opentype.js/dist/opentype.mjs' {
  export interface PathCommand {
    readonly type: 'M' | 'L' | 'Q' | 'C' | 'Z';
    readonly x?: number;
    readonly y?: number;
    readonly x1?: number;
    readonly y1?: number;
    readonly x2?: number;
    readonly y2?: number;
  }
  export interface Glyph {
    readonly index: number;
    readonly advanceWidth?: number;
    readonly path: { readonly commands: readonly PathCommand[] };
  }
  export interface Font {
    readonly unitsPerEm: number;
    readonly tables: { readonly os2?: { readonly sCapHeight?: number } };
    charToGlyph(char: string): Glyph;
  }
  export function parse(buffer: ArrayBuffer, options?: { lowMemory?: boolean }): Font;
}
