// SPDX-License-Identifier: MIT

/**
 * One outline command in font units, y up, as the TrueType outline gives it.
 * `Q` is a quadratic and `C` a cubic Bézier segment.
 */
export type GlyphCommand =
  | { readonly type: 'M' | 'L'; readonly x: number; readonly y: number }
  | { readonly type: 'Q'; readonly x1: number; readonly y1: number; readonly x: number; readonly y: number }
  | {
      readonly type: 'C';
      readonly x1: number;
      readonly y1: number;
      readonly x2: number;
      readonly y2: number;
      readonly x: number;
      readonly y: number;
    }
  | { readonly type: 'Z' };

export interface FrameGlyph {
  /** Advance width in font units. */
  readonly advance: number;
  readonly commands: readonly GlyphCommand[];
}

/**
 * The parsed frame font the renderer outlines text with. Made by
 * `loadFrameFont` (`@qrauth/shared/qr-render/font`) from the bundled font
 * bytes, so the dashboard and the API draw the same glyphs. The renderer
 * itself never parses a font, which keeps the parser out of bundles that do
 * not draw frames.
 */
export interface FrameFont {
  readonly unitsPerEm: number;
  /** Height of capital letters in font units (OS/2 sCapHeight). */
  readonly capHeight: number;
  /** The glyph for a code point; the font's .notdef glyph when it has none. */
  glyph(codePoint: number): FrameGlyph;
}
