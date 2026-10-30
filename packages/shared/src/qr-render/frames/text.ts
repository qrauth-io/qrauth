// SPDX-License-Identifier: MIT
import { fmt } from '../format.js';
import type { FrameFont, GlyphCommand } from './font.js';
import type { TextBox } from './layout.js';

/** Outlined text: path data in module units, and the ink's horizontal extent. */
export interface OutlinedText {
  readonly d: string;
  /** Font size (em) used, in modules. */
  readonly size: number;
  readonly x: number;
  readonly width: number;
  readonly baseline: number;
}

function commandPath(c: GlyphCommand, X: (x: number) => string, Y: (y: number) => string): string {
  switch (c.type) {
    case 'M':
    case 'L':
      return `${c.type}${X(c.x)} ${Y(c.y)}`;
    case 'Q':
      return `Q${X(c.x1)} ${Y(c.y1)} ${X(c.x)} ${Y(c.y)}`;
    case 'C':
      return `C${X(c.x1)} ${Y(c.y1)} ${X(c.x2)} ${Y(c.y2)} ${X(c.x)} ${Y(c.y)}`;
    case 'Z':
      return 'Z';
  }
}

/**
 * Outlines `text` as one line centred in `box`: glyph outlines from `font`
 * with advance widths (no kerning or shaping), scaled so capitals are
 * `box.cap` high, or smaller when the line would be wider than the box.
 * Every coordinate goes through `fmt`, so the path is byte-stable.
 */
export function outlineText(text: string, box: TextBox, font: FrameFont): OutlinedText | null {
  const glyphs = Array.from(text, (ch) => font.glyph(ch.codePointAt(0) as number));
  const advance = glyphs.reduce((sum, g) => sum + g.advance, 0);
  if (glyphs.length === 0 || advance <= 0) return null;

  const upm = font.unitsPerEm;
  const sizeForCap = (box.cap * upm) / font.capHeight;
  const sizeForWidth = (box.width * upm) / advance;
  const size = Math.min(sizeForCap, sizeForWidth);
  const k = size / upm;
  const width = advance * k;
  const x0 = box.x + (box.width - width) / 2;
  const baseline = box.y + box.height / 2 + (font.capHeight * k) / 2;

  let d = '';
  let pen = x0;
  for (const g of glyphs) {
    const at = pen;
    const X = (x: number): string => fmt(at + x * k);
    const Y = (y: number): string => fmt(baseline - y * k);
    for (const c of g.commands) d += commandPath(c, X, Y);
    pen += g.advance * k;
  }
  return { d, size, x: x0, width, baseline };
}
