// SPDX-License-Identifier: MIT
/**
 * `@qrauth/shared/qr-render/font`: parses the bundled frame font into the
 * `FrameFont` the renderer outlines frame text with (ADR-0005 PR 5). A
 * separate entry so the font parser (opentype.js, MIT) is only bundled where
 * frames are drawn; the dashboard loads it on demand. The font bytes are
 * `@qrauth/shared/assets/fonts/NotoSans-SemiBold-frames.ttf` (SIL OFL 1.1,
 * licence alongside), read from disk by the API and fetched same-origin by
 * the dashboard. Fonts are never fetched from a third-party host.
 */
import { parse, type Glyph, type PathCommand } from 'opentype.js/dist/opentype.mjs';

import type { FrameFont, FrameGlyph, GlyphCommand } from './frames/font.js';

export type { FrameFont, FrameGlyph, GlyphCommand } from './frames/font.js';

/** Published path of the bundled frame font inside @qrauth/shared. */
export const FRAME_FONT_ASSET = 'assets/fonts/NotoSans-SemiBold-frames.ttf';

/** Upper bound on font bytes accepted by loadFrameFont; the bundled subset is about 52 KB. */
export const FRAME_FONT_MAX_BYTES = 512 * 1024;

const TRUETYPE_SIGNATURE = 0x00010000;

function num(value: number | undefined): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) throw new Error('qr-render: malformed glyph outline');
  return value;
}

function toCommand(c: PathCommand): GlyphCommand {
  switch (c.type) {
    case 'M':
    case 'L':
      return { type: c.type, x: num(c.x), y: num(c.y) };
    case 'Q':
      return { type: 'Q', x1: num(c.x1), y1: num(c.y1), x: num(c.x), y: num(c.y) };
    case 'C':
      return { type: 'C', x1: num(c.x1), y1: num(c.y1), x2: num(c.x2), y2: num(c.y2), x: num(c.x), y: num(c.y) };
    case 'Z':
      return { type: 'Z' };
    default:
      throw new Error('qr-render: unknown glyph outline command');
  }
}

function toFrameGlyph(glyph: Glyph): FrameGlyph {
  return { advance: num(glyph.advanceWidth ?? 0), commands: glyph.path.commands.map(toCommand) };
}

/**
 * Parses TrueType font bytes into a FrameFont. Equal bytes give equal
 * glyphs in Node and in browsers: TrueType outlines are integer points (and
 * midpoints of them), and the renderer formats every coordinate with one
 * fixed-precision formatter. Glyphs are converted once per code point and
 * cached. Throws for anything that is not a TrueType font of at most
 * FRAME_FONT_MAX_BYTES.
 */
export function loadFrameFont(bytes: Uint8Array): FrameFont {
  if (!(bytes instanceof Uint8Array) || bytes.length < 12 || bytes.length > FRAME_FONT_MAX_BYTES) {
    throw new Error(`qr-render: font must be a TrueType font of at most ${FRAME_FONT_MAX_BYTES} bytes`);
  }
  const signature = ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
  if (signature !== TRUETYPE_SIGNATURE) throw new Error('qr-render: font must be a TrueType (glyf) font');

  const copy = bytes.slice();
  const font = parse(copy.buffer as ArrayBuffer);
  const capHeight = font.tables.os2?.sCapHeight;
  if (!(font.unitsPerEm > 0) || typeof capHeight !== 'number' || !(capHeight > 0)) {
    throw new Error('qr-render: font has no units per em or cap height');
  }

  const cache = new Map<number, FrameGlyph>();
  return {
    unitsPerEm: font.unitsPerEm,
    capHeight,
    glyph(codePoint: number): FrameGlyph {
      let glyph = cache.get(codePoint);
      if (!glyph) {
        glyph = toFrameGlyph(font.charToGlyph(String.fromCodePoint(codePoint)));
        cache.set(codePoint, glyph);
      }
      return glyph;
    },
  };
}
