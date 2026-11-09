// SPDX-License-Identifier: MIT

/**
 * Code points the bundled frame font draws (assets/fonts/
 * NotoSans-SemiBold-frames.ttf), as inclusive ranges. This is the font's
 * cmap: Latin (Basic, Latin-1 Supplement, Extended-A), Greek, Cyrillic and
 * common punctuation, without combining marks (text is drawn unshaped).
 * A test checks it against the font; regenerate after rebuilding the font
 * (scripts/subset-frame-font.sh):
 *   UPDATE_FONT_COVERAGE=1 npm test -w packages/shared -- font-coverage
 */
export const FRAME_FONT_COVERAGE: readonly (readonly [number, number])[] = [
  // @generated-coverage-start
  [0x0020, 0x007e],
  [0x00a0, 0x00ac],
  [0x00ae, 0x017f],
  [0x0370, 0x0377],
  [0x037a, 0x037f],
  [0x0384, 0x038a],
  [0x038c, 0x038c],
  [0x038e, 0x03a1],
  [0x03a3, 0x03e1],
  [0x03f0, 0x0482],
  [0x048a, 0x04ff],
  [0x2013, 0x2014],
  [0x2018, 0x201a],
  [0x201c, 0x201e],
  [0x2022, 0x2022],
  [0x2026, 0x2026],
  [0x2039, 0x203a],
  [0x20ac, 0x20ac],
  [0x2122, 0x2122],
  // @generated-coverage-end
];

/** True when the bundled frame font has a glyph for `codePoint`. */
export function isFrameCodePointSupported(codePoint: number): boolean {
  let lo = 0;
  let hi = FRAME_FONT_COVERAGE.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const [start, end] = FRAME_FONT_COVERAGE[mid];
    if (codePoint < start) hi = mid - 1;
    else if (codePoint > end) lo = mid + 1;
    else return true;
  }
  return false;
}

/** The distinct characters of `text` the frame font cannot draw, in order of appearance. */
export function unsupportedFrameChars(text: string): string[] {
  const out: string[] = [];
  for (const ch of text) {
    if (!isFrameCodePointSupported(ch.codePointAt(0) as number) && !out.includes(ch)) out.push(ch);
  }
  return out;
}

/** True when every character of `text` has a glyph in the bundled frame font. */
export function isFrameTextSupported(text: string): boolean {
  return unsupportedFrameChars(text).length === 0;
}
