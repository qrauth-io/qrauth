// SPDX-License-Identifier: MIT
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { FRAME_FONT_ASSET, loadFrameFont } from '../font.js';
import { frameLayout, type DrawnFrameTemplate } from '../frames/layout.js';
import { outlineText } from '../frames/text.js';
import {
  BADGE_MARK_SIGNED,
  BADGE_MARK_VERIFIED,
  badgeMark,
  checkStyle,
  DEFAULT_STYLE,
  isFrameTextSupported,
  FRAME_GLYPH_UNSUPPORTED_MESSAGE,
  FRAME_TEXT_CONTRAST_MIN,
  contrastRatio,
  renderQr,
  styleFrameLayout,
  type PathItem,
  type QrFrame,
  type QrStyleV2,
} from '../index.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const FONT = loadFrameFont(new Uint8Array(readFileSync(join(HERE, '..', '..', '..', FRAME_FONT_ASSET))));
const URL_28 = 'https://qrauth.io/v/aB3dE5gH';
const URL_55 = 'https://qrauth.io/v/aB3dE5gH9kLmNpQrStUvWxYz0123456789X';

const TEMPLATES: readonly DrawnFrameTemplate[] = ['caption', 'banner-bottom', 'banner-top', 'rounded-label', 'badge'];
/** Texts that reach every vertical extreme: accented capitals, descenders, 40 characters. */
const TEXTS = ['Scan me', 'ΆΈΉΊΌΎΏ gjpqy ÅÉÎ', 'Сканируйте меня Йй Щщ', 'W'.repeat(40), 'ÁÉÍÓÚ ÀÈÌ ąęįų ÇŞ çş jgpq ÅŻ'];

const withFrame = (template: string, text: string, extra: Partial<QrStyleV2> = {}): QrStyleV2 => ({
  ...DEFAULT_STYLE,
  ...extra,
  frame: { template: template as QrFrame['template'], text, color: '#000000', textColor: '#FFFFFF' },
});

/** Every coordinate pair in a path made of absolute M/L/Q/C/Z commands (glyph outlines). */
function points(d: string): [number, number][] {
  const nums = d.replace(/[MLQCZ]/g, ' ').trim().split(/\s+/).filter(Boolean).map(Number);
  const out: [number, number][] = [];
  for (let i = 0; i + 1 < nums.length; i += 2) out.push([nums[i], nums[i + 1]]);
  return out;
}

describe('frame layout keeps out of the quiet zone', () => {
  for (const template of TEMPLATES) {
    for (const url of [URL_28, URL_55]) {
      for (const quietZone of [4, 10]) {
        it(`${template}, ${url.length} chars, quiet zone ${quietZone}`, () => {
          for (const text of TEXTS) {
            const style = withFrame(template, text, { quietZone, logo: { kind: 'qrauth' } });
            const { drawList, meta } = renderQr({ data: url, style, font: FONT });
            const side = meta.symbolSize + 2 * quietZone;
            const layout = styleFrameLayout(style, meta.symbolSize)!;
            expect(layout).toEqual(frameLayout(template, side));
            expect([drawList.width, drawList.height]).toEqual([layout.width, layout.height]);
            const { codeX: x0, codeY: y0 } = layout;

            const items = drawList.items;
            const layers = items.map((it) => (it.kind === 'path' ? it.layer : 'image'));
            // Frame paint is first; the code's opaque background covers the
            // whole code square right after it; text comes last.
            const bgIndex = layers.indexOf('background');
            expect(layers.slice(0, bgIndex)).toEqual(template === 'caption' ? [] : ['frame']);
            expect(layers[layers.length - 1]).toBe('frame-text');
            const bg = items[bgIndex] as PathItem;
            expect(bg.d).toBe(
              template === 'caption'
                ? `M0 0h${layout.width}v${layout.height}h${-layout.width}z`
                : `M${x0} ${y0}h${side}v${side}h${-side}z`,
            );

            // Nothing after the background may paint inside the code square
            // except the code itself (modules, eyes, logo), which stays
            // within the symbol, inside the quiet zone.
            for (const it of items.slice(bgIndex + 1)) {
              if (it.kind === 'image') {
                expect(it.x).toBeGreaterThanOrEqual(x0 + quietZone);
                expect(it.x + it.width).toBeLessThanOrEqual(x0 + quietZone + meta.symbolSize);
                continue;
              }
              if (it.layer !== 'frame-text') continue;
              for (const [px, py] of points(it.d)) {
                const inside = px > x0 && px < x0 + side && py > y0 && py < y0 + side;
                expect(inside, `${text}: (${px}, ${py}) inside the code square`).toBe(false);
                expect(px).toBeGreaterThanOrEqual(0);
                expect(px).toBeLessThanOrEqual(layout.width);
                expect(py).toBeGreaterThanOrEqual(0);
                expect(py).toBeLessThanOrEqual(layout.height);
              }
            }
          }
        });
      }
    }
  }

  it('text boxes lie outside the code square for every template and size', () => {
    for (const template of TEMPLATES) {
      for (let side = 29; side <= 197; side += 4) {
        const l = frameLayout(template, side);
        expect(Number.isInteger(l.width) && Number.isInteger(l.height), `${template} ${side}`).toBe(true);
        for (const b of l.textBoxes) {
          const overlapsX = b.x < l.codeX + side && b.x + b.width > l.codeX;
          const overlapsY = b.y < l.codeY + side && b.y + b.height > l.codeY;
          expect(overlapsX && overlapsY, `${template} ${side}`).toBe(false);
        }
      }
    }
  });

  it('the artwork size does not depend on the text or the font', () => {
    for (const template of TEMPLATES) {
      const a = renderQr({ data: URL_28, style: withFrame(template, 'x'), font: FONT }).drawList;
      const b = renderQr({ data: URL_28, style: withFrame(template, 'W'.repeat(40)) }).drawList;
      expect([a.width, a.height]).toEqual([b.width, b.height]);
    }
  });

  it('a none frame draws exactly the unframed code', () => {
    const plain = renderQr({ data: URL_28, style: DEFAULT_STYLE }).svg;
    expect(renderQr({ data: URL_28, style: withFrame('none', 'ignored'), font: FONT }).svg).toBe(plain);
  });
});

describe('frame text', () => {
  it('is outlined as paths, never <text>, and fits its box', () => {
    for (const template of TEMPLATES) {
      const { svg, meta } = renderQr({ data: URL_28, style: withFrame(template, 'W'.repeat(40)), font: FONT });
      expect(svg).not.toContain('<text');
      expect(svg).not.toContain('font-family');
      expect(meta.notDrawn).toEqual([]);
    }
    const layout = frameLayout('banner-bottom', 41);
    const box = layout.textBoxes[0];
    const long = outlineText('W'.repeat(40), box, FONT)!;
    expect(long.width).toBeCloseTo(box.width, 9);
    const short = outlineText('Hi', box, FONT)!;
    expect((short.size * FONT.capHeight) / FONT.unitsPerEm).toBeCloseTo(box.cap, 9);
    expect(short.width).toBeLessThan(box.width);
  });

  it('without a font, the frame is drawn without text and reported', () => {
    const { drawList, meta } = renderQr({ data: URL_28, style: withFrame('banner-bottom', 'Scan me') });
    expect(drawList.items.some((it) => it.kind === 'path' && it.layer === 'frame-text')).toBe(false);
    expect(meta.notDrawn).toEqual(['frame']);
    // A caption without text needs no font.
    expect(renderQr({ data: URL_28, style: withFrame('caption', '') }).meta.notDrawn).toEqual([]);
    expect(renderQr({ data: URL_28, style: withFrame('badge', '') }).meta.notDrawn).toEqual(['frame']);
  });

  it('the same input renders the same bytes with separately loaded fonts', () => {
    const other = loadFrameFont(new Uint8Array(readFileSync(join(HERE, '..', '..', '..', FRAME_FONT_ASSET))));
    const style = withFrame('badge', 'Σαρώστε με');
    expect(renderQr({ data: URL_28, style, font: other }).svg).toBe(renderQr({ data: URL_28, style, font: FONT }).svg);
  });
});

describe('badge mark by issuer status (D9, 2026-10-30)', () => {
  const style = withFrame('badge', 'Scan me');
  const markPath = (issuerVerified: boolean): string => {
    const layout = styleFrameLayout(style, renderQr({ data: URL_28, style }).meta.symbolSize)!;
    const box = layout.textBoxes.find((b) => b.role === 'mark')!;
    return outlineText(badgeMark(issuerVerified), box, FONT)!.d;
  };

  it('reads "Verified by QRAuth" only for a verified issuer, "Signed with QRAuth" otherwise', () => {
    expect(badgeMark(true)).toBe('Verified by QRAuth');
    expect(badgeMark(false)).toBe('Signed with QRAuth');
    expect(BADGE_MARK_VERIFIED).toBe(badgeMark(true));
    expect(BADGE_MARK_SIGNED).toBe(badgeMark(false));
  });

  it('every glyph of both wordings is in the frame font', () => {
    for (const mark of [BADGE_MARK_VERIFIED, BADGE_MARK_SIGNED]) {
      expect(isFrameTextSupported(mark)).toBe(true);
      // No character falls back to .notdef.
      for (const ch of mark) expect(FONT.glyph(ch.codePointAt(0) as number).commands).not.toEqual(FONT.glyph(0xffff).commands);
    }
  });

  it('draws the wording it is given as outlined paths, and reports it', () => {
    const verified = renderQr({ data: URL_28, style, font: FONT, issuerVerified: true });
    const signed = renderQr({ data: URL_28, style, font: FONT, issuerVerified: false });
    expect(verified.meta.badgeMark).toBe(BADGE_MARK_VERIFIED);
    expect(signed.meta.badgeMark).toBe(BADGE_MARK_SIGNED);
    expect(verified.svg).toContain(markPath(true));
    expect(verified.svg).not.toContain(markPath(false));
    expect(signed.svg).toContain(markPath(false));
    expect(signed.svg).not.toContain(markPath(true));
    expect(signed.svg).not.toContain('<text');
  });

  it('an omitted issuer status draws the unverified wording', () => {
    expect(renderQr({ data: URL_28, style, font: FONT }).svg).toBe(
      renderQr({ data: URL_28, style, font: FONT, issuerVerified: false }).svg,
    );
  });

  it('the issuer status changes nothing but the badge mark', () => {
    for (const template of TEMPLATES.filter((t) => t !== 'badge')) {
      const framed = withFrame(template, 'Scan me');
      const a = renderQr({ data: URL_28, style: framed, font: FONT, issuerVerified: true });
      expect(a.svg).toBe(renderQr({ data: URL_28, style: framed, font: FONT, issuerVerified: false }).svg);
      expect(a.meta.badgeMark).toBeNull();
    }
    const v = renderQr({ data: URL_28, style, font: FONT, issuerVerified: true }).drawList;
    const s = renderQr({ data: URL_28, style, font: FONT, issuerVerified: false }).drawList;
    const isText = (it: (typeof v.items)[number]): boolean => it.kind === 'path' && it.layer === 'frame-text';
    expect(v.items.filter((it) => !isText(it))).toEqual(s.items.filter((it) => !isText(it)));
  });
});

describe('frame scan rules', () => {
  const grey = (g: number): string => `#${g.toString(16).padStart(2, '0').repeat(3)}`.toUpperCase();
  /** The darkest grey on black that reaches `floor`, and the grey one step darker, which does not. */
  function pairAround(floor: number): { pass: string; fail: string } {
    for (let g = 0; g < 255; g++) {
      if (contrastRatio(grey(g), '#000000') >= floor) return { pass: grey(g), fail: grey(g - 1) };
    }
    throw new Error('unreachable');
  }

  it(`rejects frame text below ${FRAME_TEXT_CONTRAST_MIN}:1 against the frame colour`, () => {
    const { pass, fail } = pairAround(FRAME_TEXT_CONTRAST_MIN);
    const style = (textColor: string): QrStyleV2 => ({
      ...DEFAULT_STYLE,
      frame: { template: 'banner-bottom', text: 'Scan', color: '#000000', textColor },
    });
    expect(checkStyle(style(pass)).errors).toEqual([]);
    expect(checkStyle(style(fail)).errors.map((e) => e.code)).toEqual(['frame-contrast-too-low']);
    expect(checkStyle(style(fail)).errors[0].message).toMatch(/Frame text contrast .* is below 4.5:1/);
  });

  it('checks a caption against the background', () => {
    const { pass, fail } = pairAround(FRAME_TEXT_CONTRAST_MIN);
    const style = (textColor: string): QrStyleV2 => ({
      ...DEFAULT_STYLE,
      fg: '#FFFFFF',
      bg: '#000000',
      inverted: true,
      frame: { template: 'caption', text: 'Scan', color: '#FF0000', textColor },
    });
    expect(checkStyle(style(pass)).errors).toEqual([]);
    expect(checkStyle(style(fail)).errors.map((e) => e.code)).toEqual(['frame-contrast-too-low']);
  });

  it('keeps the code floors unchanged', () => {
    const low = { ...DEFAULT_STYLE, fg: grey(0x94) };
    expect(contrastRatio(low.fg, low.bg)).toBeGreaterThanOrEqual(3);
    expect(checkStyle(low).errors).toEqual([]);
  });

  it('rejects characters the font cannot draw', () => {
    const style = (text: string): QrStyleV2 => ({
      ...DEFAULT_STYLE,
      frame: { template: 'banner-top', text, color: '#000000', textColor: '#FFFFFF' },
    });
    expect(checkStyle(style('Σαρώστε με')).errors).toEqual([]);
    expect(checkStyle(style('Сканируйте')).errors).toEqual([]);
    for (const text of ['日本', 'emoji 🙂', 'á', 'مرحبا']) {
      expect(checkStyle(style(text)).errors).toEqual([
        { code: 'frame-glyph-unsupported', message: FRAME_GLYPH_UNSUPPORTED_MESSAGE },
      ]);
    }
    expect(FRAME_GLYPH_UNSUPPORTED_MESSAGE).toBe('This character is not supported in frame text yet');
    // A `none` frame draws no text, so its text is not checked.
    expect(checkStyle({ ...style('日本'), frame: { ...style('日本').frame!, template: 'none' } }).errors).toEqual([]);
  });
});
