// SPDX-License-Identifier: MIT
import { describe, expect, it } from 'vitest';

import { DEFAULT_STYLE, isValidFrameText, parseStyle, upgradeStyle } from '../style.js';

const withFrameText = (text: string): unknown => ({
  ...DEFAULT_STYLE,
  frame: { template: 'caption', text, color: '#FFFFFF', textColor: '#000000' },
});

const REJECTED: ReadonlyArray<readonly [string, string]> = [
  ['CR', '\r'],
  ['LF', '\n'],
  ['NEL U+0085', '\u0085'],
  ['LINE SEPARATOR U+2028', ' '],
  ['PARAGRAPH SEPARATOR U+2029', ' '],
  ['NUL', '\u0000'],
  ['TAB', '\t'],
  ['VT', '\u000B'],
  ['ESC', '\u001B'],
  ['DEL', '\u007F'],
  ['C1 U+0080', '\u0080'],
  ['C1 U+009F', '\u009F'],
  ['LRM U+200E', '‎'],
  ['RLM U+200F', '‏'],
  ['LRE U+202A', '‪'],
  ['RLO U+202E', '‮'],
  ['LRI U+2066', '⁦'],
  ['PDI U+2069', '⁩'],
];

describe('frame text', () => {
  it.each(REJECTED)('rejects %s', (_name, ch) => {
    const text = `Scan${ch}me`;
    expect(isValidFrameText(text)).toBe(false);
    expect(() => parseStyle(withFrameText(text))).toThrow();
  });

  it.each(['Scan to verify', 'Σκανάρετε εδώ', 'مرحبا', '日本語 OK', '<b>x</b> & "q"', 'emoji 🙂'])(
    'accepts %j',
    (text) => {
      expect(isValidFrameText(text)).toBe(true);
      expect(parseStyle(withFrameText(text)).frame?.text).toBe(text);
    },
  );

  it('the v1 upgrade turns line breaks into spaces and drops control and bidi characters', () => {
    const v2 = upgradeStyle({
      templateId: 'classic',
      fgColor: '#000000',
      bgColor: '#FFFFFF',
      showLogo: false,
      captionText: ' Scan\r\nto verify‮\u0007 now ',
    });
    expect(v2.frame?.text).toBe('Scan to verify now');
    // The upgraded style is itself a valid v2 style.
    expect(parseStyle(v2)).toEqual(v2);
  });

  it('the v1 upgrade still truncates to 40 characters', () => {
    const v2 = upgradeStyle({
      templateId: 'classic',
      fgColor: '#000000',
      bgColor: '#FFFFFF',
      showLogo: false,
      captionText: 'x'.repeat(39) + ' yyyy',
    });
    expect(v2.frame?.text).toBe('x'.repeat(39));
    expect(parseStyle(v2)).toEqual(v2);
  });
});
