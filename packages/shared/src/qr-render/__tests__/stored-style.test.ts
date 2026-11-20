// SPDX-License-Identifier: MIT
import { describe, expect, it } from 'vitest';

import { renderQr } from '../index.js';
import { DEFAULT_STYLE, parseStoredStyle, parseStyle } from '../style.js';
import { URL_28 } from './golden-cases.js';

// The four v1 shapes stored in production (2026-10-28): every stored style
// has exactly these keys. Caption text is a neutral stand-in of the stored
// length (15 characters).
const CAPTION = 'Scan to verify!';
const PROD_V1_SHAPES = [
  { templateId: 'classic', fgColor: '#000000', bgColor: '#FFFFFF', showLogo: false, captionText: CAPTION },
  { templateId: 'classic', fgColor: '#000000', bgColor: '#FFFFFF', showLogo: true, captionText: CAPTION },
  { templateId: 'custom', fgColor: '#000000', bgColor: '#FFFFFF', showLogo: false, captionText: CAPTION },
  { templateId: 'midnight', fgColor: '#E0E0E0', bgColor: '#212121', showLogo: true, captionText: CAPTION },
] as const;

describe('stored styles', () => {
  it.each([null, undefined])('%s (no stored style) reads as DEFAULT_STYLE', (input) => {
    expect(parseStoredStyle(input)).toEqual(DEFAULT_STYLE);
  });

  it.each([null, undefined])('%s renders exactly like DEFAULT_STYLE', (input) => {
    const stored = renderQr({ data: URL_28, style: input });
    expect(stored.style).toEqual(DEFAULT_STYLE);
    expect(stored.svg).toBe(renderQr({ data: URL_28, style: DEFAULT_STYLE }).svg);
  });

  it('a submitted style is still required', () => {
    expect(() => parseStyle(null)).toThrow();
    expect(() => parseStyle(undefined)).toThrow();
  });

  it.each(PROD_V1_SHAPES)('production shape $templateId (logo $showLogo) upgrades losslessly and renders', (v1) => {
    const style = parseStoredStyle(v1);
    expect(style).toMatchObject({
      version: 2,
      presetId: v1.templateId,
      fg: v1.fgColor,
      bg: v1.bgColor,
      inverted: v1.templateId === 'midnight',
      logo: v1.showLogo ? { kind: 'qrauth' } : null,
      frame: { template: 'caption', text: CAPTION },
    });
    const { svg, meta } = renderQr({ data: URL_28, style: v1 });
    expect(svg.startsWith('<svg')).toBe(true);
    expect(meta.errors).toEqual([]);
  });

  it('other values still throw', () => {
    expect(() => renderQr({ data: URL_28, style: {} })).toThrow();
    expect(() => renderQr({ data: URL_28, style: 'classic' })).toThrow();
  });
});
