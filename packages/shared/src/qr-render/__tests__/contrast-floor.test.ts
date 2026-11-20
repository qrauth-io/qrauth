// SPDX-License-Identifier: MIT
import { describe, expect, it } from 'vitest';

import { contrastRatio } from '../colour.js';
import {
  checkStyle,
  CONTRAST_MIN,
  CONTRAST_MIN_INVERTED_WITH_LOGO,
  CONTRAST_MIN_WITH_LOGO,
  contrastFloor,
} from '../scan-rules.js';
import { DEFAULT_STYLE, type QrStyleV2 } from '../style.js';

const errorCodes = (style: QrStyleV2): string[] => checkStyle(style).errors.map((i) => i.code);

const withColour = (fg: string, logo: QrStyleV2['logo']): QrStyleV2 => ({ ...DEFAULT_STYLE, fg, logo });

describe('contrast floor (ADR-0005 D4.1, D9)', () => {
  it('is 3:1 without a logo, 3.5:1 with one, 7:1 light-on-dark with one', () => {
    const dark = { fg: '#000000', bg: '#FFFFFF' };
    const light = { fg: '#FFFFFF', bg: '#000000' };
    expect([CONTRAST_MIN, CONTRAST_MIN_WITH_LOGO, CONTRAST_MIN_INVERTED_WITH_LOGO]).toEqual([3, 3.5, 7]);
    expect(contrastFloor({ ...dark, logo: null })).toBe(3);
    expect(contrastFloor({ ...light, logo: null })).toBe(3);
    expect(contrastFloor({ ...dark, logo: { kind: 'qrauth' } })).toBe(3.5);
    expect(contrastFloor({ ...dark, logo: { kind: 'asset', assetId: 'a', scale: 1 } })).toBe(3.5);
    expect(contrastFloor({ ...light, logo: { kind: 'qrauth' } })).toBe(7);
    expect(contrastFloor({ ...light, logo: { kind: 'asset', assetId: 'a', scale: 1 } })).toBe(7);
  });

  // #0089FE is 3.4945:1 on white, #008BF4 is 3.5004:1, #949494 is 3.03:1.
  it('fixture ratios', () => {
    expect(contrastRatio('#0089FE', '#FFFFFF')).toBeGreaterThanOrEqual(3.49);
    expect(contrastRatio('#0089FE', '#FFFFFF')).toBeLessThan(3.5);
    expect(contrastRatio('#008BF4', '#FFFFFF')).toBeGreaterThanOrEqual(3.5);
    expect(contrastRatio('#949494', '#FFFFFF')).toBeGreaterThanOrEqual(3);
    expect(contrastRatio('#949494', '#FFFFFF')).toBeLessThan(3.1);
  });

  it.each([{ kind: 'qrauth' as const }, { kind: 'asset' as const, assetId: 'a', scale: 0.5 }])(
    'with a %o logo: 3.49:1 is rejected, 3.5:1 is accepted',
    (logo) => {
      expect(errorCodes(withColour('#0089FE', logo))).toEqual(['contrast-too-low-with-logo']);
      expect(errorCodes(withColour('#008BF4', logo))).toEqual([]);
      expect(checkStyle(withColour('#0089FE', logo)).errors[0].message).toBe(
        'With a logo, colour contrast 3.49:1 is below 3.5:1',
      );
    },
  );

  it('without a logo: 3.0:1 is accepted (with the low-contrast warning)', () => {
    const report = checkStyle(withColour('#949494', null));
    expect(report.errors).toEqual([]);
    expect(report.warnings.map((i) => i.code)).toEqual(['contrast-low']);
    expect(errorCodes(withColour('#0089FE', null))).toEqual([]);
  });

  it('without a logo: below 3:1 is still rejected', () => {
    expect(errorCodes(withColour('#959595', null))).toEqual(['contrast-too-low']);
  });

  // Light on black: #959595 is 7.01:1, #949494 6.92:1; #5A5A5A 3.04:1, #595959 2.998:1.
  const lightOnBlack = (fg: string, logo: QrStyleV2['logo']): QrStyleV2 => ({
    ...DEFAULT_STYLE,
    fg,
    bg: '#000000',
    inverted: true,
    logo,
  });

  it('light-on-dark with a logo: 6.92:1 is rejected, 7.01:1 is accepted', () => {
    expect(contrastRatio('#949494', '#000000')).toBeLessThan(7);
    expect(contrastRatio('#959595', '#000000')).toBeGreaterThanOrEqual(7);
    expect(errorCodes(lightOnBlack('#949494', { kind: 'qrauth' }))).toEqual(['contrast-too-low-inverted-with-logo']);
    expect(errorCodes(lightOnBlack('#959595', { kind: 'qrauth' }))).toEqual([]);
    expect(checkStyle(lightOnBlack('#949494', { kind: 'qrauth' })).errors[0].message).toBe(
      'Light on dark with a logo, colour contrast 6.92:1 is below 7:1',
    );
  });

  it('light-on-dark without a logo keeps the 3:1 floor', () => {
    expect(errorCodes(lightOnBlack('#5A5A5A', null))).toEqual([]);
    expect(errorCodes(lightOnBlack('#595959', null))).toEqual(['contrast-too-low']);
  });

  it('the floor follows the colours, not the inverted flag', () => {
    // Light on dark with a logo but inverted: false: still the 7:1 floor (and inverted-required).
    const codes = errorCodes({ ...lightOnBlack('#949494', { kind: 'qrauth' }), inverted: false });
    expect(codes).toContain('contrast-too-low-inverted-with-logo');
    expect(codes).toContain('inverted-required');
  });
});
