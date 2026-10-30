// SPDX-License-Identifier: MIT
import { describe, expect, it } from 'vitest';

import { checkStyle } from '../scan-rules.js';
import { DEFAULT_STYLE } from '../style.js';

const codes = (style: Parameters<typeof checkStyle>[0]) => {
  const report = checkStyle(style);
  return { errors: report.errors.map((i) => i.code), warnings: report.warnings.map((i) => i.code) };
};

describe('polarity (ADR-0005 D4.2)', () => {
  it('dark on light, inverted false: no polarity issue', () => {
    expect(codes(DEFAULT_STYLE)).toEqual({ errors: [], warnings: [] });
  });

  it('dark on light, inverted true: a mismatch warning, not an error', () => {
    expect(codes({ ...DEFAULT_STYLE, inverted: true })).toEqual({ errors: [], warnings: ['inverted-mismatch'] });
  });

  it('light on dark, inverted true: the scanner warning only', () => {
    expect(codes({ ...DEFAULT_STYLE, fg: '#FFFFFF', bg: '#000000', inverted: true })).toEqual({
      errors: [],
      warnings: ['inverted'],
    });
  });

  it('light on dark, inverted false: an error', () => {
    expect(codes({ ...DEFAULT_STYLE, fg: '#FFFFFF', bg: '#000000', inverted: false })).toEqual({
      errors: ['inverted-required'],
      warnings: [],
    });
  });

  it('equal luminance counts as not lighter', () => {
    // Too little contrast to save, but the polarity rule itself sees no inversion.
    const report = codes({ ...DEFAULT_STYLE, fg: '#777777', bg: '#777777', inverted: true });
    expect(report.warnings).toContain('inverted-mismatch');
  });
});
