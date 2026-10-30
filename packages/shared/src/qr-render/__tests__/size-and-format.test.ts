// SPDX-License-Identifier: MIT
import { describe, expect, it } from 'vitest';

import { renderQrCore } from '../core.js';
import { fmt } from '../format.js';
import { renderQr } from '../index.js';
import { SVG_SIZE_MAX } from '../svg.js';
import { URL_28 } from './golden-cases.js';

describe('fmt', () => {
  it('formats with at most 3 decimals, trims zeros, normalises -0', () => {
    expect(fmt(1.5)).toBe('1.5');
    expect(fmt(2)).toBe('2');
    expect(fmt(0.1234)).toBe('0.123');
    expect(fmt(-0)).toBe('0');
    expect(fmt(-0.0001)).toBe('0');
    expect(fmt(999999999999999)).toBe('999999999999999');
  });

  it.each([Infinity, -Infinity, NaN, 1e21, -1e21, 1e30])('throws for %s', (value) => {
    expect(() => fmt(value)).toThrow(/qr-render/);
  });

  it('throws for non-numbers', () => {
    expect(() => fmt('5' as unknown as number)).toThrow(/qr-render/);
  });
});

describe('size option', () => {
  const render = (size: unknown): string =>
    renderQr({ data: URL_28, style: null, size: size as { value: number; unit: 'px' } }).svg;

  it('accepts sizes up to the documented maximum per unit', () => {
    expect(render({ value: 300, unit: 'px' })).toContain('width="300"');
    expect(render({ value: SVG_SIZE_MAX.px, unit: 'px' })).toContain(`width="${SVG_SIZE_MAX.px}"`);
    expect(render({ value: 25.4, unit: 'mm' })).toContain('width="25.4mm"');
    expect(render({ value: SVG_SIZE_MAX.mm, unit: 'mm' })).toContain(`width="${SVG_SIZE_MAX.mm}mm"`);
  });

  it.each([
    { value: 0, unit: 'px' },
    { value: -50, unit: 'px' },
    { value: SVG_SIZE_MAX.px + 1, unit: 'px' },
    { value: SVG_SIZE_MAX.mm + 0.5, unit: 'mm' },
    { value: 1e30, unit: 'mm' },
    { value: NaN, unit: 'px' },
    { value: Infinity, unit: 'px' },
    { value: '100', unit: 'px' },
  ])('rejects value $value $unit', (size) => {
    expect(() => render(size)).toThrow(/qr-render: size/);
  });

  it.each(['em', 'in', '', 'PX', '__proto__', 'toString'])('rejects unit %j', (unit) => {
    expect(() => render({ value: 100, unit })).toThrow(/qr-render: size unit/);
  });

  it('applies to the core renderer too', () => {
    expect(() => renderQrCore(URL_28, { size: { value: 0, unit: 'px' } })).toThrow(/qr-render: size/);
    expect(renderQrCore(URL_28, { size: { value: 100, unit: 'px' } })).toContain('width="100"');
  });
});
