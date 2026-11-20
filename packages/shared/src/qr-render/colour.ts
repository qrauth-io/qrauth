// SPDX-License-Identifier: MIT

const HEX = /^#[0-9a-fA-F]{6}$/;

/** True for a `#RRGGBB` colour. */
export function isHexColour(value: unknown): value is string {
  return typeof value === 'string' && HEX.test(value);
}

/** Validates and upper-cases a `#RRGGBB` colour, so equal colours serialise equally. */
export function normaliseColour(value: string): string {
  if (!isHexColour(value)) throw new Error(`qr-render: invalid colour ${JSON.stringify(value)}`);
  return value.toUpperCase();
}

function channel(hex: string, at: number): number {
  const c = parseInt(hex.slice(at, at + 2), 16) / 255;
  return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
}

/** WCAG 2.x relative luminance of a `#RRGGBB` colour. */
export function relativeLuminance(hex: string): number {
  const h = normaliseColour(hex);
  return 0.2126 * channel(h, 1) + 0.7152 * channel(h, 3) + 0.0722 * channel(h, 5);
}

/** WCAG 2.x contrast ratio, (L1 + 0.05) / (L2 + 0.05), always >= 1. */
export function contrastRatio(a: string, b: string): number {
  const la = relativeLuminance(a);
  const lb = relativeLuminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

/** True when `fg` is lighter than `bg`, i.e. a light-on-dark code. */
export function isLighter(fg: string, bg: string): boolean {
  return relativeLuminance(fg) > relativeLuminance(bg);
}
