import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

import { qrToSvg } from '../src/utils/qr-svg.js';
import {
  AUTH_SESSION_URL,
  WEB_COMPONENT_CASES,
} from '../../shared/src/qr-render/__tests__/golden-cases';

/**
 * ADR-0005 PR 7: the components draw their QR code through the shared
 * renderer's core entry point, byte for byte the SVG the shared package and
 * the dashboard produce for the same input (the same golden files).
 */
const GOLDEN_DIR = resolve(__dirname, '../../shared/src/qr-render/__tests__/golden');

describe('qrToSvg (shared core renderer)', () => {
  for (const c of WEB_COMPONENT_CASES) {
    it(`matches golden/${c.name}.svg`, () => {
      expect(qrToSvg(c.data, c.size.value)).toBe(readFileSync(resolve(GOLDEN_DIR, `${c.name}.svg`), 'utf8'));
    });
  }

  it('draws the plain code: square modules, black on white, renderer tag', () => {
    const svg = qrToSvg(AUTH_SESSION_URL, 440);
    expect(svg).toMatch(/^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg" viewBox="0 0 41 41" width="440" height="440" role="img" aria-label="QR code" data-renderer="qrauth-qr\/\d+">/);
    expect(svg).toContain('fill="#000000"');
    expect(svg).toContain('fill="#FFFFFF"');
    expect(svg).not.toMatch(/<image|href=|<text/);
  });

  it('defaults to 440 px and floors fractional widths', () => {
    expect(qrToSvg(AUTH_SESSION_URL)).toBe(qrToSvg(AUTH_SESSION_URL, 440));
    expect(qrToSvg(AUTH_SESSION_URL, 320.9)).toBe(qrToSvg(AUTH_SESSION_URL, 320));
    expect(qrToSvg(AUTH_SESSION_URL, Number.NaN)).toBe(qrToSvg(AUTH_SESSION_URL, 440));
  });

  it('clamps the width to 1..16384 px', () => {
    expect(qrToSvg(AUTH_SESSION_URL, 0)).toContain(' width="1" height="1"');
    expect(qrToSvg(AUTH_SESSION_URL, -5)).toContain(' width="1" height="1"');
    expect(qrToSvg(AUTH_SESSION_URL, 1e9)).toContain(' width="16384" height="16384"');
  });

  it('returns an empty string for empty text and for text over capacity at EC M', () => {
    expect(qrToSvg('')).toBe('');
    expect(qrToSvg('x'.repeat(2400))).toBe('');
  });
});
