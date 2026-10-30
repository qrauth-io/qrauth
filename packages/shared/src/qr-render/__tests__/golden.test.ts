// SPDX-License-Identifier: MIT
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { loadFrameFont } from '../font.js';
import { renderQr, renderQrCore } from '../index.js';
import { FRAME_FONT_FILE, GOLDEN_CASES, LOGO_PNG_BASE64, type GoldenCase } from './golden-cases.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const GOLDEN_DIR = join(HERE, 'golden');
const FONT = loadFrameFont(new Uint8Array(readFileSync(join(HERE, '..', '..', '..', FRAME_FONT_FILE))));
const UPDATE = process.env.UPDATE_GOLDEN === '1';

function logoBytes(): Uint8Array {
  return Uint8Array.from(atob(LOGO_PNG_BASE64), (c) => c.charCodeAt(0));
}

function render(c: GoldenCase): string {
  if (c.kind === 'core') return renderQrCore(c.data, { ...c.core, size: c.size });
  return renderQr({
    data: c.data,
    style: c.style,
    logoPng: c.withLogo ? logoBytes() : null,
    size: c.size,
    font: c.withFont ? FONT : null,
    issuerVerified: c.issuerVerified,
  }).svg;
}

describe('qr-render golden files (Node)', () => {
  if (UPDATE) mkdirSync(GOLDEN_DIR, { recursive: true });

  for (const c of GOLDEN_CASES) {
    it(`matches golden/${c.name}.svg`, () => {
      const file = join(GOLDEN_DIR, `${c.name}.svg`);
      const svg = render(c);
      if (UPDATE) writeFileSync(file, svg);
      expect(existsSync(file)).toBe(true);
      expect(svg).toBe(readFileSync(file, 'utf8'));
    });
  }

  it('has no stale golden files', () => {
    const expected = new Set(GOLDEN_CASES.map((c) => `${c.name}.svg`));
    const present = readdirSync(GOLDEN_DIR).filter((f) => f.endsWith('.svg'));
    expect(present.filter((f) => !expected.has(f))).toEqual([]);
  });

  it('renders the default style identically through the core and full entry points', () => {
    const full = renderQr({ data: GOLDEN_CASES[0].data, style: GOLDEN_CASES[2].style }).svg;
    expect(GOLDEN_CASES[2].name).toBe('shape-square-square');
    expect(full).toBe(renderQrCore(GOLDEN_CASES[0].data));
  });
});
