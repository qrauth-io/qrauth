// SPDX-License-Identifier: MIT
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { loadFrameFont } from '../font.js';
import { renderQr } from '../index.js';
import { FRAME_FONT_FILE } from './golden-cases.js';
import { CUSTOMER_LOGO_FIXTURE, EXPORT_GOLDEN_CASES, EXPORT_ORIGIN, EXPORT_TOKEN } from './export-golden-cases.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const GOLDEN_DIR = join(HERE, 'golden-export');
const LOGO = new Uint8Array(readFileSync(join(HERE, '..', '..', '..', 'assets', 'qrauth-logo.png')));
const CUSTOMER_LOGO = new Uint8Array(readFileSync(join(HERE, CUSTOMER_LOGO_FIXTURE)));
const FONT = loadFrameFont(new Uint8Array(readFileSync(join(HERE, '..', '..', '..', FRAME_FONT_FILE))));
const UPDATE = process.env.UPDATE_GOLDEN === '1';

describe('export golden files: preview = server SVG (Node)', () => {
  if (UPDATE) mkdirSync(GOLDEN_DIR, { recursive: true });

  for (const c of EXPORT_GOLDEN_CASES) {
    it(`matches golden-export/${c.name}.svg`, () => {
      const isCustomer = (c.style as { logo?: { kind?: string } } | null)?.logo?.kind === 'asset';
      const logoPng = isCustomer ? CUSTOMER_LOGO : LOGO;
      const { svg, style, meta } = renderQr({
        data: `${EXPORT_ORIGIN}/v/${EXPORT_TOKEN}`,
        style: c.style,
        logoPng,
        font: FONT,
        issuerVerified: c.issuerVerified,
      });
      const file = join(GOLDEN_DIR, `${c.name}.svg`);
      if (UPDATE) writeFileSync(file, svg);
      expect(existsSync(file)).toBe(true);
      expect(svg).toBe(readFileSync(file, 'utf8'));
      // A logo case embeds the real logo bytes: the QRAuth logo or the customer's.
      if (style.logo) {
        expect(svg).toContain(Buffer.from(logoPng).toString('base64'));
        expect(meta.notDrawn).not.toContain('logo');
      }
      expect(meta.notDrawn).not.toContain('frame');
    });
  }

  it('has no stale golden files', () => {
    const expected = new Set(EXPORT_GOLDEN_CASES.map((c) => `${c.name}.svg`));
    const present = readdirSync(GOLDEN_DIR).filter((f) => f.endsWith('.svg'));
    expect(present.filter((f) => !expected.has(f))).toEqual([]);
  });
});
