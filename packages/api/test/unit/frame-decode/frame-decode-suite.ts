/**
 * Decode round trip for frames (ADR-0005 D5, PR 5): one frame template ×
 * every module style × every eye style × {no logo, QRAuth logo at cap},
 * rendered with the frame font through the production render and raster
 * path (renderStyled, rasterisePng), at the rasters of the save-time check
 * (DECODE_RASTERS: the 300, 512 and 1024 px export widths raised to the
 * minimum module size, every whole scale from 3 to 16 px/module, and the
 * blurred 3 px/module raster). zxing-wasm must read back exactly the URL,
 * and nothing else, for every raster.
 *
 * One file per template (frame-decode/*.test.ts) so vitest runs the
 * templates in parallel workers. The zxing WASM binary is loaded from
 * node_modules and `fetch` is disabled: the suite contacts no host.
 */
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

import sharp from 'sharp';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { prepareZXingModule, readBarcodes } from 'zxing-wasm/reader';
import { DEFAULT_STYLE, EYE_STYLES, MODULE_STYLES, type QrFrame, type QrStyleV2 } from '@qrauth/shared/qr-render';

process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

const { QRAUTH_LOGO_PNG, rasterisePng, renderStyled } = await import('../../../src/services/qr-render.js');
const { DECODE_RASTERS, rasterWidth } = await import('../../../src/services/logo-decode.js');

const require = createRequire(import.meta.url);

/** Production-length verify URL (D4.4). */
export const FRAME_DECODE_URL = 'https://qrauth.io/v/aB3dE5gH';
const LOGOS = ['none', 'qrauth'] as const;
/** One template renders and decodes up to 576 rasters. */
const TIMEOUT_MS = 180_000;

/** Frame text per template: Greek, Cyrillic and Latin, with accents and descenders. */
const TEXTS: Readonly<Record<Exclude<QrFrame['template'], 'none'>, string>> = {
  caption: 'Σαρώστε με',
  'banner-bottom': 'Сканируйте меня',
  'banner-top': 'Scan to verify',
  'rounded-label': 'Ζήτα το μενού',
  badge: 'Café Ωμέγα — jpqy',
};

async function decode(png: Buffer): Promise<string[]> {
  const results = await readBarcodes(new Uint8Array(png), {
    formats: ['QRCode'],
    tryHarder: true,
    tryInvert: true,
    maxNumberOfSymbols: 4,
  });
  return results.filter((r) => r.isValid).map((r) => r.text);
}

export function describeFrameDecode(template: Exclude<QrFrame['template'], 'none'>): void {
  beforeAll(async () => {
    vi.stubGlobal('fetch', () => {
      throw new Error('network access is not allowed in the decode suite');
    });
    const wasm = readFileSync(require.resolve('zxing-wasm/reader/zxing_reader.wasm'));
    await prepareZXingModule({
      overrides: { wasmBinary: wasm.buffer.slice(wasm.byteOffset, wasm.byteOffset + wasm.byteLength) },
      fireImmediately: true,
    });
  });

  afterAll(() => {
    vi.unstubAllGlobals();
  });

  describe(`frame decode round trip: ${template}`, () => {
    for (const logo of LOGOS) {
      it(`every module and eye style decodes at every raster, logo ${logo}`, async () => {
        const failures: string[] = [];
        let decodes = 0;
        for (const modules of MODULE_STYLES) {
          for (const eyes of EYE_STYLES) {
            const style: QrStyleV2 = {
              ...DEFAULT_STYLE,
              modules,
              eyes,
              logo: logo === 'qrauth' ? { kind: 'qrauth' } : null,
              frame: { template, text: TEXTS[template], color: '#1B2A4A', textColor: '#FFFFFF' },
            };
            const logoPng = logo === 'qrauth' ? QRAUTH_LOGO_PNG : null;
            const { meta } = renderStyled({ data: FRAME_DECODE_URL, style, logoPng });
            expect(meta.notDrawn).toEqual([]);
            for (const raster of DECODE_RASTERS) {
              const width = rasterWidth(raster, meta.width);
              if (width === null) continue;
              const { svg } = renderStyled({ data: FRAME_DECODE_URL, style, logoPng, size: { value: width, unit: 'px' } });
              const png = await rasterisePng(svg);
              const input = raster.blur > 0 ? await sharp(png).blur(raster.blur).png().toBuffer() : png;
              const texts = await decode(input);
              decodes++;
              if (texts.length === 0 || texts.some((t) => t !== FRAME_DECODE_URL)) {
                failures.push(`${modules}/${eyes}/${raster.name}: ${JSON.stringify(texts)}`);
              }
            }
          }
        }
        // Every raster of the check fits the 1024 px limit for these codes.
        expect(decodes).toBe(MODULE_STYLES.length * EYE_STYLES.length * DECODE_RASTERS.length);
        expect(failures).toEqual([]);
      }, TIMEOUT_MS);
    }
  });
}
