/**
 * Decode round trip (ADR-0005 D5): render with the shared renderer, rasterise
 * with the production raster path (sharp, services/qr-render.ts), decode.
 * zxing-wasm must return the exact URL for every render, down to the 3:1
 * contrast floor and for inverted codes. jsQR, an independent second decoder,
 * runs on the rows listed in each row's `decoders` field (high-contrast,
 * non-inverted). The 3:1 floor is tested without a logo, the 3.5:1 floor
 * with the QRAuth logo over every raster scale from 3 to 16 px/module. The
 * rows at the two D5 rasters also render with a banner-bottom frame (the D5
 * frame dimension, rendered with the frame font); every template x module
 * and eye style, with and without a logo, at the export widths and the
 * px/module sweep is in test/unit/frame-decode/.
 *
 * The decoders are devDependencies (D9). The zxing WASM binary is loaded from
 * node_modules and `fetch` is disabled, so the suite contacts no host.
 */
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

import sharp from 'sharp';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { prepareZXingModule, readBarcodes } from 'zxing-wasm/reader';
import {
  CONTRAST_MIN,
  CONTRAST_MIN_INVERTED_WITH_LOGO,
  CONTRAST_MIN_WITH_LOGO,
  contrastRatio,
} from '@qrauth/shared/qr-render';

process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

const { QRAUTH_LOGO_PNG, qrImageDataUrl, rasterisePng, renderStyled } = await import('../../src/services/qr-render.js');
const { buildVerificationUrl } = await import('../../src/lib/qrcode-access.js');

// jsqr is CommonJS but its typings declare an ES default export, which
// NodeNext types as the module object. Load it with require, typed by the
// package's own declaration.
const require = createRequire(import.meta.url);
const jsQR = require('jsqr') as typeof import('jsqr').default;

/** Production-length verify URLs (D4.4): 28 characters today, 55 for the longest tested. */
const URL_28 = 'https://qrauth.io/v/aB3dE5gH';
const URL_55 = 'https://qrauth.io/v/aB3dE5gH9kLmNpQrStUvWxYz0123456789X';
const URLS = [URL_28, URL_55] as const;

const MODULES = ['square', 'rounded', 'dots', 'classy'] as const;
const EYES = ['square', 'rounded', 'circle', 'leaf'] as const;
const LOGOS = ['none', 'at-cap', 'half-scale'] as const;

const grey = (g: number): string => `#${g.toString(16).padStart(2, '0').repeat(3)}`.toUpperCase();

/** Lightest grey that still meets `floor` against white. */
function boundaryGrey(floor: number): string {
  for (let g = 255; g >= 0; g--) if (contrastRatio(grey(g), '#FFFFFF') >= floor) return grey(g);
  throw new Error('unreachable');
}

/** Darkest grey that still meets `floor` against black (light-on-dark). */
function boundaryGreyOnBlack(floor: number): string {
  for (let g = 0; g <= 255; g++) if (contrastRatio(grey(g), '#000000') >= floor) return grey(g);
  throw new Error('unreachable');
}

type Decoder = 'zxing' | 'jsqr';

/** One row renders and decodes up to 960 images (the 3.5:1 sweep); well above the 5 s default. */
const DECODE_TIMEOUT_MS = 120_000;

/**
 * jsQR is a secondary decoder for high-contrast, non-inverted rows only. It
 * does not read low-contrast or inverted renders reliably, including the
 * reference qrcode library's own PNG output for the same colours, so the
 * acceptance criterion for every row is zxing (ADR-0005 D4.1, D5).
 */
const JSQR_MIN_CONTRAST = 7;

type LogoVariant = (typeof LOGOS)[number];

interface Raster {
  readonly name: string;
  readonly pxPerModule: number;
  readonly blur: number;
}

/** 8 px/module, and 3 px/module with a 1 px Gaussian blur as a cheap print/camera degradation (D5). */
const D5_RASTERS: readonly Raster[] = [
  { name: '8px', pxPerModule: 8, blur: 0 },
  { name: '3px-blur1', pxPerModule: 3, blur: 1 },
];

/**
 * Every whole scale from 3 to 16 px/module, unblurred, plus the D5 blurred
 * raster. 3 px/module is the smallest the server renders (MIN_PX_PER_MODULE);
 * 2 px/module is not produced, so it is not tested (ADR-0005 D5).
 */
const SWEEP_RASTERS: readonly Raster[] = [
  ...Array.from({ length: 14 }, (_, i) => ({ name: `${i + 3}px`, pxPerModule: i + 3, blur: 0 })),
  { name: '3px-blur1', pxPerModule: 3, blur: 1 },
];

interface ColourRow {
  readonly name: string;
  readonly fg: string;
  readonly bg: string;
  readonly inverted: boolean;
  readonly decoders: readonly Decoder[];
  readonly logos: readonly LogoVariant[];
  readonly rasters: readonly Raster[];
  readonly modules: readonly (typeof MODULES)[number][];
  /** Frame dimension of D5: rows at the D5 rasters also render with a banner-bottom frame (PR 5). */
  readonly frames: readonly Frame[];
}

const FRAMES = ['none', 'banner-bottom'] as const;
type Frame = (typeof FRAMES)[number];

const COLOURS: readonly ColourRow[] = [
  { name: 'black-white', fg: '#000000', bg: '#FFFFFF', inverted: false, decoders: ['zxing', 'jsqr'], logos: LOGOS, rasters: D5_RASTERS, modules: MODULES, frames: FRAMES },
  // The 3:1 floor applies to codes without a logo (D4.1).
  { name: 'boundary-3to1', fg: boundaryGrey(CONTRAST_MIN), bg: '#FFFFFF', inverted: false, decoders: ['zxing'], logos: ['none'], rasters: D5_RASTERS, modules: MODULES, frames: FRAMES },
  // The 3.5:1 floor for codes with a logo, over every raster scale: the gap
  // below it showed at 8 px/module only (D4.1).
  {
    name: 'boundary-logo-3.5to1',
    fg: boundaryGrey(CONTRAST_MIN_WITH_LOGO),
    bg: '#FFFFFF',
    inverted: false,
    decoders: ['zxing'],
    logos: ['at-cap', 'half-scale'],
    rasters: SWEEP_RASTERS,
    modules: MODULES,
    frames: ['none'],
  },
  { name: 'inverted-midnight', fg: '#E0E0E0', bg: '#212121', inverted: true, decoders: ['zxing'], logos: LOGOS, rasters: D5_RASTERS, modules: MODULES, frames: FRAMES },
  // Light on dark without a logo: the 3:1 floor, over every raster scale.
  {
    name: 'inverted-boundary-3to1',
    fg: boundaryGreyOnBlack(CONTRAST_MIN),
    bg: '#000000',
    inverted: true,
    decoders: ['zxing'],
    logos: ['none'],
    rasters: SWEEP_RASTERS,
    modules: ['square', 'dots'],
    frames: ['none'],
  },
  // Light on dark with a logo: the 7:1 floor, over every raster scale.
  {
    name: 'inverted-logo-7to1',
    fg: boundaryGreyOnBlack(CONTRAST_MIN_INVERTED_WITH_LOGO),
    bg: '#000000',
    inverted: true,
    decoders: ['zxing'],
    logos: ['at-cap', 'half-scale'],
    rasters: SWEEP_RASTERS,
    modules: ['square', 'dots'],
    frames: ['none'],
  },
];

function logoStyle(logo: LogoVariant): unknown {
  if (logo === 'none') return null;
  if (logo === 'at-cap') return { kind: 'qrauth' };
  return { kind: 'asset', assetId: 'test-asset', scale: 0.5 };
}

async function decodeJsQr(png: Buffer): Promise<string | null> {
  const { data, info } = await sharp(png).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const result = jsQR(new Uint8ClampedArray(data.buffer, data.byteOffset, data.byteLength), info.width, info.height, {
    inversionAttempts: 'attemptBoth',
  });
  return result?.data ?? null;
}

async function decodeZxing(png: Buffer): Promise<string | null> {
  const results = await readBarcodes(new Uint8Array(png), {
    formats: ['QRCode'],
    tryHarder: true,
    tryInvert: true,
  });
  return results.find((r) => r.isValid)?.text ?? null;
}

async function raster(svg: string, blur: number): Promise<Buffer> {
  const png = await rasterisePng(svg);
  return blur > 0 ? sharp(png).blur(blur).png().toBuffer() : png;
}

beforeAll(async () => {
  vi.stubGlobal('fetch', () => {
    throw new Error('network access is not allowed in the decode suite');
  });
  const wasmBinary = readFileSync(require.resolve('zxing-wasm/reader/zxing_reader.wasm'));
  await prepareZXingModule({
    overrides: { wasmBinary: wasmBinary.buffer.slice(wasmBinary.byteOffset, wasmBinary.byteOffset + wasmBinary.byteLength) },
    fireImmediately: true,
  });
});

afterAll(() => {
  vi.unstubAllGlobals();
});

describe('qr-render decode round trip (jsQR + zxing-wasm, production raster path)', () => {
  it('scopes decoders explicitly: zxing on every row, jsQR only on high-contrast non-inverted rows', () => {
    expect(COLOURS.map((c) => c.name)).toEqual([
      'black-white',
      'boundary-3to1',
      'boundary-logo-3.5to1',
      'inverted-midnight',
      'inverted-boundary-3to1',
      'inverted-logo-7to1',
    ]);
    for (const c of COLOURS) {
      expect(c.decoders).toContain('zxing');
      if (c.decoders.includes('jsqr')) {
        expect(c.inverted).toBe(false);
        expect(contrastRatio(c.fg, c.bg)).toBeGreaterThanOrEqual(JSQR_MIN_CONTRAST);
      }
    }
  });

  it('tests each floor at its boundary, over the full raster sweep', () => {
    const floorOf = (c: ColourRow): number => {
      const logo = c.logos.some((l) => l !== 'none');
      if (!logo) return CONTRAST_MIN;
      return c.inverted ? CONTRAST_MIN_INVERTED_WITH_LOGO : CONTRAST_MIN_WITH_LOGO;
    };
    for (const c of COLOURS) {
      expect(contrastRatio(c.fg, c.bg), c.name).toBeGreaterThanOrEqual(floorOf(c));
      expect(Math.min(...c.rasters.map((r) => r.pxPerModule)), c.name).toBeGreaterThanOrEqual(3);
    }
    const boundaryRows = ['boundary-3to1', 'boundary-logo-3.5to1', 'inverted-boundary-3to1', 'inverted-logo-7to1'];
    for (const name of boundaryRows) {
      const c = COLOURS.find((row) => row.name === name)!;
      expect(contrastRatio(c.fg, c.bg), name).toBeLessThan(floorOf(c) + 0.1);
    }
    for (const name of ['boundary-logo-3.5to1', 'inverted-boundary-3to1', 'inverted-logo-7to1']) {
      const c = COLOURS.find((row) => row.name === name)!;
      expect(c.rasters.map((r) => r.pxPerModule), name).toEqual(expect.arrayContaining([3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]));
    }
    const inverted = COLOURS.filter((c) => c.name.startsWith('inverted-') && c.name !== 'inverted-midnight');
    for (const c of inverted) expect(c.modules).toEqual(['square', 'dots']);
  });

  /** Every module, eye, logo and frame combination of a row. */
  const combos = (c: ColourRow) =>
    c.modules.flatMap((modules) =>
      EYES.flatMap((eyes) => c.logos.flatMap((logo) => c.frames.map((frame) => ({ modules, eyes, logo, frame })))),
    );

  for (const url of URLS) {
    for (const colour of COLOURS) {
      it(`decodes every shape, logo and frame variant: ${url.length} chars, ${colour.name} [${colour.decoders.join(', ')}]`, async () => {
        const failures: string[] = [];
        let decodes = 0;
        for (const { modules, eyes, logo, frame } of combos(colour)) {
          const style = {
            version: 2,
            presetId: 'test',
            fg: colour.fg,
            bg: colour.bg,
            inverted: colour.inverted,
            modules,
            eyes,
            ecLevel: 'auto',
            quietZone: 4,
            logo: logoStyle(logo),
            // A frame in the code colour with text in the background colour.
            ...(frame === 'none' ? {} : { frame: { template: frame, text: 'Σαρώστε με', color: colour.fg, textColor: colour.bg } }),
          };
          const { meta, drawList } = renderStyled({ data: url, style, logoPng: QRAUTH_LOGO_PNG });
          if (logo !== 'none') {
            expect(meta.logoModules).toBeGreaterThan(0);
            expect(drawList.items.some((it) => it.kind === 'image')).toBe(true);
          }
          for (const r of colour.rasters) {
            const px = meta.width * r.pxPerModule;
            const { svg } = renderStyled({ data: url, style, logoPng: QRAUTH_LOGO_PNG, size: { value: px, unit: 'px' } });
            const png = await raster(svg, r.blur);
            const label = `${modules}/${eyes}/${logo}/${frame}/${r.name}`;
            for (const decoder of colour.decoders) {
              const text = decoder === 'zxing' ? await decodeZxing(png) : await decodeJsQr(png);
              decodes++;
              if (text !== url) failures.push(`${label} ${decoder}=${JSON.stringify(text)}`);
            }
          }
        }
        expect(decodes).toBe(combos(colour).length * colour.rasters.length * colour.decoders.length);
        expect(failures).toEqual([]);
      }, DECODE_TIMEOUT_MS);
    }
  }
});

describe('qr_image_url (create responses)', () => {
  // The four v1 shapes stored in production (2026-10-28), caption text neutral.
  const PROD_V1_SHAPES = [
    { templateId: 'classic', fgColor: '#000000', bgColor: '#FFFFFF', showLogo: false, captionText: 'Scan to verify!' },
    { templateId: 'classic', fgColor: '#000000', bgColor: '#FFFFFF', showLogo: true, captionText: 'Scan to verify!' },
    { templateId: 'custom', fgColor: '#000000', bgColor: '#FFFFFF', showLogo: false, captionText: 'Scan to verify!' },
    { templateId: 'midnight', fgColor: '#E0E0E0', bgColor: '#212121', showLogo: true, captionText: 'Scan to verify!' },
  ];

  async function decodeDataUrl(dataUrl: string): Promise<{ text: string | null; width: number }> {
    expect(dataUrl.startsWith('data:image/png;base64,')).toBe(true);
    const png = Buffer.from(dataUrl.slice('data:image/png;base64,'.length), 'base64');
    const { width } = await sharp(png).metadata();
    return { text: await decodeZxing(png), width: width ?? 0 };
  }

  it.each(['aB3dE5gH', 'Zz9Yy8Xx', 'q2W3e4R5'])('an unstyled code (%s) is a 300 px PNG that decodes to its verify URL', async (token) => {
    const { text, width } = await decodeDataUrl(await qrImageDataUrl({ token }, null));
    expect(width).toBe(300);
    expect(text).toBe(buildVerificationUrl(token));
  });

  it.each(PROD_V1_SHAPES)('stored style $templateId (logo $showLogo) decodes', async (v1) => {
    const { text, width } = await decodeDataUrl(await qrImageDataUrl({ token: 'aB3dE5gH' }, v1));
    expect(width).toBe(300);
    expect(text).toBe(buildVerificationUrl('aB3dE5gH'));
  });
});
