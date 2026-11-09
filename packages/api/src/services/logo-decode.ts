import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

import sharp from 'sharp';
import { prepareZXingModule, readBarcodes } from 'zxing-wasm/reader';
import type { QrStyleV2 } from '@qrauth/shared/qr-render';

import { IMAGE_PX_MAX, MIN_PX_PER_MODULE, QR_IMAGE_URL_PX, rasterisePng, renderStyled } from './qr-render.js';

/**
 * Save-time decode round trip for styles with a customer logo (ADR-0005
 * PR 4). Customer logos vary far more than the QRAuth logo the contrast
 * floors were measured with (D4.1), so before such a style is stored the
 * code is rendered, rasterised through the production path and decoded with
 * zxing-wasm at the export widths and raster scales. Any raster that does
 * not read back the exact URL, and only that URL, rejects the style (422).
 */

/**
 * One raster of the check, sized either by whole pixels per module or, like
 * an export, by its width in px (usually a non-integer px/module).
 */
export type DecodeRaster = {
  /** How the raster is named in the 422 message, e.g. "300 px wide". */
  readonly name: string;
  /** Gaussian blur sigma applied after rasterising (0 = none). */
  readonly blur: number;
} & ({ readonly pxPerModule: number; readonly widthPx?: never } | { readonly widthPx: number; readonly pxPerModule?: never });

/**
 * Export widths checked as the server renders them: `qr_image_url` (300 px),
 * the 512 px default image and the 1024 px dashboard and screen maximum.
 */
export const DECODE_EXPORT_WIDTHS: readonly number[] = [QR_IMAGE_URL_PX, 512, IMAGE_PX_MAX];

/** Largest scale checked: the D5 sweep's top end. */
export const DECODE_MAX_PX_PER_MODULE = 16;

/**
 * The export widths (DECODE_EXPORT_WIDTHS), every whole scale from
 * MIN_PX_PER_MODULE (3) to 16 px/module, and D5's blurred 3 px/module raster
 * as a cheap print and camera degradation. D5's 8 px/module raster is in the
 * sweep.
 */
export const DECODE_RASTERS: readonly DecodeRaster[] = [
  ...DECODE_EXPORT_WIDTHS.map((widthPx) => ({ name: `${widthPx} px wide`, widthPx, blur: 0 })),
  ...Array.from({ length: DECODE_MAX_PX_PER_MODULE - MIN_PX_PER_MODULE + 1 }, (_, i) => ({
    name: `${i + MIN_PX_PER_MODULE} px per module`,
    pxPerModule: i + MIN_PX_PER_MODULE,
    blur: 0,
  })),
  { name: '3 px per module, blurred', pxPerModule: 3, blur: 1 },
];

/**
 * The width the server would render `raster` at, for artwork `modules`
 * wide: an export width is raised to MIN_PX_PER_MODULE per module, as
 * effectivePx (qr-render.ts) does. Null when the width cannot be exported
 * (above IMAGE_PX_MAX).
 */
export function rasterWidth(raster: DecodeRaster, modules: number): number | null {
  const width =
    raster.widthPx !== undefined
      ? Math.max(raster.widthPx, MIN_PX_PER_MODULE * modules)
      : raster.pxPerModule * modules;
  return width > IMAGE_PX_MAX ? null : width;
}

export class LogoUnreadableError extends Error {
  constructor(readonly raster: string) {
    super(`The code did not read back at ${raster}`);
    this.name = 'LogoUnreadableError';
  }
}

let zxingReady: Promise<unknown> | null = null;

/**
 * Loads the zxing WASM binary from node_modules. The library's default is to
 * fetch it from a CDN; the API never does.
 */
function ensureZxing(): Promise<unknown> {
  if (!zxingReady) {
    const require = createRequire(import.meta.url);
    const wasm = readFileSync(require.resolve('zxing-wasm/reader/zxing_reader.wasm'));
    zxingReady = prepareZXingModule({
      overrides: { wasmBinary: wasm.buffer.slice(wasm.byteOffset, wasm.byteOffset + wasm.byteLength) },
      fireImmediately: true,
    }).catch((err: unknown) => {
      zxingReady = null;
      throw err;
    });
  }
  return zxingReady;
}

/**
 * True when the raster reads back as `data` and as nothing else: a logo that
 * itself holds a readable code (another URL) is refused too.
 */
async function readsBackAs(png: Buffer, data: string): Promise<boolean> {
  const results = await readBarcodes(new Uint8Array(png), { formats: ['QRCode'], tryHarder: true, tryInvert: true, maxNumberOfSymbols: 4 });
  const texts = results.filter((r) => r.isValid).map((r) => r.text);
  return texts.length > 0 && texts.every((text) => text === data);
}

/**
 * Renders `data` with `style` and `logoPng` at every DECODE_RASTERS raster
 * that the server can export (rasterWidth) and decodes each. Resolves when
 * all read back `data`; throws LogoUnreadableError naming the first raster
 * that did not. Rasterisation goes through the PNG
 * limiter's issue lane, one raster at a time.
 */
export async function assertLogoScans(
  data: string,
  style: QrStyleV2,
  logoPng: Uint8Array,
  rasters: readonly DecodeRaster[] = DECODE_RASTERS,
): Promise<void> {
  await ensureZxing();
  const { meta } = renderStyled({ data, style, logoPng });
  for (const raster of rasters) {
    const width = rasterWidth(raster, meta.width);
    if (width === null) continue;
    const { svg } = renderStyled({ data, style, logoPng, size: { value: width, unit: 'px' } });
    const png = await rasterisePng(svg, { lane: 'issue' });
    const input = raster.blur > 0 ? await sharp(png).blur(raster.blur).png().toBuffer() : png;
    if (!(await readsBackAs(input, data))) throw new LogoUnreadableError(raster.name);
  }
}
