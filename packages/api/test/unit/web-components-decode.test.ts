/**
 * Decode round trip for the web components' QR code (ADR-0005 D5, PR 7).
 *
 * `<qrauth-login>`, `<qrauth-2fa>` and `<qrauth-ephemeral>` draw their code
 * with `qrToSvg` (packages/web-components/src/utils/qr-svg.ts), the shared
 * core renderer. The browser rasterises that SVG; here sharp (librsvg) stands
 * in for it. Every payload the components encode, at the export widths (300,
 * 512, 1024 px), the widths the components draw (320, 440 px), every whole
 * scale from 3 to 16 px/module and a 3 px/module raster with a 1 px blur.
 * zxing-wasm and jsQR must both read back exactly the payload (black on
 * white, so jsQR applies to every row).
 *
 * `fetch` is disabled; the zxing WASM binary is read from node_modules.
 */
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

import sharp from 'sharp';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { prepareZXingModule, readBarcodes } from 'zxing-wasm/reader';
import { CORE_QUIET_ZONE_MIN, encode } from '@qrauth/shared/qr-render/core';

import { qrToSvg } from '../../../web-components/src/utils/qr-svg.js';
import { AUTH_SESSION_URL, EPHEMERAL_CLAIM_URL } from '../../../shared/src/qr-render/__tests__/golden-cases.js';

const require = createRequire(import.meta.url);
const jsQR = require('jsqr') as typeof import('jsqr').default;

const PAYLOADS = [
  { name: 'auth session (login, 2fa)', data: AUTH_SESSION_URL },
  { name: 'ephemeral claim', data: EPHEMERAL_CLAIM_URL },
] as const;

/** The export widths of the decode suite, then the widths the components draw (login and ephemeral 440, 2fa 320). */
const WIDTHS_PX = [300, 512, 1024, 320, 440] as const;
const SWEEP_PX_PER_MODULE = Array.from({ length: 14 }, (_, i) => i + 3);
const BLUR_PX_PER_MODULE = 3;
const BLUR_SIGMA = 1;
const DECODE_TIMEOUT_MS = 60_000;

interface Raster {
  readonly name: string;
  readonly width: number;
  readonly blur: number;
}

/** Modules per side including the components' 4-module quiet zone. */
function sideModules(data: string): number {
  return encode(data, 'M').size + 2 * CORE_QUIET_ZONE_MIN;
}

function rastersFor(data: string): Raster[] {
  const side = sideModules(data);
  return [
    ...WIDTHS_PX.map((width) => ({ name: `${width}px`, width, blur: 0 })),
    ...SWEEP_PX_PER_MODULE.map((ppm) => ({ name: `${ppm}px/module`, width: side * ppm, blur: 0 })),
    { name: `${BLUR_PX_PER_MODULE}px/module-blur${BLUR_SIGMA}`, width: side * BLUR_PX_PER_MODULE, blur: BLUR_SIGMA },
  ];
}

async function rasterise(svg: string, blur: number): Promise<Buffer> {
  const image = sharp(Buffer.from(svg, 'utf8'));
  return (blur > 0 ? image.blur(blur) : image).png().toBuffer();
}

async function decodeZxing(png: Buffer): Promise<string | null> {
  const results = await readBarcodes(new Uint8Array(png), { formats: ['QRCode'], tryHarder: true, tryInvert: true });
  return results.find((r) => r.isValid)?.text ?? null;
}

async function decodeJsQr(png: Buffer): Promise<string | null> {
  const { data, info } = await sharp(png).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  return jsQR(new Uint8ClampedArray(data.buffer, data.byteOffset, data.byteLength), info.width, info.height)?.data ?? null;
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

describe('web components QR decode round trip (qrToSvg, zxing-wasm + jsQR)', () => {
  it('covers the export widths, the component widths and the 3-16 px/module sweep', () => {
    const rasters = rastersFor(AUTH_SESSION_URL);
    expect(rasters.map((r) => r.width)).toEqual(expect.arrayContaining([300, 512, 1024, 320, 440]));
    expect(rasters.filter((r) => r.blur === 0).length).toBe(WIDTHS_PX.length + 14);
  });

  for (const payload of PAYLOADS) {
    it(`decodes ${payload.name} (${payload.data.length} chars) at every raster`, async () => {
      const failures: string[] = [];
      const rasters = rastersFor(payload.data);
      for (const r of rasters) {
        const svg = qrToSvg(payload.data, r.width);
        expect(svg, r.name).not.toBe('');
        const png = await rasterise(svg, r.blur);
        const { width } = await sharp(png).metadata();
        expect(width, r.name).toBe(r.width);
        const zxing = await decodeZxing(png);
        const jsqr = await decodeJsQr(png);
        if (zxing !== payload.data) failures.push(`${r.name} zxing=${JSON.stringify(zxing)}`);
        if (jsqr !== payload.data) failures.push(`${r.name} jsqr=${JSON.stringify(jsqr)}`);
      }
      expect(rasters.length).toBe(WIDTHS_PX.length + SWEEP_PX_PER_MODULE.length + 1);
      expect(failures).toEqual([]);
    }, DECODE_TIMEOUT_MS);
  }
});
