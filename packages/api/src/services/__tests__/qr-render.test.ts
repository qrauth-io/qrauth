import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import sharp from 'sharp';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  canonicalStyleJson,
  DEFAULT_STYLE,
  encode,
  frameLayout,
  RENDERER_VERSION,
  type QrFrame,
  type QrStyleV2,
} from '@qrauth/shared/qr-render';

process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

const {
  artworkModules,
  effectivePx,
  exportEtag,
  FRAME_FONT_SHA256,
  IMAGE_PX_MAX,
  IMAGE_PX_MIN,
  loadLogoBytes,
  logoBytesFor,
  MIN_PX_PER_MODULE,
  PNG_CONCURRENCY,
  qrImageDataUrl,
  QRAUTH_LOGO_PNG,
  rasterisePng,
  renderExport,
  styleForRender,
} = await import('../qr-render.js');
const { buildVerificationUrl } = await import('../../lib/qrcode-access.js');

const QR = { token: 'aB3dE5gH', issuerVerified: false };
const QR_VERIFIED = { ...QR, issuerVerified: true };
const LOGO_STYLE: QrStyleV2 = { ...DEFAULT_STYLE, logo: { kind: 'qrauth' } };

describe('styleForRender', () => {
  it('no stored style renders as DEFAULT_STYLE', () => {
    expect(styleForRender(null)).toEqual(DEFAULT_STYLE);
  });

  it('a stored v1 style is upgraded', () => {
    const v1 = { templateId: 'midnight', fgColor: '#E0E0E0', bgColor: '#212121', showLogo: true, captionText: '' };
    expect(styleForRender(v1)).toMatchObject({ version: 2, fg: '#E0E0E0', inverted: true, logo: { kind: 'qrauth' } });
  });
});

describe('logoBytesFor', () => {
  it('QRAuth logo for {kind: "qrauth"}, a 512x512 PNG', async () => {
    expect(logoBytesFor(LOGO_STYLE)).toBe(QRAUTH_LOGO_PNG);
    const meta = await sharp(Buffer.from(QRAUTH_LOGO_PNG)).metadata();
    expect([meta.format, meta.width, meta.height]).toEqual(['png', 512, 512]);
  });

  it('nothing without a logo, and nothing for a customer logo whose bytes are not loaded', () => {
    expect(logoBytesFor(DEFAULT_STYLE)).toBeNull();
    expect(logoBytesFor({ ...DEFAULT_STYLE, logo: { kind: 'asset', assetId: 'a1', scale: 1 } })).toBeNull();
  });

  it('the loaded bytes for a customer logo, and never for the other kinds', () => {
    const bytes = new Uint8Array([1, 2, 3]);
    expect(logoBytesFor({ ...DEFAULT_STYLE, logo: { kind: 'asset', assetId: 'a1', scale: 1 } }, bytes)).toBe(bytes);
    expect(logoBytesFor(LOGO_STYLE, bytes)).toBe(QRAUTH_LOGO_PNG);
    expect(logoBytesFor(DEFAULT_STYLE, bytes)).toBeNull();
  });
});

describe('loadLogoBytes', () => {
  const ASSET_STYLE = { ...DEFAULT_STYLE, logo: { kind: 'asset' as const, assetId: 'a1', scale: 1 } };

  it('reads a customer logo from the code’s organization', async () => {
    const bytes = new Uint8Array([7]);
    const logos = { bytes: vi.fn(async () => bytes) };
    expect(await loadLogoBytes(ASSET_STYLE, 'org_1', logos)).toBe(bytes);
    expect(logos.bytes).toHaveBeenCalledWith('org_1', 'a1');
  });

  it('does not read the library for the QRAuth logo or no logo', async () => {
    const logos = { bytes: vi.fn(async () => null) };
    expect(await loadLogoBytes(LOGO_STYLE, 'org_1', logos)).toBe(QRAUTH_LOGO_PNG);
    expect(await loadLogoBytes(DEFAULT_STYLE, 'org_1', logos)).toBeNull();
    expect(logos.bytes).not.toHaveBeenCalled();
  });
});

describe('renderExport', () => {
  it('SVG: scalable without px, sized with px', async () => {
    const plain = await renderExport(QR, DEFAULT_STYLE, null, { format: 'svg' });
    expect(plain.contentType).toBe('image/svg+xml; charset=utf-8');
    const svg = plain.body.toString('utf8');
    expect(svg.startsWith('<svg')).toBe(true);
    expect(svg).toContain(`data-renderer="qrauth-qr/${RENDERER_VERSION}"`);
    expect(svg).not.toContain('width=');
    const sized = await renderExport(QR, DEFAULT_STYLE, null, { format: 'svg', px: 512 });
    expect(sized.body.toString('utf8')).toContain('width="512" height="512"');
  });

  it.each([300, IMAGE_PX_MAX])('PNG at %i px is exactly that size', async (px) => {
    const result = await renderExport(QR, DEFAULT_STYLE, null, { format: 'png', px });
    expect(result.contentType).toBe('image/png');
    expect(result.px).toBe(px);
    const meta = await sharp(result.body).metadata();
    expect([meta.format, meta.width, meta.height]).toEqual(['png', px, px]);
  });

  it.each([undefined, IMAGE_PX_MIN - 1, IMAGE_PX_MAX + 1, 300.5])('PNG rejects px %s', async (px) => {
    await expect(renderExport(QR, DEFAULT_STYLE, null, { format: 'png', px })).rejects.toThrow(RangeError);
  });

  it('draws the QRAuth logo as an inline data: image', async () => {
    const { body, notDrawn } = await renderExport(QR, LOGO_STYLE, QRAUTH_LOGO_PNG, { format: 'svg' });
    expect(body.toString('utf8')).toContain('xlink:href="data:image/png;base64,');
    expect(notDrawn).toEqual([]);
  });

  it('draws a v1 caption as a caption frame with outlined text', async () => {
    const style = styleForRender({ templateId: 'c', fgColor: '#000000', bgColor: '#FFFFFF', showLogo: false, captionText: 'Hi' });
    const { body, notDrawn } = await renderExport(QR, style, null, { format: 'svg' });
    expect(notDrawn).toEqual([]);
    expect(body.toString('utf8')).not.toContain('<text');
    expect(body.toString('utf8')).toContain(`data-renderer="qrauth-qr/${RENDERER_VERSION}"`);
  });
});

const FRAME_TEMPLATES = ['caption', 'banner-bottom', 'banner-top', 'rounded-label', 'badge'] as const;
const framed = (template: QrFrame['template'], text = 'Σαρώστε με'): QrStyleV2 => ({
  ...DEFAULT_STYLE,
  frame: { template, text, color: '#1B2A4A', textColor: '#FFFFFF' },
});

describe('frames in exports (PR 5)', () => {
  const symbol = encode(buildVerificationUrl(QR.token), 'M').size;
  const side = symbol + 2 * DEFAULT_STYLE.quietZone;

  it.each(FRAME_TEMPLATES)('%s: the PNG is the framed artwork at the requested width', async (template) => {
    const layout = frameLayout(template, side);
    expect(artworkModules(QR, framed(template))).toBe(layout.width);
    const result = await renderExport(QR, framed(template), null, { format: 'png', px: IMAGE_PX_MAX });
    const meta = await sharp(result.body).metadata();
    expect(meta.width).toBe(IMAGE_PX_MAX);
    expect(meta.height).toBe(Math.round((IMAGE_PX_MAX * layout.height) / layout.width));
  });

  it.each(FRAME_TEMPLATES)('%s: the quiet zone and code are pixel-identical to the unframed code', async (template) => {
    const ppm = 8;
    const layout = frameLayout(template, side);
    const plain = await renderExport(QR, DEFAULT_STYLE, null, { format: 'png', px: side * ppm });
    const withFrame = await renderExport(QR, framed(template), null, { format: 'png', px: layout.width * ppm });
    const raw = (png: Buffer, crop?: { left: number; top: number; width: number; height: number }) =>
      (crop ? sharp(png).extract(crop) : sharp(png)).ensureAlpha().raw().toBuffer();
    const inner = await raw(withFrame.body, { left: layout.codeX * ppm, top: layout.codeY * ppm, width: side * ppm, height: side * ppm });
    expect(inner.equals(await raw(plain.body))).toBe(true);
  });

  it('minimum module size counts the frame width', () => {
    const style = framed('badge');
    expect(effectivePx(QR, style, { format: 'png', px: IMAGE_PX_MIN })).toBe(frameLayout('badge', side).width * MIN_PX_PER_MODULE);
  });
});

describe('minimum module size (3 px/module)', () => {
  const modules = artworkModules(QR, DEFAULT_STYLE);

  it('raises a width below 3 px x the artwork width to it, and reports it', async () => {
    expect(MIN_PX_PER_MODULE).toBe(3);
    expect(modules * MIN_PX_PER_MODULE).toBeGreaterThan(IMAGE_PX_MIN);
    const result = await renderExport(QR, DEFAULT_STYLE, null, { format: 'png', px: IMAGE_PX_MIN });
    expect(result.px).toBe(modules * MIN_PX_PER_MODULE);
    const meta = await sharp(result.body).metadata();
    expect(meta.width).toBe(modules * MIN_PX_PER_MODULE);
  });

  it('applies to sized SVG; a scalable SVG has no width', async () => {
    const sized = await renderExport(QR, DEFAULT_STYLE, null, { format: 'svg', px: IMAGE_PX_MIN });
    expect(sized.px).toBe(modules * MIN_PX_PER_MODULE);
    expect(sized.body.toString('utf8')).toContain(`width="${modules * MIN_PX_PER_MODULE}"`);
    expect((await renderExport(QR, DEFAULT_STYLE, null, { format: 'svg' })).px).toBeUndefined();
  });

  it('counts the quiet zone: a wider quiet zone raises the minimum', () => {
    const wide = { ...DEFAULT_STYLE, quietZone: 10 };
    expect(artworkModules(QR, wide)).toBe(modules + 12);
    expect(effectivePx(QR, wide, { format: 'png', px: IMAGE_PX_MIN })).toBe((modules + 12) * MIN_PX_PER_MODULE);
  });

  it('qr_image_url grows past 300 px for a code wider than 100 modules', async () => {
    const big = { token: 'x'.repeat(900), issuerVerified: false };
    const width = artworkModules(big, DEFAULT_STYLE);
    expect(width).toBeGreaterThan(100);
    const png = Buffer.from((await qrImageDataUrl(big, null)).split(',')[1], 'base64');
    expect((await sharp(png).metadata()).width).toBe(width * MIN_PX_PER_MODULE);
  });
});

describe('exportEtag', () => {
  const base = exportEtag(QR, DEFAULT_STYLE, null, { format: 'png', px: 300 });

  it('includes the frame font hash (the font bytes shipped in @qrauth/shared)', () => {
    const font = readFileSync(createRequire(import.meta.url).resolve('@qrauth/shared/assets/fonts/NotoSans-SemiBold-frames.ttf'));
    expect(FRAME_FONT_SHA256).toBe(createHash('sha256').update(font).digest('hex'));
    const parts = [
      `renderer=${RENDERER_VERSION}`,
      'style=2',
      canonicalStyleJson(DEFAULT_STYLE),
      'logo=none',
      `font=${FRAME_FONT_SHA256}`,
      'mark=none',
      buildVerificationUrl(QR.token),
      'format=png',
      'px=300',
    ];
    expect(base).toBe(`"${createHash('sha256').update(parts.join('|')).digest('hex')}"`);
  });

  it('changes with the frame text', () => {
    const a = exportEtag(QR, framed('banner-bottom', 'Scan'), null, { format: 'png', px: 300 });
    expect(a).not.toBe(exportEtag(QR, framed('banner-bottom', 'Scan me'), null, { format: 'png', px: 300 }));
  });

  it('is a stable strong ETag', () => {
    expect(base).toMatch(/^"[0-9a-f]{64}"$/);
    expect(exportEtag(QR, { ...DEFAULT_STYLE }, null, { format: 'png', px: 300 })).toBe(base);
  });

  it.each<[string, () => string]>([
    ['token', () => exportEtag({ ...QR, token: 'other123' }, DEFAULT_STYLE, null, { format: 'png', px: 300 })],
    ['style', () => exportEtag(QR, { ...DEFAULT_STYLE, modules: 'dots' }, null, { format: 'png', px: 300 })],
    ['logo bytes', () => exportEtag(QR, LOGO_STYLE, QRAUTH_LOGO_PNG, { format: 'png', px: 300 })],
    ['format', () => exportEtag(QR, DEFAULT_STYLE, null, { format: 'svg', px: 300 })],
    ['px', () => exportEtag(QR, DEFAULT_STYLE, null, { format: 'png', px: 301 })],
  ])('changes with the %s', (_label, other) => {
    expect(other()).not.toBe(base);
  });

  it('changes with the issuer status for a badge, which changes its mark (D9, 2026-10-30)', () => {
    const badge = framed('badge', 'Scan me');
    const opts = { format: 'png', px: 300 } as const;
    const signed = exportEtag(QR, badge, null, opts);
    const verified = exportEtag(QR_VERIFIED, badge, null, opts);
    expect(verified).not.toBe(signed);
    const parts = (mark: string) => [
      `renderer=${RENDERER_VERSION}`,
      'style=2',
      canonicalStyleJson(badge),
      'logo=none',
      `font=${FRAME_FONT_SHA256}`,
      `mark=${mark}`,
      buildVerificationUrl(QR.token),
      'format=png',
      'px=300',
    ];
    const tag = (mark: string) => `"${createHash('sha256').update(parts(mark).join('|')).digest('hex')}"`;
    expect(signed).toBe(tag('Signed with QRAuth'));
    expect(verified).toBe(tag('Verified by QRAuth'));
  });

  it('does not change with the issuer status when the style draws no badge', () => {
    expect(exportEtag(QR_VERIFIED, DEFAULT_STYLE, null, { format: 'png', px: 300 })).toBe(base);
    const banner = framed('banner-bottom', 'Scan me');
    expect(exportEtag(QR_VERIFIED, banner, null, { format: 'png', px: 300 })).toBe(exportEtag(QR, banner, null, { format: 'png', px: 300 }));
  });

  it('changes with the issuer status when the old default caption draws as "Signed with QRAuth" (D9, 2026-10-30)', () => {
    const caption = framed('caption', 'QRAuth Verified');
    const opts = { format: 'png', px: 300 } as const;
    const signed = exportEtag(QR, caption, null, opts);
    const verified = exportEtag(QR_VERIFIED, caption, null, opts);
    expect(signed).not.toBe(verified);
    const parts = (extra: string[]) => [
      `renderer=${RENDERER_VERSION}`,
      'style=2',
      canonicalStyleJson(caption),
      'logo=none',
      `font=${FRAME_FONT_SHA256}`,
      'mark=none',
      ...extra,
      buildVerificationUrl(QR.token),
      'format=png',
      'px=300',
    ];
    const tag = (extra: string[]) => `"${createHash('sha256').update(parts(extra).join('|')).digest('hex')}"`;
    expect(signed).toBe(tag(['text=signed']));
    // The verified tag is the one every caption image had before the rule.
    expect(verified).toBe(tag([]));
  });

  it('ignores colour case (canonical style)', () => {
    expect(exportEtag(QR, { ...DEFAULT_STYLE, fg: '#000000', bg: '#ffffff' }, null, { format: 'png', px: 300 })).toBe(base);
  });
});

describe('PNG concurrency', () => {
  it(`runs at most ${PNG_CONCURRENCY} rasterisations at once`, async () => {
    const pipeline = sharp.prototype;
    let active = 0;
    let peak = 0;
    const original = pipeline.toBuffer;
    pipeline.toBuffer = async function (this: sharp.Sharp, ...args: unknown[]) {
      active++;
      peak = Math.max(peak, active);
      try {
        await new Promise((r) => setTimeout(r, 20));
        return await (original as (...a: unknown[]) => Promise<Buffer>).apply(this, args);
      } finally {
        active--;
      }
    } as typeof original;
    try {
      await Promise.all(Array.from({ length: 12 }, () => renderExport(QR, DEFAULT_STYLE, null, { format: 'png', px: 64 })));
    } finally {
      pipeline.toBuffer = original;
    }
    expect(peak).toBe(PNG_CONCURRENCY);
  });
});

// sharp/librsvg must not fetch or read anything an SVG references (D7).
describe('rasterisation never follows external references', () => {
  let server: Server;
  let hits: string[] = [];
  let base = '';
  const dir = mkdtempSync(join(tmpdir(), 'qr-render-'));
  const RED_PNG = join(dir, 'red.png');

  beforeAll(async () => {
    writeFileSync(RED_PNG, await sharp({ create: { width: 64, height: 64, channels: 3, background: '#FF0000' } }).png().toBuffer());
    server = createServer((req, res) => {
      hits.push(req.url ?? '');
      res.writeHead(200, { 'content-type': 'image/png' });
      res.end();
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await new Promise((r) => server.close(r));
  });

  const svgWith = (body: string, prolog = ''): string =>
    `${prolog}<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="64" height="64" viewBox="0 0 64 64"><rect width="64" height="64" fill="#FFFFFF"/>${body}</svg>`;

  /** True when any pixel of the PNG is (near) pure red, i.e. the file image was drawn. */
  async function hasRed(png: Buffer): Promise<boolean> {
    const { data, info } = await sharp(png).removeAlpha().raw().toBuffer({ resolveWithObject: true });
    for (let i = 0; i < data.length; i += info.channels) {
      if (data[i] > 200 && data[i + 1] < 60 && data[i + 2] < 60) return true;
    }
    return false;
  }

  /** Rasterise; an input librsvg refuses outright also counts as "not followed". */
  async function raster(svg: string): Promise<Buffer | null> {
    try {
      return await rasterisePng(svg);
    } catch {
      return null;
    }
  }

  const nested = (href: string): string =>
    `data:image/svg+xml;base64,${Buffer.from(svgWith(`<image width="64" height="64" xlink:href="${href}"/>`)).toString('base64')}`;

  it.each<[string, () => string]>([
    ['<image> http', () => svgWith(`<image width="64" height="64" href="${base}/image.png"/>`)],
    ['<image> xlink:href http', () => svgWith(`<image width="64" height="64" xlink:href="${base}/xlink.png"/>`)],
    ['<use> http', () => svgWith(`<use href="${base}/sprite.svg#a"/>`)],
    ['CSS @import and url()', () => svgWith(`<style>@import url("${base}/style.css"); rect { fill: url("${base}/fill.svg#p"); }</style>`)],
    ['<feImage> http', () => svgWith(`<filter id="f"><feImage href="${base}/fe.png"/></filter><rect width="64" height="64" filter="url(#f)"/>`)],
    ['nested SVG in a data: image, referencing http', () => svgWith(`<image width="64" height="64" href="${nested(`${base}/nested.png`)}"/>`)],
  ])('%s: no request reaches the server', async (_label, svg) => {
    hits = [];
    await raster(svg());
    expect(hits).toEqual([]);
  });

  it.each<[string, () => string]>([
    ['file: URL', () => svgWith(`<image width="64" height="64" href="file://${RED_PNG}"/>`)],
    ['absolute path', () => svgWith(`<image width="64" height="64" href="${RED_PNG}"/>`)],
    ['relative path', () => svgWith('<image width="64" height="64" href="red.png"/>')],
    ['nested SVG in a data: image, referencing a file', () => svgWith(`<image width="64" height="64" href="${nested(`file://${RED_PNG}`)}"/>`)],
  ])('%s: renders, without the local file', async (_label, svg) => {
    const png = await raster(svg());
    expect(png).not.toBeNull();
    expect(await hasRed(png!)).toBe(false);
  });

  it('control: the same red image as an inline data: PNG is drawn', async () => {
    const red = (await sharp({ create: { width: 64, height: 64, channels: 3, background: '#FF0000' } }).png().toBuffer()).toString('base64');
    const png = await rasterisePng(svgWith(`<image width="64" height="64" href="data:image/png;base64,${red}"/>`));
    expect(await hasRed(png)).toBe(true);
  });

  it.each<[string, () => string]>([
    ['a local file', () => `file://${join(dir, 'red.png')}`],
    ['an http URL', () => `${base}/entity.txt`],
  ])('an external XML entity naming %s is refused at parse', async (_label, target) => {
    hits = [];
    const svg = svgWith('<text x="0" y="40" font-size="40">&ext;</text>', `<!DOCTYPE svg [<!ENTITY ext SYSTEM "${target()}">]>`);
    await expect(rasterisePng(svg)).rejects.toThrow(/XML parse error/);
    expect(hits).toEqual([]);
  });
});
