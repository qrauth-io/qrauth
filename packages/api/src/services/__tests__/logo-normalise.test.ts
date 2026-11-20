import { randomBytes } from 'node:crypto';

import sharp from 'sharp';
import { describe, expect, it } from 'vitest';

import {
  isAnimatedPng,
  LOGO_NORMALISED_MAX,
  LOGO_SIDE_MAX,
  LOGO_SIDE_MIN,
  LOGO_UPLOAD_MAX_BYTES,
  LogoRejectedError,
  normaliseLogo,
  sniffImageType,
} from '../logo-normalise.js';

/**
 * Logo upload sanitisation (ADR-0005 D6, D9): magic-byte sniffing, PNG/JPEG/
 * WebP only, SVG refused, animated and multi-page input refused, 64..2048 px
 * per side, EXIF orientation applied, sRGB, metadata stripped, fitted in
 * 512x512 and re-encoded as PNG.
 */

const solid = (width: number, height: number, channels: 3 | 4 = 4) =>
  sharp({ create: { width, height, channels, background: { r: 200, g: 30, b: 60, alpha: 1 } } });

const png = (w: number, h: number): Promise<Buffer> => solid(w, h).png().toBuffer();

async function rejection(input: Uint8Array): Promise<LogoRejectedError> {
  try {
    await normaliseLogo(input);
  } catch (err) {
    if (err instanceof LogoRejectedError) return err;
    throw err;
  }
  throw new Error('expected a rejection');
}

/** Inserts an acTL chunk after IHDR, which makes a PNG an APNG for every reader that checks. */
function withAcTl(pngBytes: Buffer): Buffer {
  const ihdrEnd = 8 + 12 + pngBytes.readUInt32BE(8);
  const chunk = Buffer.alloc(20);
  chunk.writeUInt32BE(8, 0);
  chunk.write('acTL', 4, 'latin1');
  chunk.writeUInt32BE(2, 8); // frames
  chunk.writeUInt32BE(0, 12); // plays
  // CRC is not checked by the sniffer; libvips is never asked to decode this.
  return Buffer.concat([pngBytes.subarray(0, ihdrEnd), chunk, pngBytes.subarray(ihdrEnd)]);
}

describe('sniffImageType: the magic bytes decide, not the declared type', () => {
  it('recognises PNG, JPEG and WebP', async () => {
    expect(sniffImageType(await png(64, 64))).toBe('image/png');
    expect(sniffImageType(await solid(64, 64, 3).jpeg().toBuffer())).toBe('image/jpeg');
    expect(sniffImageType(await solid(64, 64).webp().toBuffer())).toBe('image/webp');
  });

  it('returns null for GIF, SVG and arbitrary bytes', async () => {
    expect(sniffImageType(await solid(64, 64).gif().toBuffer())).toBeNull();
    expect(sniffImageType(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"/>'))).toBeNull();
    expect(sniffImageType(Buffer.from('RIFF0000WAVE'))).toBeNull();
    expect(sniffImageType(new Uint8Array())).toBeNull();
  });
});

describe('normaliseLogo: accepted input', () => {
  it.each([
    ['PNG', () => png(256, 256)],
    ['JPEG', () => solid(256, 256, 3).jpeg().toBuffer()],
    ['WebP', () => solid(256, 256).webp().toBuffer()],
  ])('%s becomes a PNG with its sha256, width and height', async (_label, make) => {
    const out = await normaliseLogo(await make());
    expect(sniffImageType(out.png)).toBe('image/png');
    expect(out).toMatchObject({ width: 256, height: 256 });
    expect(out.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it('fits a large image inside 512x512, keeping its aspect ratio', async () => {
    const out = await normaliseLogo(await png(2048, 1024));
    expect([out.width, out.height]).toEqual([LOGO_NORMALISED_MAX, LOGO_NORMALISED_MAX / 2]);
  });

  it('does not enlarge a small image', async () => {
    const out = await normaliseLogo(await png(LOGO_SIDE_MIN, 100));
    expect([out.width, out.height]).toEqual([LOGO_SIDE_MIN, 100]);
  });

  it('applies the EXIF orientation', async () => {
    // Orientation 6: rotate 90 degrees clockwise to display.
    const input = await solid(100, 200, 3).jpeg().withMetadata({ orientation: 6 }).toBuffer();
    const out = await normaliseLogo(input);
    expect([out.width, out.height]).toEqual([200, 100]);
  });

  it('strips EXIF and ICC metadata and outputs sRGB', async () => {
    const input = await solid(128, 128, 3)
      .jpeg()
      .withMetadata({ orientation: 1, icc: 'p3' })
      .withExif({ IFD0: { Copyright: 'someone', Artist: 'someone' } })
      .toBuffer();
    const inMeta = await sharp(input).metadata();
    expect(inMeta.exif).toBeDefined();
    expect(inMeta.icc).toBeDefined();

    const out = await sharp((await normaliseLogo(input)).png).metadata();
    expect(out.exif).toBeUndefined();
    expect(out.icc).toBeUndefined();
    expect(out.xmp).toBeUndefined();
    expect(out.space).toBe('srgb');
  });

  it('converts greyscale input to sRGB', async () => {
    const grey = await solid(128, 128, 3).toColourspace('b-w').png().toBuffer();
    expect((await sharp(grey).metadata()).channels).toBe(1);
    const out = await sharp((await normaliseLogo(grey)).png).metadata();
    expect(out.space).toBe('srgb');
    expect(out.channels).toBeGreaterThanOrEqual(3);
  });

  it('is deterministic: the same upload gives the same bytes and hash', async () => {
    const input = await png(300, 300);
    const [a, b] = await Promise.all([normaliseLogo(input), normaliseLogo(input)]);
    expect(a.sha256).toBe(b.sha256);
  });
});

describe('normaliseLogo: refused input', () => {
  it('refuses SVG with its own message', async () => {
    for (const svg of [
      '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
      '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"/>',
      '﻿  \n<svg/>',
    ]) {
      const err = await rejection(Buffer.from(svg, 'utf8'));
      expect(err.code).toBe('svg-not-accepted');
    }
  });

  it('refuses GIF and other formats', async () => {
    expect((await rejection(await solid(64, 64).gif().toBuffer())).code).toBe('unsupported-type');
    expect((await rejection(await solid(64, 64).tiff().toBuffer())).code).toBe('unsupported-type');
    expect((await rejection(randomBytes(256))).code).toBe('unsupported-type');
  });

  it('refuses a declared PNG whose bytes are not an image', async () => {
    // PNG signature followed by garbage: sniffed as PNG, then fails to decode.
    const fake = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), randomBytes(200)]);
    expect((await rejection(fake)).code).toBe('unreadable');
  });

  it('refuses input over 1 MiB', async () => {
    const big = Buffer.concat([await png(64, 64), Buffer.alloc(LOGO_UPLOAD_MAX_BYTES)]);
    expect((await rejection(big)).code).toBe('too-large');
  });

  it.each([
    ['narrower than 64 px', 63, 200],
    ['shorter than 64 px', 200, 63],
    ['wider than 2048 px', 2049, 100],
    ['taller than 2048 px', 100, 2049],
  ])('refuses an image %s', async (_label, w, h) => {
    const err = await rejection(await solid(w, h, 3).png({ palette: true }).toBuffer());
    expect(err.code).toBe('dimensions');
  });

  it('accepts the boundary sizes 64 and 2048 px', async () => {
    await expect(normaliseLogo(await png(LOGO_SIDE_MIN, LOGO_SIDE_MIN))).resolves.toBeDefined();
    await expect(normaliseLogo(await solid(LOGO_SIDE_MAX, 64, 3).png({ palette: true }).toBuffer())).resolves.toBeDefined();
  });

  it('refuses an animated WebP', async () => {
    const red = await png(64, 64);
    const blue = await sharp({ create: { width: 64, height: 64, channels: 4, background: '#0000ff' } }).png().toBuffer();
    const animated = await sharp([red, blue], { join: { animated: true } }).webp().toBuffer();
    expect((await sharp(animated).metadata()).pages).toBe(2);
    expect((await rejection(animated)).code).toBe('animated');
  });

  it('refuses an animated PNG (acTL chunk)', async () => {
    const apng = withAcTl(await png(64, 64));
    expect(isAnimatedPng(apng)).toBe(true);
    expect(isAnimatedPng(await png(64, 64))).toBe(false);
    expect((await rejection(apng)).code).toBe('animated');
  });

  it('refuses a normalised image larger than the renderer embeds', async () => {
    // Noise does not compress: 512x512 RGBA noise is under 1 MiB as lossless
    // WebP but over 1 MiB as PNG.
    const noise = await sharp(randomBytes(512 * 512 * 4), { raw: { width: 512, height: 512, channels: 4 } })
      .webp({ lossless: true })
      .toBuffer();
    expect(noise.length).toBeLessThanOrEqual(LOGO_UPLOAD_MAX_BYTES);
    expect((await rejection(noise)).code).toBe('too-complex');
  });
});
