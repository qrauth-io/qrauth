import { createHash } from 'node:crypto';

import sharp, { type Metadata, type OutputInfo } from 'sharp';
import { LOGO_PNG_MAX_BYTES } from '@qrauth/shared/qr-render';

/**
 * Customer logo upload sanitisation (ADR-0005 D6, D9). The declared type is
 * not trusted: the magic bytes decide. Only PNG, JPEG and WebP are decoded;
 * SVG is refused. The decoded image is oriented, converted to sRGB, stripped
 * of metadata, fitted inside 512x512 and re-encoded as PNG. Only that PNG is
 * kept; the upload is discarded.
 */

/** Largest upload, equal to the route's bodyLimit (D9). */
export const LOGO_UPLOAD_MAX_BYTES = 1024 * 1024;
/** Smallest and largest decoded side, in px. */
export const LOGO_SIDE_MIN = 64;
export const LOGO_SIDE_MAX = 2048;
/** The normalised PNG fits inside this square. */
export const LOGO_NORMALISED_MAX = 512;
/** Decoder pixel cap: 2048 x 2048. */
export const LOGO_INPUT_PIXELS_MAX = LOGO_SIDE_MAX * LOGO_SIDE_MAX;

export const LOGO_UPLOAD_TYPES = ['image/png', 'image/jpeg', 'image/webp'] as const;
export type LogoUploadType = (typeof LOGO_UPLOAD_TYPES)[number];

export type LogoRejection =
  | 'unsupported-type'
  | 'svg-not-accepted'
  | 'too-large'
  | 'animated'
  | 'dimensions'
  | 'unreadable'
  | 'too-complex';

export class LogoRejectedError extends Error {
  constructor(
    readonly code: LogoRejection,
    message: string,
  ) {
    super(message);
    this.name = 'LogoRejectedError';
  }
}

export interface NormalisedLogo {
  readonly png: Uint8Array;
  readonly width: number;
  readonly height: number;
  readonly sha256: string;
}

const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

function startsWith(bytes: Uint8Array, prefix: readonly number[], offset = 0): boolean {
  return bytes.length >= offset + prefix.length && prefix.every((b, i) => bytes[offset + i] === b);
}

const ascii = (s: string): number[] => Array.from(s, (c) => c.charCodeAt(0));

/** The image type from the magic bytes, or null. */
export function sniffImageType(bytes: Uint8Array): LogoUploadType | null {
  if (startsWith(bytes, PNG_SIGNATURE)) return 'image/png';
  if (startsWith(bytes, [0xff, 0xd8, 0xff])) return 'image/jpeg';
  if (startsWith(bytes, ascii('RIFF')) && startsWith(bytes, ascii('WEBP'), 8)) return 'image/webp';
  return null;
}

/** True for input that looks like SVG or other XML: optional BOM and whitespace, then `<`. */
function looksLikeMarkup(bytes: Uint8Array): boolean {
  const head = Buffer.from(bytes.subarray(0, 512)).toString('utf8').replace(/^﻿/, '').trimStart();
  return head.startsWith('<');
}

/**
 * True when a PNG has an acTL chunk before its first IDAT (an animated PNG).
 * libvips decodes only the first frame of an APNG, so this is checked here.
 */
export function isAnimatedPng(bytes: Uint8Array): boolean {
  const view = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = PNG_SIGNATURE.length;
  while (offset + 8 <= view.length) {
    const length = view.readUInt32BE(offset);
    const type = view.toString('latin1', offset + 4, offset + 8);
    if (type === 'acTL') return true;
    if (type === 'IDAT' || type === 'IEND') return false;
    offset += 12 + length;
  }
  return false;
}

const DECODE_OPTIONS = { limitInputPixels: LOGO_INPUT_PIXELS_MAX, failOn: 'error' } as const;

async function readMetadata(bytes: Uint8Array): Promise<Metadata> {
  try {
    return await sharp(bytes, DECODE_OPTIONS).metadata();
  } catch (err) {
    if (err instanceof Error && /pixel limit/i.test(err.message)) {
      throw new LogoRejectedError('dimensions', `The image may be at most ${LOGO_SIDE_MAX}x${LOGO_SIDE_MAX} px.`);
    }
    throw new LogoRejectedError('unreadable', 'The image could not be read.');
  }
}

/**
 * Validates and normalises an uploaded logo. Throws LogoRejectedError with a
 * code and a message that can be shown to the uploader.
 */
export async function normaliseLogo(bytes: Uint8Array): Promise<NormalisedLogo> {
  if (bytes.length > LOGO_UPLOAD_MAX_BYTES) {
    throw new LogoRejectedError('too-large', 'The logo may be at most 1 MiB.');
  }
  const type = sniffImageType(bytes);
  if (!type) {
    if (looksLikeMarkup(bytes)) {
      throw new LogoRejectedError('svg-not-accepted', 'SVG logos are not accepted. Upload a PNG, JPEG or WebP image.');
    }
    throw new LogoRejectedError('unsupported-type', 'Upload a PNG, JPEG or WebP image.');
  }
  if (type === 'image/png' && isAnimatedPng(bytes)) {
    throw new LogoRejectedError('animated', 'Animated images are not accepted.');
  }

  const meta = await readMetadata(bytes);
  if ((meta.pages ?? 1) > 1) {
    throw new LogoRejectedError('animated', 'Animated or multi-page images are not accepted.');
  }
  const { width = 0, height = 0 } = meta;
  if (width < LOGO_SIDE_MIN || height < LOGO_SIDE_MIN || width > LOGO_SIDE_MAX || height > LOGO_SIDE_MAX) {
    throw new LogoRejectedError(
      'dimensions',
      `Each side must be from ${LOGO_SIDE_MIN} to ${LOGO_SIDE_MAX} px; this image is ${width}x${height} px.`,
    );
  }

  let out: { data: Buffer; info: OutputInfo };
  try {
    out = await sharp(bytes, DECODE_OPTIONS)
      .rotate() // EXIF orientation
      .toColourspace('srgb')
      .resize({ width: LOGO_NORMALISED_MAX, height: LOGO_NORMALISED_MAX, fit: 'inside', withoutEnlargement: true })
      .png({ compressionLevel: 9 })
      .toBuffer({ resolveWithObject: true });
  } catch {
    throw new LogoRejectedError('unreadable', 'The image could not be read.');
  }
  // The renderer embeds at most LOGO_PNG_MAX_BYTES; only noise-like images exceed it at 512 px.
  if (out.data.length > LOGO_PNG_MAX_BYTES) {
    throw new LogoRejectedError('too-complex', 'The image is too detailed to use as a logo. Try a simpler image.');
  }
  return {
    png: new Uint8Array(out.data),
    width: out.info.width,
    height: out.info.height,
    sha256: createHash('sha256').update(out.data).digest('hex'),
  };
}
