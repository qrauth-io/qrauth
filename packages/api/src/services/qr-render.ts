import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

import sharp from 'sharp';
import {
  artworkSize as sharedArtworkSize,
  badgeMark,
  displayFrameText,
  canonicalStyleJson,
  parseStoredStyle,
  RENDERER_VERSION,
  renderQr,
  type QrStyleV2,
  type RenderInput,
  type SvgSize,
  type RenderResult,
} from '@qrauth/shared/qr-render';
import { loadFrameFont } from '@qrauth/shared/qr-render/font';

import { buildVerificationUrl } from '../lib/qrcode-access.js';
import { Semaphore, type RunOptions } from '../lib/semaphore.js';
import {
  checkModuleSize,
  PRINT_DPI_DEFAULT,
  PRINT_RASTER_PIXELS_MAX,
  printRaster,
  type ArtworkModules,
  type PrintSize,
} from './print-size.js';
import { drawListToPdf } from './qr-pdf.js';

/**
 * Server render service (ADR-0005 D7): one place that turns a QR code row
 * and its stored style into SVG, PNG or PDF bytes. No request or response
 * coupling, so a worker (bulk export, Milestone 2) can call it too.
 */

export type ExportFormat = 'svg' | 'png' | 'pdf';

/** Screen sizes (`px`): up to 1024 px, which D9 allows on every plan. Print sizes use `print`. */
export const IMAGE_PX_MIN = 64;
export const IMAGE_PX_MAX = 1024;
/** Width of `qr_image_url` in create responses, as before. */
export const QR_IMAGE_URL_PX = 300;

/**
 * Smallest rendered module, in px. A requested width below
 * MIN_PX_PER_MODULE x the artwork width (symbol plus quiet zone) is raised to
 * it; the decode suite covers 3 to 16 px/module (ADR-0005 D5).
 */
export const MIN_PX_PER_MODULE = 3;

/** At most this many PNG rasterisations run at once (D7). SVG is not limited. */
export const PNG_CONCURRENCY = 4;
/** Waiters per lane (issue, export) before a PNG request is refused with 503. */
export const PNG_QUEUE_MAX = 64;
/** Longest a PNG request waits for a slot before it is refused with 503. */
export const PNG_WAIT_TIMEOUT_MS = 10_000;
/** Retry-After (seconds) sent with a 503 when the PNG queue is busy. */
export const RENDER_RETRY_AFTER_SECONDS = 5;

export interface ExportOptions {
  readonly format: ExportFormat;
  /**
   * Screen size: output width in px. Required for a PNG without `print`;
   * optional for SVG (scalable when omitted). Never with `print` or PDF.
   */
  readonly px?: number;
  /**
   * Print size (PR 6): the artwork width in mm, with `dpi` for PNG (default
   * 300) and `marginMm` for PDF. Required for PDF. An SVG with a print size
   * carries it as `width`/`height` in mm.
   */
  readonly print?: PrintSize;
}

export interface ExportResult {
  readonly contentType: string;
  readonly body: Buffer;
  /** Width actually rendered in px, after the minimum module size; undefined for SVG without `px` and for PDF. */
  readonly px: number | undefined;
  /** Parts of the style that could not be drawn (a customer logo whose bytes are missing). */
  readonly notDrawn: readonly ('frame' | 'logo')[];
}

/** The QR code fields rendering needs. */
export interface RenderableQr {
  readonly token: string;
  /**
   * The issuing organization is a verified issuer (`isIssuerVerified` from
   * @qrauth/shared, read from the organization row by the caller). It picks
   * the badge mark's wording: "Verified by QRAuth" or "Signed with QRAuth"
   * (ADR-0005 D9, amendment of 2026-10-30).
   */
  readonly issuerVerified: boolean;
}

/**
 * The QRAuth logo as a 512x512 PNG. The file ships in @qrauth/shared
 * (assets/qrauth-logo.png); the dashboard preview draws the same bytes.
 */
export const QRAUTH_LOGO_PNG: Uint8Array = readFileSync(
  createRequire(import.meta.url).resolve('@qrauth/shared/assets/qrauth-logo.png'),
);

/**
 * The frame font (ADR-0005 PR 5): the subset Noto Sans that ships in
 * @qrauth/shared (assets/fonts, SIL OFL 1.1). The dashboard preview fetches
 * the same file and outlines frame text with the same code, so previews and
 * exports agree byte for byte. Read from disk, never fetched.
 */
export const FRAME_FONT_BYTES: Uint8Array = readFileSync(
  createRequire(import.meta.url).resolve('@qrauth/shared/assets/fonts/NotoSans-SemiBold-frames.ttf'),
);
export const FRAME_FONT = loadFrameFont(FRAME_FONT_BYTES);
/** sha256 of the frame font, part of every export's ETag. */
export const FRAME_FONT_SHA256 = createHash('sha256').update(FRAME_FONT_BYTES).digest('hex');

/** renderQr with the frame font: every server render outlines frame text the same way. */
export function renderStyled(input: Omit<RenderInput, 'font'>): RenderResult {
  return renderQr({ ...input, font: FRAME_FONT });
}

/**
 * The PNG limiter (lib/semaphore.ts): issuance (create and bulk responses)
 * is served before exports; each lane is capped and waits time out.
 */
export const pngLimiter = new Semaphore({
  limit: PNG_CONCURRENCY,
  maxQueue: PNG_QUEUE_MAX,
  timeoutMs: PNG_WAIT_TIMEOUT_MS,
});

/** Reads a stored `style` column: null (no style) gives DEFAULT_STYLE, v1 is upgraded. */
export function styleForRender(stored: unknown): QrStyleV2 {
  return parseStoredStyle(stored);
}

/**
 * Logo bytes for a style. `{kind: "qrauth"}` is the QRAuth logo;
 * `{kind: "asset"}` is `assetLogo`, the organization's normalised PNG
 * (loadLogoBytes). A customer logo whose bytes are not available renders
 * with its area excavated and left empty, and `notDrawn` reports it.
 */
export function logoBytesFor(style: QrStyleV2, assetLogo: Uint8Array | null = null): Uint8Array | null {
  if (style.logo?.kind === 'qrauth') return QRAUTH_LOGO_PNG;
  if (style.logo?.kind === 'asset') return assetLogo;
  return null;
}

/** Reads an organization's logo bytes (services/logo-library.ts). */
export interface LogoSource {
  bytes(organizationId: string, assetId: string): Promise<Uint8Array | null>;
}

/** The logo bytes `style` draws for a code of `organizationId`, loading a customer logo from `logos`. */
export async function loadLogoBytes(style: QrStyleV2, organizationId: string, logos: LogoSource): Promise<Uint8Array | null> {
  const assetLogo = style.logo?.kind === 'asset' ? await logos.bytes(organizationId, style.logo.assetId) : null;
  return logoBytesFor(style, assetLogo);
}

function checkPx(px: number | undefined, required: boolean): void {
  if (px === undefined) {
    if (required) throw new RangeError('px is required for PNG');
    return;
  }
  if (!Number.isInteger(px) || px < IMAGE_PX_MIN || px > IMAGE_PX_MAX) {
    throw new RangeError(`px must be an integer from ${IMAGE_PX_MIN} to ${IMAGE_PX_MAX}`);
  }
}

/** Artwork size in modules: symbol plus quiet zone on both sides, plus the frame. */
export function artworkSize(qr: RenderableQr, style: QrStyleV2): ArtworkModules {
  return sharedArtworkSize(buildVerificationUrl(qr.token), style);
}

/** Artwork width in modules: symbol plus quiet zone on both sides, plus the frame. */
export function artworkModules(qr: RenderableQr, style: QrStyleV2): number {
  return artworkSize(qr, style).width;
}

/** Combinations the route also rejects (400); checked here so other callers cannot make them. */
function checkFormatSizing(opts: ExportOptions): void {
  if (opts.print && opts.px !== undefined) throw new RangeError('px and a print size are mutually exclusive');
  if (opts.format === 'pdf' && !opts.print) throw new RangeError('PDF needs a print size');
  if (opts.print?.dpi !== undefined && opts.format !== 'png') throw new RangeError('dpi applies to PNG only');
  if (opts.print?.marginMm !== undefined && opts.format !== 'pdf') throw new RangeError('margin applies to PDF only');
}

/**
 * The width to render, in px. Screen sizes: `px` raised to
 * MIN_PX_PER_MODULE x the artwork width; undefined stays undefined (a
 * scalable SVG). Print PNG: round(size_mm / 25.4 x dpi), never raised (that
 * would change the physical size). Print SVG and PDF: undefined (sized in
 * mm). Throws RangeError for a `px` outside IMAGE_PX_MIN..IMAGE_PX_MAX or a
 * missing `px` for a screen PNG, and PrintSizeError (a RangeError) for a
 * print size above the raster caps or with modules below the minimum.
 */
export function effectivePx(qr: RenderableQr, style: QrStyleV2, opts: ExportOptions): number | undefined {
  checkFormatSizing(opts);
  if (opts.print) {
    const art = artworkSize(qr, style);
    if (opts.format !== 'png') {
      checkModuleSize(opts.print.sizeMm, art);
      return undefined;
    }
    return printRaster(opts.print.sizeMm, opts.print.dpi ?? PRINT_DPI_DEFAULT, art).width;
  }
  checkPx(opts.px, opts.format === 'png');
  if (opts.px === undefined) return undefined;
  return Math.max(opts.px, MIN_PX_PER_MODULE * artworkModules(qr, style));
}

/** The badge mark `style` draws for `qr`, or null when it draws no badge. */
export function exportBadgeMark(qr: RenderableQr, style: QrStyleV2): string | null {
  return style.frame?.template === 'badge' ? badgeMark(qr.issuerVerified) : null;
}

/**
 * True when `style`'s frame text draws differently from the stored text for
 * `qr`: the old default caption on an unverified issuer's code draws as
 * "Signed with QRAuth" (ADR-0005 D9, 2026-10-30).
 */
export function exportFrameTextReplaced(qr: RenderableQr, style: QrStyleV2): boolean {
  const frame = style.frame;
  if (!frame || frame.template === 'none') return false;
  return displayFrameText(frame.text, qr.issuerVerified) !== frame.text;
}

/**
 * Strong ETag of an export (D7): renderer version, style schema version,
 * canonical style, logo hash, frame font hash, the badge mark's wording
 * (so a change in the issuer's verification changes the tag of a badge
 * image, D9 2026-10-30), `text=signed` when the old default caption draws
 * as "Signed with QRAuth" (other images keep their tags), verification
 * URL, format and size (`px`, or the print size: size_mm, dpi and
 * margin_mm). Screen-size tags are unchanged by PR 6.
 */
export function exportEtag(qr: RenderableQr, style: QrStyleV2, logoBytes: Uint8Array | null, opts: ExportOptions): string {
  const logoHash = logoBytes ? createHash('sha256').update(logoBytes).digest('hex') : 'none';
  const parts = [
    `renderer=${RENDERER_VERSION}`,
    `style=${style.version}`,
    canonicalStyleJson(style),
    `logo=${logoHash}`,
    `font=${FRAME_FONT_SHA256}`,
    `mark=${exportBadgeMark(qr, style) ?? 'none'}`,
    ...(exportFrameTextReplaced(qr, style) ? ['text=signed'] : []),
    buildVerificationUrl(qr.token),
    `format=${opts.format}`,
    `px=${opts.px ?? 'auto'}`,
    ...(opts.print
      ? [`size_mm=${opts.print.sizeMm}`, `dpi=${opts.print.dpi ?? 'none'}`, `margin_mm=${opts.print.marginMm ?? 'none'}`]
      : []),
  ];
  return `"${createHash('sha256').update(parts.join('|')).digest('hex')}"`;
}

function svgSize(opts: ExportOptions, px: number | undefined): SvgSize | undefined {
  if (px !== undefined) return { value: px, unit: 'px' };
  if (opts.print && opts.format === 'svg') return { value: opts.print.sizeMm, unit: 'mm' };
  return undefined;
}

/**
 * Render a code in `format`. PNG is rasterised from the SVG by sharp and PDF
 * drawn from the draw list by pdfkit (vector), at most PNG_CONCURRENCY at a
 * time (pngLimiter). Screen widths are raised to the minimum module size
 * (effectivePx); `px` in the result is the width rendered. Throws
 * RangeError for an invalid size (PrintSizeError for a refused print size).
 */
export async function renderExport(
  qr: RenderableQr,
  style: QrStyleV2,
  logoBytes: Uint8Array | null,
  opts: ExportOptions,
  run: RunOptions = {},
): Promise<ExportResult> {
  const px = effectivePx(qr, style, opts);
  const size = svgSize(opts, px);
  const { svg, drawList, meta } = renderStyled({
    data: buildVerificationUrl(qr.token),
    style,
    logoPng: logoBytes,
    issuerVerified: qr.issuerVerified,
    ...(size ? { size } : {}),
  });

  if (opts.format === 'svg') {
    return { contentType: 'image/svg+xml; charset=utf-8', body: Buffer.from(svg, 'utf8'), px, notDrawn: meta.notDrawn };
  }

  if (opts.format === 'pdf' && opts.print) {
    const page = { sizeMm: opts.print.sizeMm, marginMm: opts.print.marginMm ?? 0, title: `QR code ${qr.token}` };
    const body = await pngLimiter.run(() => drawListToPdf(drawList, page), run);
    return { contentType: 'application/pdf', body, px: undefined, notDrawn: meta.notDrawn };
  }

  const density = opts.print ? (opts.print.dpi ?? PRINT_DPI_DEFAULT) : undefined;
  return { contentType: 'image/png', body: await rasterisePng(svg, run, density), px, notDrawn: meta.notDrawn };
}

/**
 * Input limits for rasterisation. The SVG comes from a buffer, so librsvg has
 * no base location and resolves no external reference (http, file or
 * relative); `unlimited: false` keeps libvips' guards against oversized and
 * deeply nested input on. A test proves no external fetch or file read.
 */
/**
 * sharp's operation cache never hits here (every SVG is a new buffer) and
 * only holds memory: 400 renders at 1024 px measured 150 MB peak RSS with it,
 * 144 MB without, at the same 12.7 ms per render.
 */
sharp.cache(false);

/**
 * A frame makes the artwork taller than wide (at most about 1.3 times, the
 * badge on the smallest symbol); the cap leaves room for twice the width.
 */
export const RASTER_MAX_ASPECT = 2;

/** Input pixel cap for screen sizes (and create responses). */
const SCREEN_RASTER_PIXELS_MAX = IMAGE_PX_MAX * IMAGE_PX_MAX * RASTER_MAX_ASPECT;

/**
 * A print raster above this many pixels is large: large rasters run one at a
 * time (largeRasterLimiter), so the worst case is one 100-megapixel render
 * beside three smaller ones, not four at once (PR 6 notes).
 */
export const LARGE_RASTER_PIXELS = 16_000_000;

/** One large print raster at a time; it waits for this slot before a pngLimiter slot, with the same policy. */
export const largeRasterLimiter = new Semaphore({
  limit: 1,
  maxQueue: 8,
  timeoutMs: PNG_WAIT_TIMEOUT_MS,
});

const ROOT_SIZE = /^<svg[^>]* width="([0-9.]+)" height="([0-9.]+)"/;

/** Pixels of a renderer SVG's root width x height (px), or 0 for a scalable SVG. */
function svgPixels(svg: string): number {
  const match = ROOT_SIZE.exec(svg);
  return match ? Math.ceil(Number(match[1])) * Math.ceil(Number(match[2])) : 0;
}

/**
 * The production raster path: sharp (librsvg) turns a renderer SVG into a
 * PNG at the SVG's own width and height, through pngLimiter (default lane:
 * export). `density` (dpi) marks a print raster: it is written to the PNG's
 * pHYs chunk and allows up to PRINT_RASTER_PIXELS_MAX; screen PNGs keep
 * sharp's default (72 dpi), as before. The renderer emits only `data:` image
 * references.
 */
export async function rasterisePng(svg: string, run: RunOptions = {}, density?: number): Promise<Buffer> {
  const input = {
    unlimited: false,
    limitInputPixels: density !== undefined ? PRINT_RASTER_PIXELS_MAX : SCREEN_RASTER_PIXELS_MAX,
  } as const;
  const raster = (): Promise<Buffer> => {
    const image = sharp(Buffer.from(svg, 'utf8'), input).png();
    return (density !== undefined ? image.withDensity(density) : image).toBuffer();
  };
  if (svgPixels(svg) <= LARGE_RASTER_PIXELS) return pngLimiter.run(raster, run);
  return largeRasterLimiter.run(() => pngLimiter.run(raster, run), run);
}

/**
 * The image for a create response could not be rendered (queue busy, sharp
 * failure). Creation stops before anything is stored; the route answers 503.
 */
export class RenderUnavailableError extends Error {
  constructor(cause: unknown) {
    super('QR image rendering is unavailable', { cause });
    this.name = 'RenderUnavailableError';
  }
}

/**
 * `qr_image_url` for create responses: the stored style as a 300 px PNG data
 * URL, on the issuance lane. `assetLogo` is the customer logo's bytes when
 * the style draws one. Any failure is a RenderUnavailableError.
 */
export async function qrImageDataUrl(qr: RenderableQr, storedStyle: unknown, assetLogo: Uint8Array | null = null): Promise<string> {
  try {
    const style = styleForRender(storedStyle);
    const logo = logoBytesFor(style, assetLogo);
    const { body } = await renderExport(qr, style, logo, { format: 'png', px: QR_IMAGE_URL_PX }, { lane: 'issue' });
    return `data:image/png;base64,${body.toString('base64')}`;
  } catch (err) {
    throw new RenderUnavailableError(err);
  }
}
