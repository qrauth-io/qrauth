// SPDX-License-Identifier: MIT
import { MIN_MODULE_MM } from './scan-rules.js';

/**
 * Print sizing for exports (ADR-0005 D7, PR 6): the limits and the
 * arithmetic that turn a physical size into a raster or a PDF page. The API
 * enforces them on the image endpoint; the dashboard checks the same values
 * before it asks. Pure: no rendering.
 *
 * A print size is the full artwork width (code, quiet zone and frame); the
 * height follows the artwork's aspect ratio.
 */

/** Artwork width, in mm. */
export const PRINT_SIZE_MM_MIN = 10;
export const PRINT_SIZE_MM_MAX = 1000;
/** The same range in inches (10 mm and 1000 mm, rounded inwards). */
export const PRINT_SIZE_IN_MIN = 0.4;
export const PRINT_SIZE_IN_MAX = 39.37;
/** Default artwork width when a print export gives no size. */
export const PRINT_SIZE_MM_DEFAULT = 50;

/** PNG resolution, dots per inch (whole numbers). */
export const PRINT_DPI_MIN = 72;
export const PRINT_DPI_MAX = 1200;
export const PRINT_DPI_DEFAULT = 300;

/** PDF margin around the artwork, in mm, on every side. */
export const PDF_MARGIN_MM_MIN = 0;
export const PDF_MARGIN_MM_MAX = 50;

/**
 * Raster caps for a print PNG: at most 12,000 px per side and 100
 * megapixels in all. The largest square render is 10,000 x 10,000 px
 * (846.6 mm at 300 dpi, 423.3 mm at 600 dpi, 211.6 mm at 1200 dpi).
 */
export const PRINT_RASTER_SIDE_MAX = 12_000;
export const PRINT_RASTER_PIXELS_MAX = 100_000_000;

/** Smallest printed module, in mm (`MIN_MODULE_MM`, D4.6): a print size with smaller modules is refused. */
export const PRINT_MODULE_MM_MIN = MIN_MODULE_MM;

/**
 * Smallest rendered module of a print PNG, in px: the 3 px floor of screen
 * sizes (D5). A print PNG is never enlarged to reach it (that would change
 * its physical size), so a size and dpi below it are refused.
 */
export const PRINT_PX_PER_MODULE_MIN = 3;

const MM_PER_INCH = 25.4;

/** Artwork size in modules (symbol, quiet zone and frame). */
export interface ArtworkModules {
  readonly width: number;
  readonly height: number;
}

/** Why a print size is refused: 400 above the raster caps (states the maximum), 422 too small (states the minimum). */
export interface PrintSizeRefusal {
  readonly status: 400 | 422;
  readonly code: 'print-raster-too-large' | 'print-size-too-small';
  readonly message: string;
}

/** Rounds a length in mm to 0.1 mm, the precision print sizes are kept at. */
export function roundMm(mm: number): number {
  return Math.round(mm * 10) / 10;
}

/** Inches to mm, rounded to 0.1 mm. */
export function inchesToMm(inches: number): number {
  return roundMm(inches * MM_PER_INCH);
}

/** mm to PDF points (1/72 in). */
export function mmToPoints(mm: number): number {
  return (mm * 72) / MM_PER_INCH;
}

/** Pixel width of a print PNG: round(size_mm / 25.4 x dpi) (D7). */
export function printPxWidth(sizeMm: number, dpi: number): number {
  return Math.round((sizeMm / MM_PER_INCH) * dpi);
}

/** Pixel height that keeps the artwork's aspect ratio at `pxWidth`. */
export function printPxHeight(pxWidth: number, art: ArtworkModules): number {
  return Math.round((pxWidth * art.height) / art.width);
}

function fmtMm(mm: number): string {
  return `${Number(mm.toFixed(1))} mm`;
}

/** Smallest artwork width at which every module is at least PRINT_MODULE_MM_MIN wide. */
export function minPrintWidthMm(art: ArtworkModules): number {
  // The epsilon keeps float noise (0.4 x 41 = 16.400000000000002) from rounding up a step.
  return Math.ceil(PRINT_MODULE_MM_MIN * art.width * 10 - 1e-9) / 10;
}

function exceedsCaps(width: number, height: number): boolean {
  return width > PRINT_RASTER_SIDE_MAX || height > PRINT_RASTER_SIDE_MAX || width * height > PRINT_RASTER_PIXELS_MAX;
}

/** Largest artwork width (0.1 mm steps), at `dpi`, whose raster stays within the side and pixel caps. */
export function maxPrintWidthMm(art: ArtworkModules, dpi: number): number {
  const aspect = art.height / art.width;
  const maxPx = Math.min(PRINT_RASTER_SIDE_MAX / Math.max(1, aspect), Math.sqrt(PRINT_RASTER_PIXELS_MAX / aspect));
  // Estimate, then step down past the pixel rounding of printPxWidth/printPxHeight.
  let tenths = Math.min(PRINT_SIZE_MM_MAX * 10, Math.floor(((maxPx * MM_PER_INCH) / dpi) * 10));
  for (;;) {
    const width = printPxWidth(tenths / 10, dpi);
    if (tenths <= 0 || !exceedsCaps(width, printPxHeight(width, art))) return tenths / 10;
    tenths -= 1;
  }
}

/** Refusal for modules under PRINT_MODULE_MM_MIN at `sizeMm` (any format with a physical size), or null. */
export function moduleSizeRefusal(sizeMm: number, art: ArtworkModules): PrintSizeRefusal | null {
  const moduleMm = sizeMm / art.width;
  if (moduleMm + 1e-9 >= PRINT_MODULE_MM_MIN) return null;
  return {
    status: 422,
    code: 'print-size-too-small',
    message: `At ${fmtMm(sizeMm)} each module of this code would be ${moduleMm.toFixed(2)} mm; the minimum is ${PRINT_MODULE_MM_MIN} mm, so this code needs at least ${fmtMm(minPrintWidthMm(art))}.`,
  };
}

/** The raster of a print PNG (width and height in px), or why it is refused. */
export function printRasterOrRefusal(
  sizeMm: number,
  dpi: number,
  art: ArtworkModules,
): { readonly width: number; readonly height: number } | { readonly refusal: PrintSizeRefusal } {
  const tooSmall = moduleSizeRefusal(sizeMm, art);
  if (tooSmall) return { refusal: tooSmall };
  const width = printPxWidth(sizeMm, dpi);
  const height = printPxHeight(width, art);
  if (exceedsCaps(width, height)) {
    return {
      refusal: {
        status: 400,
        code: 'print-raster-too-large',
        message: `The image would be ${width} x ${height} px; the maximum is ${PRINT_RASTER_SIDE_MAX.toLocaleString('en-US')} px per side and ${PRINT_RASTER_PIXELS_MAX / 1_000_000} megapixels. At ${dpi} dpi this code can be at most ${fmtMm(maxPrintWidthMm(art, dpi))} wide.`,
      },
    };
  }
  if (width / art.width < PRINT_PX_PER_MODULE_MIN) {
    const minDpi = Math.ceil((PRINT_PX_PER_MODULE_MIN * art.width * MM_PER_INCH) / sizeMm);
    return {
      refusal: {
        status: 422,
        code: 'print-size-too-small',
        message: `At ${fmtMm(sizeMm)} and ${dpi} dpi each module would be under ${PRINT_PX_PER_MODULE_MIN} px; use at least ${minDpi} dpi or a larger size.`,
      },
    };
  }
  return { width, height };
}
