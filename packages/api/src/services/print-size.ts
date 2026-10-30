import {
  moduleSizeRefusal,
  printRasterOrRefusal,
  type ArtworkModules,
  type PrintSizeRefusal,
} from '@qrauth/shared/qr-render';

/**
 * Print sizing for the image endpoint (ADR-0005 D7, PR 6). The limits and
 * arithmetic live in `@qrauth/shared/qr-render` (print.ts) so the dashboard
 * checks the same values; this module turns a refusal into an error the
 * route answers.
 */

export {
  inchesToMm,
  maxPrintWidthMm,
  minPrintWidthMm,
  mmToPoints,
  PDF_MARGIN_MM_MAX,
  PDF_MARGIN_MM_MIN,
  PRINT_DPI_DEFAULT,
  PRINT_DPI_MAX,
  PRINT_DPI_MIN,
  PRINT_MODULE_MM_MIN,
  PRINT_PX_PER_MODULE_MIN,
  PRINT_RASTER_PIXELS_MAX,
  PRINT_RASTER_SIDE_MAX,
  PRINT_SIZE_IN_MAX,
  PRINT_SIZE_IN_MIN,
  PRINT_SIZE_MM_DEFAULT,
  PRINT_SIZE_MM_MAX,
  PRINT_SIZE_MM_MIN,
  printPxHeight,
  printPxWidth,
  roundMm,
  type ArtworkModules,
} from '@qrauth/shared/qr-render';

/** A requested print size, normalised (mm to 0.1 mm). */
export interface PrintSize {
  /** Artwork width in mm, rounded to 0.1 mm. */
  readonly sizeMm: number;
  /** PNG only: dots per inch. */
  readonly dpi?: number;
  /** PDF only: margin on every side, in mm, rounded to 0.1 mm. */
  readonly marginMm?: number;
}

/**
 * A print size the endpoint refuses for this code. `status` is 400 for a
 * raster above the caps (the message states the maximum) and 422 for a code
 * that would print too small (the message states the minimum).
 */
export class PrintSizeError extends RangeError {
  readonly status: PrintSizeRefusal['status'];
  readonly code: PrintSizeRefusal['code'];

  constructor(refusal: PrintSizeRefusal) {
    super(refusal.message);
    this.name = 'PrintSizeError';
    this.status = refusal.status;
    this.code = refusal.code;
  }
}

/** Throws PrintSizeError when modules would be under 0.4 mm at `sizeMm` (any format with a physical size). */
export function checkModuleSize(sizeMm: number, art: ArtworkModules): void {
  const refusal = moduleSizeRefusal(sizeMm, art);
  if (refusal) throw new PrintSizeError(refusal);
}

/** The raster of a print PNG: width and height in px, within the caps. Throws PrintSizeError. */
export function printRaster(sizeMm: number, dpi: number, art: ArtworkModules): { width: number; height: number } {
  const result = printRasterOrRefusal(sizeMm, dpi, art);
  if ('refusal' in result) throw new PrintSizeError(result.refusal);
  return { width: result.width, height: result.height };
}
