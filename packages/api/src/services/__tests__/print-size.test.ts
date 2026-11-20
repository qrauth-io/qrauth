import { describe, expect, it } from 'vitest';

import { checkModuleSize, printRaster, PrintSizeError } from '../print-size.js';

/**
 * The API wrapper over the shared print arithmetic (@qrauth/shared/qr-render
 * print.ts, tested there): a refusal becomes a PrintSizeError with the
 * route's status and code.
 */

const SQUARE = { width: 41, height: 41 } as const;

function thrown(fn: () => unknown): PrintSizeError {
  try {
    fn();
  } catch (err) {
    if (err instanceof PrintSizeError) return err;
    throw err;
  }
  throw new Error('expected a PrintSizeError');
}

describe('PrintSizeError', () => {
  it('too small: 422 print-size-too-small, a RangeError', () => {
    const err = thrown(() => checkModuleSize(16.3, SQUARE));
    expect(err).toBeInstanceOf(RangeError);
    expect([err.status, err.code]).toEqual([422, 'print-size-too-small']);
    expect(err.message).toContain('needs at least 16.4 mm');
  });

  it('too large: 400 print-raster-too-large', () => {
    const err = thrown(() => printRaster(1000, 1200, SQUARE));
    expect([err.status, err.code]).toEqual([400, 'print-raster-too-large']);
  });

  it('a size within the limits returns the raster', () => {
    expect(printRaster(30, 300, SQUARE)).toEqual({ width: 354, height: 354 });
    expect(() => checkModuleSize(16.4, SQUARE)).not.toThrow();
  });
});
