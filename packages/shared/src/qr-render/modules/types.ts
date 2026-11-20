// SPDX-License-Identifier: MIT

/**
 * Input to a module path builder. `isOn(col, row)` is true for a dark module
 * drawn in the module layer; it is false outside the symbol, and for finder,
 * alignment and excavated modules. `(x, y)` is where module (0, 0) is drawn:
 * the quiet zone, plus the frame's offset when there is one.
 */
export interface ModuleGrid {
  readonly size: number;
  readonly x: number;
  readonly y: number;
  isOn(col: number, row: number): boolean;
}

/** Builds the `d` attribute of the single module-layer path. */
export type ModuleBuilder = (grid: ModuleGrid) => string;

export type ModuleStyle = 'square' | 'rounded' | 'dots' | 'classy';
