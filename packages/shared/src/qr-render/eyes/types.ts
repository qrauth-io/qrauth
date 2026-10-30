// SPDX-License-Identifier: MIT
import { roundedRect, type Radii } from '../shape.js';

export type EyeStyle = 'square' | 'rounded' | 'circle' | 'leaf';

/**
 * Corner radii for one eye family. Every family keeps the finder geometry
 * readers rely on: a 7x7 outer ring 1 module thick, a 1-module light ring and
 * a 3x3 inner block (1:1:3:1:1). Only corner radii change. Alignment
 * patterns (5x5 ring and 1x1 centre) use the same family (ADR-0005 D2).
 */
export interface EyeShape {
  readonly outer: Radii;
  readonly hole: Radii;
  readonly inner: Radii;
  readonly alignRing: Radii;
  readonly alignHole: Radii;
  readonly alignCentre: Radii;
}

/** Finder outer ring with the 5x5 cut-out, at top-left (x, y). */
export function eyeOuterPath(shape: EyeShape, x: number, y: number): string {
  return roundedRect(x, y, 7, 7, shape.outer) + roundedRect(x + 1, y + 1, 5, 5, shape.hole, true);
}

/** Finder 3x3 inner block, at the finder's top-left (x, y). */
export function eyeInnerPath(shape: EyeShape, x: number, y: number): string {
  return roundedRect(x + 2, y + 2, 3, 3, shape.inner);
}

/** Alignment pattern centred on module (cx, cy): 5x5 ring plus 1x1 centre. */
export function alignmentPath(shape: EyeShape, cx: number, cy: number): string {
  return (
    roundedRect(cx - 2, cy - 2, 5, 5, shape.alignRing) +
    roundedRect(cx - 1, cy - 1, 3, 3, shape.alignHole, true) +
    roundedRect(cx, cy, 1, 1, shape.alignCentre)
  );
}
