// SPDX-License-Identifier: MIT
import type { Radii } from '../shape.js';
import type { EyeShape } from './types.js';

const all = (r: number): Radii => [r, r, r, r];
const diagonal = (r: number): Radii => [r, 0, r, 0];

/** Rounded corners on every corner. */
export const roundedEye: EyeShape = {
  outer: all(2),
  hole: all(1),
  inner: all(1),
  alignRing: all(1.25),
  alignHole: all(0.75),
  alignCentre: all(0.3),
};

/** Full radii: rings become circles, blocks become discs. */
export const circleEye: EyeShape = {
  outer: all(3.5),
  hole: all(2.5),
  inner: all(1.5),
  alignRing: all(2.5),
  alignHole: all(1.5),
  alignCentre: all(0.5),
};

/** Top-left and bottom-right corners rounded, the other two square. */
export const leafEye: EyeShape = {
  outer: diagonal(3),
  hole: diagonal(2),
  inner: diagonal(1.5),
  alignRing: diagonal(2),
  alignHole: diagonal(1),
  alignCentre: diagonal(0.5),
};
