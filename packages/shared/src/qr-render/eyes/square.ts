// SPDX-License-Identifier: MIT
import { SQUARE } from '../shape.js';
import type { EyeShape } from './types.js';

export const squareEye: EyeShape = {
  outer: SQUARE,
  hole: SQUARE,
  inner: SQUARE,
  alignRing: SQUARE,
  alignHole: SQUARE,
  alignCentre: SQUARE,
};
