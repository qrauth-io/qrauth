// SPDX-License-Identifier: MIT
import { circle } from '../shape.js';
import type { ModuleBuilder } from './types.js';

/** Dot radius in modules (ADR-0005 D2). */
export const DOT_RADIUS = 0.45;

/** One circle of radius 0.45 module per dark module. */
export const dotModules: ModuleBuilder = ({ size, x, y, isOn }) => {
  let d = '';
  for (let row = 0; row < size; row++) {
    for (let col = 0; col < size; col++) {
      if (isOn(col, row)) d += circle(col + x + 0.5, row + y + 0.5, DOT_RADIUS);
    }
  }
  return d;
};
