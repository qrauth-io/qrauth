// SPDX-License-Identifier: MIT
import { fmt } from '../format.js';
import type { ModuleBuilder } from './types.js';

/** Square modules, merged into one rectangle per horizontal run. */
export const squareModules: ModuleBuilder = ({ size, x, y, isOn }) => {
  let d = '';
  for (let row = 0; row < size; row++) {
    let col = 0;
    while (col < size) {
      if (!isOn(col, row)) {
        col++;
        continue;
      }
      const start = col;
      while (col < size && isOn(col, row)) col++;
      const run = col - start;
      d += `M${fmt(start + x)} ${fmt(row + y)}h${fmt(run)}v1h${fmt(-run)}z`;
    }
  }
  return d;
};
