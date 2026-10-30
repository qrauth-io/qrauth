// SPDX-License-Identifier: MIT
import { cornerModules } from './rounded.js';
import type { ModuleBuilder } from './types.js';

const R = 0.5;

/** Rounds the top-left and bottom-right corners where both sides are exposed. */
export const classyModules: ModuleBuilder = (grid) =>
  cornerModules(grid, (top, right, bottom, left) => [
    top && left ? R : 0,
    0,
    bottom && right ? R : 0,
    0,
  ]);
