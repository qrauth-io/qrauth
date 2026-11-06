// SPDX-License-Identifier: MIT
import { roundedRect, type Radii } from '../shape.js';
import type { ModuleBuilder, ModuleGrid } from './types.js';

const R = 0.5;

/** Which corners of a module get the radius, decided by its four neighbours. */
type CornerRule = (top: boolean, right: boolean, bottom: boolean, left: boolean) => Radii;

/** Shared walk for the per-module rounded styles. */
export function cornerModules(grid: ModuleGrid, rule: CornerRule): string {
  const { size, x, y, isOn } = grid;
  let d = '';
  for (let row = 0; row < size; row++) {
    for (let col = 0; col < size; col++) {
      if (!isOn(col, row)) continue;
      const radii = rule(
        !isOn(col, row - 1),
        !isOn(col + 1, row),
        !isOn(col, row + 1),
        !isOn(col - 1, row),
      );
      d += roundedRect(col + x, row + y, 1, 1, radii);
    }
  }
  return d;
}

/**
 * Rounds only the outer corners of connected runs: a corner is rounded when
 * both neighbours that share it are light.
 */
export const roundedModules: ModuleBuilder = (grid) =>
  cornerModules(grid, (top, right, bottom, left) => [
    top && left ? R : 0,
    top && right ? R : 0,
    bottom && right ? R : 0,
    bottom && left ? R : 0,
  ]);
