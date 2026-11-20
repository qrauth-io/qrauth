// SPDX-License-Identifier: MIT
import { fmt } from './format.js';

/** Corner radii in module units: top-left, top-right, bottom-right, bottom-left. */
export type Radii = readonly [number, number, number, number];

export const SQUARE: Radii = [0, 0, 0, 0];

function arc(r: number, dx: number, dy: number, sweep: 0 | 1): string {
  return `a${fmt(r)} ${fmt(r)} 0 0 ${sweep} ${fmt(dx)} ${fmt(dy)}`;
}

function line(cmd: 'h' | 'v', d: number): string {
  return d === 0 ? '' : `${cmd}${fmt(d)}`;
}

/**
 * Closed sub-path of a rectangle with per-corner radii. `hole` reverses the
 * winding (counter-clockwise), so the sub-path cuts out of an enclosing one
 * under both the nonzero and evenodd fill rules.
 */
export function roundedRect(
  x: number,
  y: number,
  w: number,
  h: number,
  radii: Radii,
  hole = false,
): string {
  const [tl, tr, br, bl] = radii;
  const start = `M${fmt(x + tl)} ${fmt(y)}`;
  if (!hole) {
    return (
      start +
      line('h', w - tl - tr) +
      (tr ? arc(tr, tr, tr, 1) : '') +
      line('v', h - tr - br) +
      (br ? arc(br, -br, br, 1) : '') +
      line('h', -(w - br - bl)) +
      (bl ? arc(bl, -bl, -bl, 1) : '') +
      line('v', -(h - bl - tl)) +
      (tl ? arc(tl, tl, -tl, 1) : '') +
      'z'
    );
  }
  return (
    start +
    (tl ? arc(tl, -tl, tl, 0) : '') +
    line('v', h - tl - bl) +
    (bl ? arc(bl, bl, bl, 0) : '') +
    line('h', w - bl - br) +
    (br ? arc(br, br, -br, 0) : '') +
    line('v', -(h - br - tr)) +
    (tr ? arc(tr, -tr, -tr, 0) : '') +
    line('h', -(w - tr - tl)) +
    'z'
  );
}

/** Closed circle sub-path, drawn as two half arcs. */
export function circle(cx: number, cy: number, r: number): string {
  return `M${fmt(cx - r)} ${fmt(cy)}${arc(r, 2 * r, 0, 1)}${arc(r, -2 * r, 0, 1)}z`;
}
