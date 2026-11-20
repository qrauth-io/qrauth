// SPDX-License-Identifier: MIT
import type { DrawItem, DrawList } from './draw-list.js';
import { alignmentPath, eyeInnerPath, eyeOuterPath, type EyeShape } from './eyes/types.js';
import { fmt } from './format.js';
import type { FrameLayout } from './frames/layout.js';
import type { CentredSquare } from './logo.js';
import { finderOrigins, inFinder, type QrMatrix } from './matrix.js';
import type { ModuleBuilder } from './modules/types.js';

/** Fully resolved render input: no defaults, no validation left to do. */
export interface RenderSpec {
  readonly matrix: QrMatrix;
  /** Upper-case `#RRGGBB`. */
  readonly fg: string;
  readonly bg: string;
  readonly quietZone: number;
  readonly modules: ModuleBuilder;
  readonly modulesCrisp: boolean;
  readonly eye: EyeShape;
  readonly eyeCrisp: boolean;
  /** Cleared square for a logo (border included), or null. */
  readonly excavation: CentredSquare | null;
  /** Logo drawn centred in the excavation; ignored without an excavation. */
  readonly logo: { readonly png: Uint8Array; readonly side: number } | null;
  /** Frame around the code (ADR-0005 PR 5), or null for none. */
  readonly frame?: FrameSpec | null;
}

export interface FrameSpec {
  readonly layout: FrameLayout;
  /** Upper-case `#RRGGBB`. */
  readonly color: string;
  readonly textColor: string;
  /** Outlined text (frames/text.ts) in module units, or '' for none. */
  readonly textPath: string;
}

function inSquare(sq: CentredSquare | null, col: number, row: number): boolean {
  return !!sq && col >= sq.start && col < sq.start + sq.side && row >= sq.start && row < sq.start + sq.side;
}

/** Builds the ordered draw list shared by the core and full renderers. */
export function buildDrawList(spec: RenderSpec): DrawList {
  const { matrix, quietZone: q, excavation } = spec;
  const { size, dark, alignment } = matrix;
  const side = size + 2 * q;
  const frame = spec.frame ?? null;
  const layout = frame?.layout ?? null;
  const width = layout ? layout.width : side;
  const height = layout ? layout.height : side;
  // Top-left of the code square (quiet zone included), and of module (0, 0).
  const cx = layout ? layout.codeX : 0;
  const cy = layout ? layout.codeY : 0;
  const ox = cx + q;
  const oy = cy + q;

  const inAlignment = (col: number, row: number): boolean =>
    alignment.some(([cx, cy]) => Math.abs(col - cx) <= 2 && Math.abs(row - cy) <= 2);

  const isOn = (col: number, row: number): boolean =>
    col >= 0 &&
    row >= 0 &&
    col < size &&
    row < size &&
    dark[row * size + col] === 1 &&
    !inFinder(size, col, row) &&
    !inAlignment(col, row) &&
    !inSquare(excavation, col, row);

  const finders = finderOrigins(size);
  const items: DrawItem[] = [];
  // Frame paint first; the code's opaque background is drawn over it, so the
  // frame never shows inside the quiet zone.
  if (frame && layout && layout.underlay) {
    items.push({ kind: 'path', layer: 'frame', d: layout.underlay, fill: frame.color, fillRule: 'nonzero', crisp: false });
  }
  const covers = !layout || layout.backgroundCoversArtwork;
  items.push(
    {
      kind: 'path',
      layer: 'background',
      d: covers
        ? `M0 0h${fmt(width)}v${fmt(height)}h${fmt(-width)}z`
        : `M${fmt(cx)} ${fmt(cy)}h${fmt(side)}v${fmt(side)}h${fmt(-side)}z`,
      fill: spec.bg,
      fillRule: 'nonzero',
      crisp: true,
    },
    {
      kind: 'path',
      layer: 'modules',
      d: spec.modules({ size, x: ox, y: oy, isOn }),
      fill: spec.fg,
      fillRule: 'nonzero',
      crisp: spec.modulesCrisp,
    },
    {
      kind: 'path',
      layer: 'eye-outer',
      d: finders.map(([x, y]) => eyeOuterPath(spec.eye, x + ox, y + oy)).join(''),
      fill: spec.fg,
      fillRule: 'evenodd',
      crisp: spec.eyeCrisp,
    },
    {
      kind: 'path',
      layer: 'eye-inner',
      d:
        finders.map(([x, y]) => eyeInnerPath(spec.eye, x + ox, y + oy)).join('') +
        alignment.map(([ax, ay]) => alignmentPath(spec.eye, ax + ox, ay + oy)).join(''),
      fill: spec.fg,
      fillRule: 'evenodd',
      crisp: spec.eyeCrisp,
    },
  );

  if (excavation && spec.logo) {
    const logoSide = Math.min(spec.logo.side, excavation.side - 2);
    const inset = (excavation.side - logoSide) / 2;
    items.push({
      kind: 'image',
      x: excavation.start + ox + inset,
      y: excavation.start + oy + inset,
      width: logoSide,
      height: logoSide,
      mimeType: 'image/png',
      bytes: spec.logo.png,
    });
  }

  if (frame && frame.textPath) {
    items.push({ kind: 'path', layer: 'frame-text', d: frame.textPath, fill: frame.textColor, fillRule: 'nonzero', crisp: false });
  }

  return { width, height, items };
}
