// SPDX-License-Identifier: MIT

/** Paint layers, in drawing order. One path per layer and colour. */
/** `frame` is the frame's shape and `frame-text` its outlined text (ADR-0005 PR 5). */
export type Layer = 'frame' | 'background' | 'modules' | 'eye-outer' | 'eye-inner' | 'frame-text';

export interface PathItem {
  readonly kind: 'path';
  readonly layer: Layer;
  /** SVG path data in module units. */
  readonly d: string;
  /** Validated `#RRGGBB`, upper case. */
  readonly fill: string;
  readonly fillRule: 'nonzero' | 'evenodd';
  /** Only straight, module-aligned edges: safe to render with crisp edges. */
  readonly crisp: boolean;
}

export interface ImageItem {
  readonly kind: 'image';
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height: number;
  readonly mimeType: 'image/png';
  /** Image bytes; serialised inline as a `data:` URI, never as a URL. */
  readonly bytes: Uint8Array;
}

export type DrawItem = PathItem | ImageItem;

/**
 * Renderer output model: an ordered list of paint operations in module units.
 * The SVG serialiser and (later) other back ends walk the same list.
 */
export interface DrawList {
  /** Full artwork width and height in modules, quiet zone and frame included. */
  readonly width: number;
  readonly height: number;
  readonly items: readonly DrawItem[];
}
