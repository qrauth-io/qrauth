// SPDX-License-Identifier: MIT
import type { DrawItem, DrawList } from './draw-list.js';
import { base64, escapeXml, fmt } from './format.js';

/**
 * Geometry version. Bump on any change that draws the same input
 * differently; the golden files change in the same commit (ADR-0005 D8).
 * 2: frames and outlined frame text are drawn (PR 5).
 */
export const RENDERER_VERSION = 2;

/** Physical size written to the root `width`/`height`; omitted when absent. */
export interface SvgSize {
  /** Width, greater than 0 and at most SVG_SIZE_MAX[unit]. Height follows the aspect ratio. */
  readonly value: number;
  readonly unit: 'px' | 'mm';
}

/** Largest root width per unit: 16384 px, 1000 mm. */
export const SVG_SIZE_MAX: Readonly<Record<SvgSize['unit'], number>> = { px: 16384, mm: 1000 };

function checkSize(size: SvgSize): void {
  const max = Object.prototype.hasOwnProperty.call(SVG_SIZE_MAX, size.unit) ? SVG_SIZE_MAX[size.unit] : undefined;
  if (max === undefined) throw new Error(`qr-render: size unit must be px or mm`);
  if (typeof size.value !== 'number' || !Number.isFinite(size.value) || size.value <= 0 || size.value > max) {
    throw new Error(`qr-render: size must be greater than 0 and at most ${max} ${size.unit}`);
  }
}

function attr(name: string, value: string): string {
  return ` ${name}="${escapeXml(value)}"`;
}

function item(it: DrawItem): string {
  if (it.kind === 'image') {
    return (
      '<image' +
      attr('x', fmt(it.x)) +
      attr('y', fmt(it.y)) +
      attr('width', fmt(it.width)) +
      attr('height', fmt(it.height)) +
      attr('preserveAspectRatio', 'xMidYMid meet') +
      attr('xlink:href', `data:${it.mimeType};base64,${base64(it.bytes)}`) +
      '/>'
    );
  }
  if (it.d === '') return '';
  return (
    '<path' +
    attr('d', it.d) +
    attr('fill', it.fill) +
    (it.fillRule === 'evenodd' ? attr('fill-rule', 'evenodd') : '') +
    (it.crisp ? attr('shape-rendering', 'crispEdges') : '') +
    '/>'
  );
}

/**
 * Serialise a draw list. Attribute and element order are fixed, there is no
 * DOM and nothing random or time-derived, so equal inputs give equal bytes in
 * every environment.
 */
export function toSvg(list: DrawList, size?: SvgSize): string {
  if (size !== undefined) checkSize(size);
  const hasImage = list.items.some((it) => it.kind === 'image');
  const dims = size
    ? attr('width', `${fmt(size.value)}${size.unit === 'mm' ? 'mm' : ''}`) +
      attr('height', `${fmt((size.value * list.height) / list.width)}${size.unit === 'mm' ? 'mm' : ''}`)
    : '';
  return (
    '<svg' +
    attr('xmlns', 'http://www.w3.org/2000/svg') +
    (hasImage ? attr('xmlns:xlink', 'http://www.w3.org/1999/xlink') : '') +
    attr('viewBox', `0 0 ${fmt(list.width)} ${fmt(list.height)}`) +
    dims +
    attr('role', 'img') +
    attr('aria-label', 'QR code') +
    attr('data-renderer', `qrauth-qr/${RENDERER_VERSION}`) +
    '>' +
    list.items.map(item).join('') +
    '</svg>'
  );
}
