// SPDX-License-Identifier: MIT
/**
 * `@qrauth/shared/qr-render/core`: matrix, square modules, square eyes, quiet
 * zone and colours. No zod and no other module or eye styles, so bundles that
 * only need the plain code (the web components) stay small.
 */
import { buildDrawList } from './build.js';
import { normaliseColour } from './colour.js';
import { squareEye } from './eyes/square.js';
import { encode, type EcLevel } from './matrix.js';
import { squareModules } from './modules/square.js';
import { toSvg, type SvgSize } from './svg.js';

export { encode, type EcLevel, type QrMatrix } from './matrix.js';
export { RENDERER_VERSION, SVG_SIZE_MAX, type SvgSize } from './svg.js';

export const CORE_QUIET_ZONE_MIN = 4;
export const CORE_QUIET_ZONE_MAX = 10;

export interface CoreOptions {
  /** Default M. */
  readonly ecLevel?: EcLevel;
  /** Whole modules, 4..10. Default 4. */
  readonly quietZone?: number;
  /** `#RRGGBB`. Default black. */
  readonly fg?: string;
  /** `#RRGGBB`. Default white. */
  readonly bg?: string;
  /** Root width (height follows the aspect ratio). Omitted by default. */
  readonly size?: SvgSize;
}

/**
 * Plain square QR code as an SVG string. Pure and synchronous; equal inputs
 * give byte-identical output in Node and in browsers. Throws on empty data,
 * data that does not fit, or invalid options.
 */
export function renderQrCore(data: string, options: CoreOptions = {}): string {
  const quietZone = options.quietZone ?? CORE_QUIET_ZONE_MIN;
  if (!Number.isInteger(quietZone) || quietZone < CORE_QUIET_ZONE_MIN || quietZone > CORE_QUIET_ZONE_MAX) {
    throw new Error(`qr-render: quietZone must be an integer from ${CORE_QUIET_ZONE_MIN} to ${CORE_QUIET_ZONE_MAX}`);
  }
  const list = buildDrawList({
    matrix: encode(data, options.ecLevel ?? 'M'),
    fg: normaliseColour(options.fg ?? '#000000'),
    bg: normaliseColour(options.bg ?? '#FFFFFF'),
    quietZone,
    modules: squareModules,
    modulesCrisp: true,
    eye: squareEye,
    eyeCrisp: true,
    excavation: null,
    logo: null,
  });
  return toSvg(list, options.size);
}
