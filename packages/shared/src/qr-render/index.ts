// SPDX-License-Identifier: MIT
/**
 * `@qrauth/shared/qr-render`: the shared QR renderer (ADR-0005 D1). One pure,
 * synchronous function draws every code, so the dashboard, the API and the
 * exports agree byte for byte. Not re-exported from the package root.
 */
import { buildDrawList } from './build.js';
import { normaliseColour } from './colour.js';
import type { DrawList } from './draw-list.js';
import { circleEye, leafEye, roundedEye } from './eyes/shapes.js';
import { squareEye } from './eyes/square.js';
import type { EyeShape, EyeStyle } from './eyes/types.js';
import type { FrameFont } from './frames/font.js';
import { displayFrameText } from './frames/claim.js';
import { badgeMark, frameLayout, type FrameLayout } from './frames/layout.js';
import { outlineText } from './frames/text.js';
import { assertLogoPng, logoExcavation, maxLogoModules } from './logo.js';
import { encode, type EcLevel } from './matrix.js';
import { classyModules } from './modules/classy.js';
import { dotModules } from './modules/dots.js';
import { roundedModules } from './modules/rounded.js';
import { squareModules } from './modules/square.js';
import type { ModuleBuilder, ModuleStyle } from './modules/types.js';
import { checkStyle, resolveEcLevel, type ScanIssue } from './scan-rules.js';
import { parseStoredStyle, type QrFrame, type QrStyleV2 } from './style.js';
import type { ArtworkModules } from './print.js';
import { RENDERER_VERSION, toSvg, type SvgSize } from './svg.js';

// Public surface. Internals (path builders, codeword and block maps, the
// serialiser, number formatting) are not exported; tests import them from
// their modules directly.

// Rendering
export { renderQrCore, CORE_QUIET_ZONE_MAX, CORE_QUIET_ZONE_MIN, type CoreOptions } from './core.js';
export { RENDERER_VERSION, SVG_SIZE_MAX, type SvgSize } from './svg.js';
export { encode, type EcLevel, type QrMatrix } from './matrix.js';
export type { DrawItem, DrawList, ImageItem, Layer, PathItem } from './draw-list.js';
export type { EyeStyle } from './eyes/types.js';
export type { ModuleStyle } from './modules/types.js';

// Style model (D2, D8)
export {
  canonicalStyleJson,
  DEFAULT_STYLE,
  EC_LEVELS,
  EYE_STYLES,
  FRAME_TEMPLATES,
  FRAME_TEXT_MAX,
  isValidFrameText,
  LOGO_SCALE_MAX,
  LOGO_SCALE_MIN,
  MODULE_STYLES,
  parseStoredStyle,
  parseStyle,
  QUIET_ZONE_MAX,
  QUIET_ZONE_MIN,
  qrStyleV1Schema,
  qrStyleV2Schema,
  upgradeStyle,
  type QrFrame,
  type QrLogo,
  type QrStyle,
  type QrStyleV1,
  type QrStyleV2,
} from './style.js';

// Scannability rules (D4)
export {
  checkStyle,
  CONTRAST_MIN,
  CONTRAST_MIN_INVERTED_WITH_LOGO,
  CONTRAST_MIN_WITH_LOGO,
  CONTRAST_WARN,
  contrastFloor,
  FRAME_GLYPH_UNSUPPORTED_MESSAGE,
  FRAME_TEXT_CONTRAST_MIN,
  ecFloor,
  MIN_MODULE_MM,
  resolveEcLevel,
  type ScanIssue,
  type ScanIssueCode,
  type ScanReport,
} from './scan-rules.js';
export { contrastRatio, isHexColour, isLighter, relativeLuminance } from './colour.js';

// Print sizing (PR 6): limits and arithmetic for print exports.
export {
  inchesToMm,
  maxPrintWidthMm,
  minPrintWidthMm,
  mmToPoints,
  moduleSizeRefusal,
  PDF_MARGIN_MM_MAX,
  PDF_MARGIN_MM_MIN,
  PRINT_DPI_DEFAULT,
  PRINT_DPI_MAX,
  PRINT_DPI_MIN,
  PRINT_MODULE_MM_MIN,
  PRINT_PX_PER_MODULE_MIN,
  PRINT_RASTER_PIXELS_MAX,
  PRINT_RASTER_SIDE_MAX,
  PRINT_SIZE_IN_MAX,
  PRINT_SIZE_IN_MIN,
  PRINT_SIZE_MM_DEFAULT,
  PRINT_SIZE_MM_MAX,
  PRINT_SIZE_MM_MIN,
  printPxHeight,
  printPxWidth,
  printRasterOrRefusal,
  roundMm,
  type ArtworkModules,
  type PrintSizeRefusal,
} from './print.js';
export { LOGO_EC_BUDGET, LOGO_PNG_MAX_BYTES, MAX_LOGO_VERSION, maxLogoModules } from './logo.js';

// Frames (PR 5). The font parser is in `@qrauth/shared/qr-render/font`.
export {
  FRAME_QRAUTH_CLAIM_MESSAGE,
  LEGACY_DEFAULT_CAPTION,
  displayFrameText,
  isFrameClaimRefused,
  referencesQrauth,
  type ClaimFrame,
} from './frames/claim.js';
export { FRAME_FONT_COVERAGE, isFrameTextSupported, unsupportedFrameChars } from './frames/coverage.js';
export type { FrameFont, FrameGlyph, GlyphCommand } from './frames/font.js';
export {
  BADGE_MARK_SIGNED,
  BADGE_MARK_VERIFIED,
  badgeMark,
  frameLayout,
  type DrawnFrameTemplate,
  type FrameLayout,
  type TextBox,
} from './frames/layout.js';

const MODULE_BUILDERS: Readonly<Record<ModuleStyle, ModuleBuilder>> = {
  square: squareModules,
  rounded: roundedModules,
  dots: dotModules,
  classy: classyModules,
};

const EYE_SHAPES: Readonly<Record<EyeStyle, EyeShape>> = {
  square: squareEye,
  rounded: roundedEye,
  circle: circleEye,
  leaf: leafEye,
};

export interface RenderInput {
  /** The text to encode (the verify URL). */
  readonly data: string;
  /**
   * The code's style: v1, v2, or null/undefined when none is stored (renders
   * with DEFAULT_STYLE). Validated here; anything else throws.
   */
  readonly style: unknown;
  /**
   * Normalised logo PNG (D6), or null. Must start with the PNG signature and
   * be at most LOGO_PNG_MAX_BYTES; otherwise renderQr throws. Drawn only when
   * the style has a logo.
   */
  readonly logoPng?: Uint8Array | null;
  /** Root width (height follows). Omitted by default. */
  readonly size?: SvgSize;
  /**
   * The frame font (`loadFrameFont` from `@qrauth/shared/qr-render/font`,
   * over the bundled font bytes). Frame text is outlined with it; without
   * it a frame is drawn without its text and `notDrawn` reports `frame`.
   */
  readonly font?: FrameFont | null;
  /**
   * Whether QRAuth has verified the issuing organization (`isIssuerVerified`
   * from `@qrauth/shared`). The badge template's mark reads "Verified by
   * QRAuth" only when true, "Signed with QRAuth" otherwise (ADR-0005 D9,
   * 2026-10-30). The renderer never looks this up; callers pass it, and
   * an omitted value draws the unverified wording.
   */
  readonly issuerVerified?: boolean;
}

export interface RenderMeta {
  readonly rendererVersion: number;
  readonly version: number;
  readonly ecLevel: EcLevel;
  /** Modules per side without quiet zone. */
  readonly symbolSize: number;
  /** Full artwork width in modules, frame included. */
  readonly width: number;
  /** Full artwork height in modules, frame included. */
  readonly height: number;
  /** Largest logo square the symbol allows (border included), 0 when none fits. */
  readonly logoCap: number;
  /** Excavated square side actually used, 0 without a logo. */
  readonly logoModules: number;
  /** Write-time rule results for the style; rendering is not blocked by them. */
  readonly warnings: readonly ScanIssue[];
  readonly errors: readonly ScanIssue[];
  /** Parts of the style this renderer version does not draw yet. */
  readonly notDrawn: readonly ('frame' | 'logo')[];
  /** The badge mark the artwork carries, or null when the style draws no badge. */
  readonly badgeMark: string | null;
  /** The frame text drawn (displayFrameText), or null when no frame is drawn. */
  readonly frameText: string | null;
}

export interface RenderResult {
  readonly svg: string;
  readonly drawList: DrawList;
  readonly style: QrStyleV2;
  readonly meta: RenderMeta;
}

/** The style's frame when it draws one (anything but `none`). */
function drawnFrame(style: QrStyleV2): (QrFrame & { template: Exclude<QrFrame['template'], 'none'> }) | null {
  const frame = style.frame;
  if (!frame || frame.template === 'none') return null;
  return frame as QrFrame & { template: Exclude<QrFrame['template'], 'none'> };
}

/**
 * Layout of the style's frame around a symbol of `symbolSize` modules, or
 * null when the style draws none. Depends only on the template and the
 * sizes, never on the text, so the artwork size is known without a font.
 */
export function styleFrameLayout(style: QrStyleV2, symbolSize: number): FrameLayout | null {
  const frame = drawnFrame(style);
  return frame ? frameLayout(frame.template, symbolSize + 2 * style.quietZone) : null;
}

/**
 * Artwork size in modules (symbol, quiet zone on both sides, frame) of
 * `data` drawn with `style`: what a print size (PR 6) spans. Equals
 * `meta.width`/`meta.height` of renderQr, without drawing.
 */
export function artworkSize(data: string, style: QrStyleV2): ArtworkModules {
  const size = encode(data, resolveEcLevel(style)).size;
  const layout = styleFrameLayout(style, size);
  if (layout) return { width: layout.width, height: layout.height };
  const side = size + 2 * style.quietZone;
  return { width: side, height: side };
}

/** The frame's text, and the badge's fixed mark `mark`, outlined with `font`. */
function frameTextPath(layout: FrameLayout, text: string, mark: string, font: FrameFont): string {
  return layout.textBoxes.map((box) => outlineText(box.role === 'mark' ? mark : text, box, font)?.d ?? '').join('');
}

/**
 * Render a QR code. Pure and synchronous: equal inputs give byte-identical
 * SVG in Node and in browsers. Stored styles always render: no style renders
 * with DEFAULT_STYLE, and a valid v1 or v2 style renders even when it would
 * fail today's write-time rules (reported in `meta.errors`).
 */
export function renderQr(input: RenderInput): RenderResult {
  const style = parseStoredStyle(input.style);
  const ecLevel = resolveEcLevel(style);
  const matrix = encode(input.data, ecLevel);

  const logoCap = style.logo ? maxLogoModules(matrix) : 0;
  const scale = style.logo?.kind === 'asset' ? style.logo.scale : 1;
  const excavation = style.logo ? logoExcavation(matrix.size, logoCap, scale) : null;
  const logoPng = input.logoPng ?? null;
  if (logoPng !== null) assertLogoPng(logoPng);
  const frame = drawnFrame(style);
  const layout = styleFrameLayout(style, matrix.size);
  const font = input.font ?? null;
  const mark = frame?.template === 'badge' ? badgeMark(input.issuerVerified === true) : null;
  const frameText = frame ? displayFrameText(frame.text, input.issuerVerified === true) : '';

  const drawList = buildDrawList({
    matrix,
    fg: normaliseColour(style.fg),
    bg: normaliseColour(style.bg),
    quietZone: style.quietZone,
    modules: MODULE_BUILDERS[style.modules],
    modulesCrisp: style.modules === 'square',
    eye: EYE_SHAPES[style.eyes],
    eyeCrisp: style.eyes === 'square',
    excavation,
    logo: excavation && logoPng ? { png: logoPng, side: (logoCap - 2) * scale } : null,
    frame:
      frame && layout
        ? {
            layout,
            color: normaliseColour(frame.color),
            textColor: normaliseColour(frame.textColor),
            textPath: font ? frameTextPath(layout, frameText, mark ?? '', font) : '',
          }
        : null,
  });

  const notDrawn: Array<'frame' | 'logo'> = [];
  // Text needs the font: any frame text, and the badge's fixed mark.
  if (frame && !font && (frame.text !== '' || frame.template === 'badge')) notDrawn.push('frame');
  if (style.logo && (!excavation || !logoPng)) notDrawn.push('logo');

  const report = checkStyle(style, matrix.version);
  return {
    svg: toSvg(drawList, input.size),
    drawList,
    style,
    meta: {
      rendererVersion: RENDERER_VERSION,
      version: matrix.version,
      ecLevel,
      symbolSize: matrix.size,
      width: drawList.width,
      height: drawList.height,
      logoCap,
      logoModules: excavation?.side ?? 0,
      warnings: report.warnings,
      errors: report.errors,
      notDrawn,
      badgeMark: mark,
      frameText: frame ? frameText : null,
    },
  };
}
