// SPDX-License-Identifier: MIT
import { describe, expect, it } from 'vitest';

import * as core from '../core.js';
import * as full from '../index.js';

// Runtime exports only; types are checked by tsc. A change here is a change
// to the public API of @qrauth/shared/qr-render(/core).
const FULL_EXPORTS = [
  'CONTRAST_MIN',
  'CONTRAST_MIN_INVERTED_WITH_LOGO',
  'CONTRAST_MIN_WITH_LOGO',
  'CONTRAST_WARN',
  'CORE_QUIET_ZONE_MAX',
  'CORE_QUIET_ZONE_MIN',
  'DEFAULT_STYLE',
  'EC_LEVELS',
  'BADGE_MARK_SIGNED',
  'BADGE_MARK_VERIFIED',
  'EYE_STYLES',
  'FRAME_FONT_COVERAGE',
  'FRAME_GLYPH_UNSUPPORTED_MESSAGE',
  'FRAME_TEXT_CONTRAST_MIN',
  'FRAME_TEMPLATES',
  'FRAME_TEXT_MAX',
  'FRAME_QRAUTH_CLAIM_MESSAGE',
  'LEGACY_DEFAULT_CAPTION',
  'LOGO_EC_BUDGET',
  'LOGO_PNG_MAX_BYTES',
  'LOGO_SCALE_MAX',
  'LOGO_SCALE_MIN',
  'MAX_LOGO_VERSION',
  'MIN_MODULE_MM',
  'MODULE_STYLES',
  'QUIET_ZONE_MAX',
  'QUIET_ZONE_MIN',
  'RENDERER_VERSION',
  'SVG_SIZE_MAX',
  'canonicalStyleJson',
  'checkStyle',
  'contrastFloor',
  'badgeMark',
  'contrastRatio',
  'displayFrameText',
  'ecFloor',
  'frameLayout',
  'isFrameTextSupported',
  'isFrameClaimRefused',
  'encode',
  'isHexColour',
  'isLighter',
  'isValidFrameText',
  'maxLogoModules',
  'parseStoredStyle',
  'parseStyle',
  'qrStyleV1Schema',
  'qrStyleV2Schema',
  'referencesQrauth',
  'relativeLuminance',
  'renderQr',
  'renderQrCore',
  'resolveEcLevel',
  'styleFrameLayout',
  'unsupportedFrameChars',
  'upgradeStyle',
  // Print sizing (PR 6)
  'PDF_MARGIN_MM_MAX',
  'PDF_MARGIN_MM_MIN',
  'PRINT_DPI_DEFAULT',
  'PRINT_DPI_MAX',
  'PRINT_DPI_MIN',
  'PRINT_MODULE_MM_MIN',
  'PRINT_PX_PER_MODULE_MIN',
  'PRINT_RASTER_PIXELS_MAX',
  'PRINT_RASTER_SIDE_MAX',
  'PRINT_SIZE_IN_MAX',
  'PRINT_SIZE_IN_MIN',
  'PRINT_SIZE_MM_DEFAULT',
  'PRINT_SIZE_MM_MAX',
  'PRINT_SIZE_MM_MIN',
  'artworkSize',
  'inchesToMm',
  'maxPrintWidthMm',
  'minPrintWidthMm',
  'mmToPoints',
  'moduleSizeRefusal',
  'printPxHeight',
  'printPxWidth',
  'printRasterOrRefusal',
  'roundMm',
];

const CORE_EXPORTS = [
  'CORE_QUIET_ZONE_MAX',
  'CORE_QUIET_ZONE_MIN',
  'RENDERER_VERSION',
  'SVG_SIZE_MAX',
  'encode',
  'renderQrCore',
];

const FONT_EXPORTS = ['FRAME_FONT_ASSET', 'FRAME_FONT_MAX_BYTES', 'loadFrameFont'];

describe('public exports', () => {
  it('./qr-render exports exactly the documented surface', () => {
    expect(Object.keys(full).sort()).toEqual([...FULL_EXPORTS].sort());
  });

  it('./qr-render/core exports exactly the documented surface', () => {
    expect(Object.keys(core).sort()).toEqual([...CORE_EXPORTS].sort());
  });

  it('./qr-render/font exports exactly the documented surface', async () => {
    const font = await import('../font.js');
    expect(Object.keys(font).sort()).toEqual([...FONT_EXPORTS].sort());
  });

  it.each(['codewordMap', 'blockLayout', 'centredSquare', 'logoExcavation', 'assertLogoPng', 'normaliseColour', 'toSvg', 'fmt', 'outlineText', 'loadFrameFont'])(
    'does not export the internal %s',
    (name) => {
      expect(name in full).toBe(false);
    },
  );
});
