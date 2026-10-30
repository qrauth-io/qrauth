// SPDX-License-Identifier: MIT
/**
 * Golden-file cases for the shared QR renderer (ADR-0005 D1). Plain data with
 * no imports, so the Node suite (this package) and the web package's
 * browser-like suite render the same inputs through their own import of
 * `@qrauth/shared/qr-render` and compare against the same files in ./golden.
 *
 * Regenerate after an intended geometry change (and bump RENDERER_VERSION):
 *   UPDATE_GOLDEN=1 npm test -w packages/shared
 */

/** 64x64 test logo PNG (blue square, white centre, red dot). */
export const LOGO_PNG_BASE64 =
  'iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAMAAACdt4HsAAAACVBMVEUVZcD////TLy/3hTtGAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAMElEQVRYw+3UoREAMAgAMcr+Q9fW9HAgSAZ4+REAH6cgINAdyIeAwOaAHwhMBoC1LiRrBJGISySLAAAAAElFTkSuQmCC';

/** Production-length verify URLs: 28 characters (version 3 at M, 4 at H) and 55. */
export const URL_28 = 'https://qrauth.io/v/aB3dE5gH';
export const URL_55 = 'https://qrauth.io/v/aB3dE5gH9kLmNpQrStUvWxYz0123456789X';

export interface GoldenCase {
  readonly name: string;
  /** `core` renders through renderQrCore, `full` through renderQr. */
  readonly kind: 'core' | 'full';
  readonly data: string;
  readonly style?: unknown;
  readonly core?: {
    readonly ecLevel?: 'M' | 'Q' | 'H';
    readonly quietZone?: number;
    readonly fg?: string;
    readonly bg?: string;
  };
  readonly size?: { readonly value: number; readonly unit: 'px' | 'mm' };
  readonly withLogo?: boolean;
  /** Pass the bundled frame font (FRAME_FONT_FILE), parsed with loadFrameFont. */
  readonly withFont?: boolean;
  /** Passed as `issuerVerified`: the badge mark's wording (ADR-0005 D9, 2026-10-30). */
  readonly issuerVerified?: boolean;
}

/** The bundled frame font, relative to packages/shared. */
export const FRAME_FONT_FILE = 'assets/fonts/NotoSans-SemiBold-frames.ttf';

const frame = (template: string, text: string, color = '#000000', textColor = '#FFFFFF'): Record<string, unknown> => ({
  template,
  text,
  color,
  textColor,
});

const MODULES = ['square', 'rounded', 'dots', 'classy'] as const;
const EYES = ['square', 'rounded', 'circle', 'leaf'] as const;

function v2(overrides: Record<string, unknown>): Record<string, unknown> {
  return {
    version: 2,
    presetId: 'classic',
    fg: '#000000',
    bg: '#FFFFFF',
    inverted: false,
    modules: 'square',
    eyes: 'square',
    ecLevel: 'auto',
    quietZone: 4,
    logo: null,
    ...overrides,
  };
}

const shapeCases: GoldenCase[] = MODULES.flatMap((modules) =>
  EYES.map((eyes) => ({
    name: `shape-${modules}-${eyes}`,
    kind: 'full' as const,
    data: URL_28,
    style: v2({ modules, eyes }),
  })),
);

export const GOLDEN_CASES: readonly GoldenCase[] = [
  { name: 'core-default', kind: 'core', data: URL_28 },
  {
    name: 'core-options',
    kind: 'core',
    data: URL_55,
    core: { ecLevel: 'Q', quietZone: 6, fg: '#1b2a4a', bg: '#fff8e1' },
    size: { value: 440, unit: 'px' },
  },
  ...shapeCases,
  {
    name: 'logo-qrauth-at-cap',
    kind: 'full',
    data: URL_28,
    style: v2({ logo: { kind: 'qrauth' } }),
    withLogo: true,
  },
  {
    name: 'logo-asset-scale-half',
    kind: 'full',
    data: URL_28,
    style: v2({ modules: 'rounded', eyes: 'circle', logo: { kind: 'asset', assetId: 'asset-1', scale: 0.5 } }),
    withLogo: true,
  },
  {
    name: 'logo-url55-classy',
    kind: 'full',
    data: URL_55,
    style: v2({ modules: 'classy', eyes: 'rounded', logo: { kind: 'qrauth' } }),
    withLogo: true,
  },
  {
    name: 'logo-without-bytes',
    kind: 'full',
    data: URL_28,
    style: v2({ logo: { kind: 'qrauth' } }),
  },
  {
    name: 'inverted-midnight',
    kind: 'full',
    data: URL_28,
    style: v2({ presetId: 'midnight', fg: '#E0E0E0', bg: '#212121', inverted: true, modules: 'dots', eyes: 'leaf' }),
  },
  {
    name: 'quiet-zone-10-ec-h-mm',
    kind: 'full',
    data: URL_28,
    style: v2({ quietZone: 10, ecLevel: 'H' }),
    size: { value: 30, unit: 'mm' },
  },
  // Frames (PR 5): every template, Greek and Cyrillic text, auto-fit, a
  // stored character outside the font (drawn as .notdef), and no font.
  {
    name: 'frame-caption-greek',
    kind: 'full',
    data: URL_28,
    style: v2({ frame: frame('caption', 'Σαρώστε με', '#FFFFFF', '#000000') }),
    withFont: true,
  },
  {
    name: 'frame-banner-bottom',
    kind: 'full',
    data: URL_28,
    style: v2({ modules: 'rounded', eyes: 'rounded', frame: frame('banner-bottom', 'Scan me') }),
    withFont: true,
  },
  {
    name: 'frame-banner-top-cyrillic',
    kind: 'full',
    data: URL_55,
    style: v2({ modules: 'dots', eyes: 'circle', frame: frame('banner-top', 'Сканируйте меня', '#1B2A4A', '#FFF8E1') }),
    withFont: true,
  },
  {
    name: 'frame-rounded-label-logo',
    kind: 'full',
    data: URL_28,
    style: v2({ logo: { kind: 'qrauth' }, quietZone: 6, frame: frame('rounded-label', 'Scan to verify', '#4A148C') }),
    withLogo: true,
    withFont: true,
  },
  // The badge mark by issuer status: "Verified by QRAuth" for a verified
  // issuer, "Signed with QRAuth" otherwise.
  {
    name: 'frame-badge-greek',
    kind: 'full',
    data: URL_28,
    style: v2({ modules: 'classy', eyes: 'leaf', frame: frame('badge', 'Καφέ Ωμέγα', '#003768') }),
    withFont: true,
    size: { value: 512, unit: 'px' },
    issuerVerified: true,
  },
  {
    name: 'frame-badge-greek-signed',
    kind: 'full',
    data: URL_28,
    style: v2({ modules: 'classy', eyes: 'leaf', frame: frame('badge', 'Καφέ Ωμέγα', '#003768') }),
    withFont: true,
    size: { value: 512, unit: 'px' },
    issuerVerified: false,
  },
  {
    name: 'frame-badge-empty-text',
    kind: 'full',
    data: URL_28,
    style: v2({ frame: frame('badge', '') }),
    withFont: true,
    issuerVerified: true,
  },
  {
    name: 'frame-badge-empty-text-signed',
    kind: 'full',
    data: URL_28,
    style: v2({ frame: frame('badge', '') }),
    withFont: true,
  },
  {
    name: 'frame-banner-bottom-40-chars',
    kind: 'full',
    data: URL_28,
    style: v2({ frame: frame('banner-bottom', 'Scan this code to verify the menu, today') }),
    withFont: true,
  },
  {
    name: 'frame-stored-unsupported-glyph',
    kind: 'full',
    data: URL_28,
    style: v2({ frame: frame('banner-bottom', 'Menu 日本') }),
    withFont: true,
  },
  {
    name: 'frame-banner-bottom-no-font',
    kind: 'full',
    data: URL_28,
    style: v2({ frame: frame('banner-bottom', 'Scan me') }),
  },
  {
    name: 'v1-dark-logo-caption',
    kind: 'full',
    data: URL_28,
    style: {
      templateId: 'dark',
      fgColor: '#FFFFFF',
      bgColor: '#1B2A4A',
      showLogo: true,
      captionText: 'QRAuth Verified',
    },
    withLogo: true,
    withFont: true,
    issuerVerified: true,
  },
  // The old default caption on an unverified issuer's code draws as
  // "Signed with QRAuth" (ADR-0005 D9, 2026-10-30).
  {
    name: 'v1-dark-logo-caption-signed',
    kind: 'full',
    data: URL_28,
    style: {
      templateId: 'dark',
      fgColor: '#FFFFFF',
      bgColor: '#1B2A4A',
      showLogo: true,
      captionText: 'QRAuth Verified',
    },
    withLogo: true,
    withFont: true,
    issuerVerified: false,
  },
];
