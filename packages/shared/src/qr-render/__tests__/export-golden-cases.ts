// SPDX-License-Identifier: MIT
/**
 * Cross-package golden cases (ADR-0005 PR 3): the dashboard preview must be
 * byte-identical to the server's SVG export for the same code and style.
 * Plain data with no imports. Three suites render these cases through their
 * own production path and compare against the same files in ./golden-export:
 *
 * - packages/shared: renderQr with the logo file read from disk
 * - packages/api:    renderExport({ token, issuerVerified }, style, logoBytesFor(style, customerLogo), { format: 'svg' })
 * - packages/web:    the dashboard preview function with the logo bytes it fetches
 *
 * Cases whose style has the QRAuth logo draw the real logo bytes
 * (packages/shared/assets/qrauth-logo.png); cases with a customer logo
 * (`kind: "asset"`) draw CUSTOMER_LOGO_FIXTURE, a PNG produced by the API's
 * upload normalisation; the others draw none. Every suite passes the
 * bundled frame font (assets/fonts/NotoSans-SemiBold-frames.ttf), so frame
 * text is outlined identically in the preview and the export (PR 5).
 * `issuerVerified` is passed through as the issuer's status, which picks the
 * badge mark's wording (D9, 2026-10-30); omitted means unverified.
 * Regenerate after an intended
 * geometry change: UPDATE_GOLDEN=1 npm test -w packages/shared
 */

/** The verify URL origin of production; suites encode `${EXPORT_ORIGIN}/v/${token}`. */
export const EXPORT_ORIGIN = 'https://qrauth.io';
export const EXPORT_TOKEN = 'aB3dE5gH';
/** The customer logo the `asset` cases draw, relative to this directory. */
export const CUSTOMER_LOGO_FIXTURE = 'fixtures/customer-logo.png';

export interface ExportGoldenCase {
  readonly name: string;
  /** A stored style: v2, v1 (upgraded on read) or null (DEFAULT_STYLE). */
  readonly style: unknown;
  /** The issuing organization is verified (isIssuerVerified); omitted means not. */
  readonly issuerVerified?: boolean;
}

const v2 = (overrides: Record<string, unknown>): Record<string, unknown> => ({
  version: 2,
  presetId: 'classic',
  fg: '#000000',
  bg: '#FFFFFF',
  inverted: false,
  modules: 'square',
  eyes: 'square',
  ecLevel: 'auto',
  quietZone: 4,
  logo: { kind: 'qrauth' },
  ...overrides,
});

export const EXPORT_GOLDEN_CASES: readonly ExportGoldenCase[] = [
  { name: 'no-style', style: null },
  { name: 'v1-classic-logo', style: { templateId: 'classic', fgColor: '#000000', bgColor: '#FFFFFF', showLogo: true, captionText: 'QRAuth Verified' }, issuerVerified: true },
  { name: 'v1-classic-logo-signed', style: { templateId: 'classic', fgColor: '#000000', bgColor: '#FFFFFF', showLogo: true, captionText: 'QRAuth Verified' }, issuerVerified: false },
  { name: 'v1-midnight-logo', style: { templateId: 'midnight', fgColor: '#E0E0E0', bgColor: '#212121', showLogo: true, captionText: '' } },
  { name: 'v2-classic-logo', style: v2({}) },
  { name: 'v2-rounded-rounded-no-logo-qz6', style: v2({ modules: 'rounded', eyes: 'rounded', logo: null, quietZone: 6 }) },
  { name: 'v2-dots-circle-logo', style: v2({ presetId: 'ocean', fg: '#003768', bg: '#E3F2FD', modules: 'dots', eyes: 'circle' }) },
  { name: 'v2-classy-leaf-logo-caption', style: v2({ modules: 'classy', eyes: 'leaf', frame: { template: 'caption', text: 'Scan to verify', color: '#FFFFFF', textColor: '#000000' } }) },
  { name: 'v2-dark-inverted-logo-ec-h', style: v2({ presetId: 'dark', fg: '#FFFFFF', bg: '#1B2A4A', inverted: true, ecLevel: 'H' }) },
  { name: 'v2-customer-logo-scale-0.75', style: v2({ modules: 'rounded', logo: { kind: 'asset', assetId: 'golden-logo', scale: 0.75 } }) },
  // Frames (PR 5), Greek and Cyrillic text included.
  { name: 'v2-banner-bottom-greek', style: v2({ frame: { template: 'banner-bottom', text: 'Σαρώστε με', color: '#000000', textColor: '#FFFFFF' } }) },
  { name: 'v2-badge-cyrillic-rounded', style: v2({ modules: 'rounded', eyes: 'rounded', logo: null, frame: { template: 'badge', text: 'Сканируйте меня', color: '#1B5E20', textColor: '#FFFFFF' } }), issuerVerified: true },
  { name: 'v2-badge-cyrillic-rounded-signed', style: v2({ modules: 'rounded', eyes: 'rounded', logo: null, frame: { template: 'badge', text: 'Сканируйте меня', color: '#1B5E20', textColor: '#FFFFFF' } }), issuerVerified: false },
  { name: 'v2-banner-top-dots', style: v2({ presetId: 'ocean', fg: '#003768', bg: '#E3F2FD', modules: 'dots', eyes: 'circle', frame: { template: 'banner-top', text: 'Menu & offers', color: '#003768', textColor: '#E3F2FD' } }) },
  { name: 'v2-rounded-label-customer-logo', style: v2({ modules: 'rounded', logo: { kind: 'asset', assetId: 'golden-logo', scale: 0.75 }, frame: { template: 'rounded-label', text: 'Scan to verify', color: '#4A148C', textColor: '#FFFFFF' } }) },
  { name: 'v2-customer-logo-inverted-scale-1', style: v2({ presetId: 'dark', fg: '#FFFFFF', bg: '#1B2A4A', inverted: true, logo: { kind: 'asset', assetId: 'golden-logo', scale: 1 } }) },
];
