import { renderQrCore, SVG_SIZE_MAX } from '@qrauth/shared/qr-render/core';

/** Width used when `size` is not a finite number. */
const DEFAULT_SIZE = 440;

/**
 * Synchronously render a QR code as an inline SVG string, through the shared
 * QRAuth renderer's core entry point (ADR-0005 D1). The dashboard and the
 * API render the same plain code byte for byte. esbuild inlines the renderer
 * at build time, so the published bundle has no runtime dependency.
 *
 * Plain square code, EC level M, black on white, 4-module quiet zone per
 * ISO/IEC 18004 (required on stricter readers: iPhone Camera, older Android,
 * low light).
 *
 * @param text   The payload to encode (the auth-session or claim URL).
 * @param size   The SVG width and height in pixels (default 440).
 * @returns      An <svg> element as a string, or '' when text is empty or
 *               exceeds QR capacity at EC level M.
 */
export function qrToSvg(text: string, size = DEFAULT_SIZE): string {
  if (!text) return '';
  const width = Math.min(SVG_SIZE_MAX.px, Math.max(1, Math.floor(Number.isFinite(size) ? size : DEFAULT_SIZE)));
  try {
    return renderQrCore(text, { size: { value: width, unit: 'px' } });
  } catch {
    return '';
  }
}
