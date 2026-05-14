import QRCode from 'qrcode';

/**
 * Synchronously render a QR code as an inline SVG string.
 *
 * Replaces the previous external image fallback (api.qrserver.com).
 * Uses qrcode's sync create() + manual <rect> emission so callers
 * do not need to become async.
 *
 * Quiet zone: 4 modules per ISO/IEC 18004 — required for reliable
 * scanning on stricter readers (iPhone Camera, older Android, low-light).
 *
 * @param text   The payload to encode (typically the auth-session URL).
 * @param size   The target SVG width/height in pixels (default 440).
 * @returns      An <svg> element as a string, or '' when text is empty
 *               or exceeds QR capacity at EC level M.
 */
export function qrToSvg(text: string, size = 440): string {
  if (!text) return '';

  const safeSize = Math.max(1, Math.floor(Number.isFinite(size) ? size : 440));

  let qr: { modules: { size: number; data: Uint8Array } };
  try {
    qr = QRCode.create(text, { errorCorrectionLevel: 'M' });
  } catch {
    return '';
  }

  const matrix = qr.modules;
  const margin = 4;
  const totalModules = matrix.size + margin * 2;
  const cell = safeSize / totalModules;

  let rects = '';
  for (let y = 0; y < matrix.size; y++) {
    for (let x = 0; x < matrix.size; x++) {
      if (matrix.data[y * matrix.size + x]) {
        const px = (x + margin) * cell;
        const py = (y + margin) * cell;
        rects += `<rect x="${px.toFixed(2)}" y="${py.toFixed(2)}" width="${cell.toFixed(2)}" height="${cell.toFixed(2)}"/>`;
      }
    }
  }

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${safeSize} ${safeSize}" width="${safeSize}" height="${safeSize}" shape-rendering="crispEdges" role="img" aria-label="QR code"><rect width="100%" height="100%" fill="#ffffff"/><g fill="#000000">${rects}</g></svg>`;
}
