// SPDX-License-Identifier: MIT

/** `toFixed` switches to exponent notation from here on, which `fmt` cannot trim safely. */
const FMT_LIMIT = 1e21;

/**
 * The single number formatter for every coordinate the renderer emits.
 * Fixed precision of at most 3 decimals, trailing zeros trimmed, `-0`
 * normalised to `0`. `toFixed` is locale-independent, so the output is the
 * same in Node and in every browser. Throws for non-finite values and for
 * magnitudes of 1e21 or more.
 */
export function fmt(value: number): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new Error(`qr-render: non-finite number ${String(value)}`);
  }
  if (Math.abs(value) >= FMT_LIMIT) throw new Error(`qr-render: number out of range ${value}`);
  const fixed = value.toFixed(3);
  const trimmed = fixed.replace(/\.?0+$/, '');
  return trimmed === '-0' || trimmed === '' ? '0' : trimmed;
}

const XML_ESCAPES: Readonly<Record<string, string>> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&apos;',
};

/** The single XML escape applied to every string value written into the SVG. */
export function escapeXml(text: string): string {
  return text.replace(/[&<>"']/g, (ch) => XML_ESCAPES[ch] ?? ch);
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** Standard padded base64. Uses neither Buffer nor btoa, so it is isomorphic. */
export function base64(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i] << 16;
    out += `${B64[(n >> 18) & 63]}${B64[(n >> 12) & 63]}==`;
  } else if (rest === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += `${B64[(n >> 18) & 63]}${B64[(n >> 12) & 63]}${B64[(n >> 6) & 63]}=`;
  }
  return out;
}
