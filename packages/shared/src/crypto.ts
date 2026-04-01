import { TOKEN_CHARSET, TOKEN_LENGTH } from "./constants.js";

/**
 * Generate a cryptographically random token using the Web Crypto API.
 *
 * Uses `crypto.getRandomValues` which is available in:
 *   - Node.js 19+ (global) / Node.js 15–18 via `globalThis.crypto`
 *   - Cloudflare Workers / Deno
 *   - React Native (Hermes >= 0.71 with the `react-native-get-random-values` polyfill)
 *   - All modern browsers
 *
 * The algorithm uses rejection sampling to eliminate modular bias: if a drawn
 * byte falls outside the largest multiple of CHARSET_LENGTH that fits in a
 * byte, it is discarded and redrawn.
 *
 * @param length - Number of characters in the returned token.
 *   Defaults to {@link TOKEN_LENGTH}.
 * @returns A randomly generated token string.
 */
export function generateToken(length: number = TOKEN_LENGTH): string {
  const charsetLength = TOKEN_CHARSET.length;
  // Largest multiple of charsetLength that fits in a byte (0–255).
  const maxUnbiasedByte = Math.floor(256 / charsetLength) * charsetLength;

  const result: string[] = [];

  while (result.length < length) {
    // Request enough random bytes to satisfy the remaining characters plus
    // a small surplus to reduce the likelihood of needing a second pass.
    const needed = length - result.length;
    const buffer = new Uint8Array(needed + Math.ceil(needed * 0.25));
    crypto.getRandomValues(buffer);

    for (const byte of buffer) {
      if (result.length >= length) break;
      // Reject bytes that would introduce bias.
      if (byte >= maxUnbiasedByte) continue;
      result.push(TOKEN_CHARSET[byte % charsetLength]);
    }
  }

  return result.join("");
}

/**
 * Build the canonical payload string that is signed by the issuer's private
 * key and later verified by the `crypto.subtle.verify` call on the server.
 *
 * The string is deterministic: given the same inputs in the same order, it
 * always produces the same output.  Each field is separated by `:` so there
 * is no ambiguity between adjacent empty segments.
 *
 * Actual hashing (SHA-256) and signing (ECDSA) are performed server-side
 * where the private key is available.  This helper is shared so both the
 * signing path and the verification path use an identical canonical form.
 *
 * @param token      - The short token embedded in the QR image.
 * @param url        - The destination URL the QR code resolves to.
 * @param geoHash    - Geohash of the registered location, or an empty string
 *                     when no location is bound to the QR code.
 * @param expiry     - ISO 8601 expiry datetime string, or an empty string when
 *                     the QR code does not expire.
 * @returns The canonical payload string ready for signing / hashing.
 */
export function hashPayload(
  token: string,
  url: string,
  geoHash: string,
  expiry: string
): string {
  return `${token}:${url}:${geoHash}:${expiry}`;
}

/**
 * Encode a `Uint8Array` to a URL-safe Base64 string (RFC 4648 §5).
 *
 * Replaces `+` with `-`, `/` with `_`, and strips trailing `=` padding so the
 * result can be embedded in a URL query parameter or JWT without additional
 * percent-encoding.
 *
 * @param buffer - Raw bytes to encode.
 * @returns URL-safe Base64 string with no padding.
 */
export function base64UrlEncode(buffer: Uint8Array): string {
  // Convert each byte to its character code and build a binary string, then
  // hand off to `btoa` which is available in all target environments.
  let binary = "";
  for (let i = 0; i < buffer.length; i++) {
    binary += String.fromCharCode(buffer[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

/**
 * Decode a URL-safe Base64 string (RFC 4648 §5) back to a `Uint8Array`.
 *
 * Accepts both padded and unpadded input, and handles both the standard
 * (`+`/`/`) and URL-safe (`-`/`_`) alphabets.
 *
 * @param str - Base64url string to decode.
 * @returns Decoded bytes.
 * @throws {DOMException} If `str` is not a valid Base64 string after
 *   normalisation (thrown by `atob`).
 */
export function base64UrlDecode(str: string): Uint8Array {
  // Restore standard Base64 alphabet.
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");

  // Re-add padding so `atob` is happy.
  const padded = base64.padEnd(
    base64.length + ((4 - (base64.length % 4)) % 4),
    "="
  );

  const binary = atob(padded);
  const buffer = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    buffer[i] = binary.charCodeAt(i);
  }
  return buffer;
}
