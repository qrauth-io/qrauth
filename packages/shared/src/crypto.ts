import { TOKEN_CHARSET, TOKEN_LENGTH } from "./constants.js";

/**
 * Domain-separation prefix for the CLI terminal verification code (ADR-0002
 * §"Security considerations"). The code is an anti-phishing aid, NOT a secret:
 * it lets a human confirm the QR they are approving belongs to the session
 * their own terminal started. Derived from server-held session material
 * (`sessionId`), never from the PKCE `code_verifier`.
 */
export const CLI_VERIFICATION_CODE_DOMAIN = "qrauth:cli-verify:v1:";

/**
 * Derive the short, human-comparable CLI verification code for a session.
 *
 * Single source of truth shared by the API (renders it on the approval page)
 * and the CLI (prints it in the terminal): both reproduce the exact same code
 * from `sessionId` alone, so no round-trip or stored column is needed.
 *
 * Uses the Web Crypto `crypto.subtle.digest` so it runs identically in Node
 * (19+) and the browser without pulling `node:crypto` into browser bundles.
 * The SHA-256 output is byte-identical to a Node `createHash('sha256')` digest,
 * so codes match across both runtimes.
 *
 * Format: `XXXX-XXXX` (8 uppercase hex chars). Hex avoids letter ambiguity.
 */
export async function deriveCliVerificationCode(sessionId: string): Promise<string> {
  const data = new TextEncoder().encode(CLI_VERIFICATION_CODE_DOMAIN + sessionId);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const hex = Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const slice = hex.slice(0, 8).toUpperCase();
  return `${slice.slice(0, 4)}-${slice.slice(4, 8)}`;
}

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
