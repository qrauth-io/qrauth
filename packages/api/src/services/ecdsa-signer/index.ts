/**
 * ECDSA signer abstraction (AUDIT-FINDING-016).
 *
 * Mirrors the existing `SlhDsaSigner` abstraction. The hot signing
 * paths (`SigningService.signCanonical`, proximity attestations,
 * auth-session approvals) used to read ECDSA PEM files off the API
 * server's local disk and sign in-process. That meant an API-server
 * compromise yielded the private keys. Finding-016 moves those key
 * bytes to the standalone signer service and routes every ECDSA sign
 * through this interface.
 *
 * Backends:
 *   - `LocalEcdsaSigner` — reads the encrypted envelope from disk,
 *     decrypts via `lib/key-at-rest.ts`, signs in-process. Dev-only
 *     fallback. Inherits the same blast radius as the API server box.
 *   - `HttpEcdsaSigner` — POSTs to the signer service's
 *     `/v1/sign-ecdsa` endpoint. Production backend. The API server
 *     never holds the private bytes.
 *
 * The interface is narrow on purpose: only `signCanonical`. Adding
 * methods forces every backend to implement them.
 */

export interface EcdsaSigner {
  /**
   * Sign a pre-built canonical UTF-8 string with the ECDSA-P256 private
   * key identified by `keyId`. Returns the DER-encoded signature as
   * base64. Never mutates the input.
   */
  signCanonical(keyId: string, canonical: string): Promise<string>;
}

export { LocalEcdsaSigner } from './local.js';
export { HttpEcdsaSigner } from './http.js';
