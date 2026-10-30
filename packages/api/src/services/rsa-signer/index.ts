/**
 * RSA signer abstraction (ADR-0003 Slice 7a).
 *
 * Mirrors the `EcdsaSigner` abstraction. OIDC Core §15.1 makes RS256
 * mandatory-to-implement for every OP, so ID tokens must be signable with
 * RSA in addition to ES256. As with ECDSA (Finding-016), the RSA private key
 * never lives on the API box: signing routes through this interface to the
 * standalone signer service.
 *
 * Backends:
 *   - `LocalRsaSigner`  — reads the encrypted envelope from disk, decrypts via
 *     `lib/key-at-rest.ts`, signs in-process. Dev/test fallback only; inherits
 *     the API box's blast radius.
 *   - `HttpRsaSigner`   — POSTs to the signer service's `/v1/sign-rsa-jws`
 *     endpoint. Production backend; the API server never holds the private bytes.
 *
 * The interface is narrow on purpose — only `signJws`. RSA is used solely for
 * the OIDC ID-token JWS path; there is no prefixed-canonical RSA surface.
 */

export interface RsaSigner {
  /**
   * Sign a JWS canonical input (`base64url(header).base64url(payload)`) with
   * the RSA private key identified by `keyId`, using RSASSA-PKCS1-v1_5 +
   * SHA-256 (RS256, RFC 7518 §3.3). Returns the base64url-encoded signature,
   * suitable for direct concatenation as the third segment of a compact JWS.
   *
   * Signs the bytes DIRECTLY (no domain prefix) — required for verification by
   * stock OIDC clients (`jose.jwtVerify`). ADR-0003 Slice 7a.
   */
  signJws(keyId: string, canonicalInput: string): Promise<string>;
}

export { LocalRsaSigner } from './local.js';
export { HttpRsaSigner } from './http.js';
