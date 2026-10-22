import { createSign } from 'node:crypto';

/**
 * ADR-0003 Slice 7a — prefix-free RSA JWS signing primitive (RS256).
 *
 * Additive sibling of {@link ./ecdsa-jws.ts} `signEcdsaJws`. OIDC Core §15.1
 * makes RS256 mandatory-to-implement for every OP; Slice 6 Phase A
 * conformance blocked on it. This module signs the JWS canonical input bytes
 * directly (no domain prefix) with RSASSA-PKCS1-v1_5 + SHA-256 — RS256 per
 * RFC 7518 §3.3 — and returns the base64url-encoded signature, ready to
 * concatenate as the third segment of a compact JWS.
 *
 * Cryptographic-domain separation from the prefixed `/v1/sign-ecdsa` endpoint
 * holds by INPUT FORMAT, identically to the ECDSA JWS path: a JWS canonical
 * input is `<base64url>.<base64url>`, and the `qrauth:ecdsa-canonical:v1:`
 * prefix is not valid base64url (`:` is outside the alphabet), so a
 * prefixed-canonical message can never reach this path. The
 * {@link JWS_CANONICAL_INPUT_RE} guard (re-exported from `./ecdsa-jws.ts`, a
 * single source of truth shared by both JWS endpoints) is the defense-in-depth
 * that keeps this endpoint from signing arbitrary bytes.
 *
 * RS256 vs ES256 separation: the algorithms are distinct, so an RS256
 * signature never verifies under an ES256 verifier (and vice versa) even over
 * an identical canonical input — the JWS `alg` header pins which one applies.
 */

export { JWS_CANONICAL_INPUT_RE } from './ecdsa-jws.js';

/**
 * Sign a validated JWS canonical input with the RSA private key in `pem`.
 * Signs the UTF-8 bytes of `canonicalInput` directly — no domain prefix —
 * with RSA-SHA256 (RS256) and returns the base64url-encoded signature.
 *
 * The caller is responsible for validating `canonicalInput` against
 * {@link JWS_CANONICAL_INPUT_RE} first.
 */
export function signRsaJws(pem: string, canonicalInput: string): string {
  const signer = createSign('RSA-SHA256');
  signer.update(canonicalInput, 'utf8');
  signer.end();
  return signer.sign(pem).toString('base64url');
}
