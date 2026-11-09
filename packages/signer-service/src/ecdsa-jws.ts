import { createSign } from 'node:crypto';

/**
 * ADR-0003 Slice 3a — prefix-free ECDSA JWS signing primitive.
 *
 * The existing `/v1/sign-ecdsa` endpoint prepends the
 * `qrauth:ecdsa-canonical:v1:` domain-separation prefix to every message
 * (Audit-2 N-2) before signing, and returns a DER-encoded signature.
 * That output is unverifiable by a stock OIDC client: `jose.jwtVerify`
 * computes the ES256 signature over exactly `base64url(header).base64url(payload)`
 * — no prefix — and expects the IEEE P1363 raw `R||S` encoding, not DER.
 *
 * This module is the prefix-free counterpart used by the OIDC ID-token
 * path. It signs the JWS canonical input bytes directly (no prefix) and
 * returns the base64url-encoded raw `R||S` signature (64 bytes for P-256),
 * ready to concatenate as the third segment of a compact JWS.
 *
 * Cryptographic-domain separation from the prefixed endpoint is preserved
 * by input format: a JWS canonical input is `<base64url>.<base64url>` and
 * the `qrauth:ecdsa-canonical:v1:` prefix is NOT valid base64url (`:` is
 * outside the alphabet), so a prefixed-canonical signature can never be a
 * valid JWS and a JWS signature can never satisfy the prefixed verifier.
 * The {@link JWS_CANONICAL_INPUT_RE} guard below is the defense-in-depth
 * that keeps this endpoint from signing arbitrary bytes.
 */

/**
 * Structural guard for a JWS signing input: two non-empty base64url
 * segments joined by a single dot (`<protected>.<payload>`). Anything
 * containing a `:` (e.g. the canonical domain prefix) or any character
 * outside the base64url alphabet is rejected.
 */
export const JWS_CANONICAL_INPUT_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

/**
 * Sign a validated JWS canonical input with the ECDSA-P256 private key in
 * `pem`. Signs the UTF-8 bytes of `canonicalInput` directly — no domain
 * prefix — and returns the base64url-encoded raw `R||S` signature.
 *
 * `dsaEncoding: 'ieee-p1363'` makes Node emit the 64-byte raw signature
 * JWS requires; no manual DER→P1363 conversion is involved.
 *
 * The caller is responsible for validating `canonicalInput` against
 * {@link JWS_CANONICAL_INPUT_RE} first.
 */
export function signEcdsaJws(pem: string, canonicalInput: string): string {
  const signer = createSign('SHA256');
  signer.update(canonicalInput, 'utf8');
  signer.end();
  const raw = signer.sign({ key: pem, dsaEncoding: 'ieee-p1363' });
  return raw.toString('base64url');
}
