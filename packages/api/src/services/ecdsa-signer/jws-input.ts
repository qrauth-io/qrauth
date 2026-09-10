/**
 * Structural guard for a JWS signing input: two non-empty base64url
 * segments joined by a single dot (`<protected>.<payload>`). Mirrors the
 * regex enforced server-side by the signer's `/v1/sign-ecdsa-jws`
 * endpoint (`packages/signer-service/src/ecdsa-jws.ts`).
 *
 * The `qrauth:ecdsa-canonical:v1:` domain prefix is not valid base64url
 * (`:` is outside the alphabet), so this guard rejects any attempt to push
 * prefixed-canonical bytes through the prefix-free JWS path — the
 * cryptographic-domain separation that keeps the two signing surfaces from
 * cross-replaying. ADR-0003 Slice 3a.
 */
export const JWS_CANONICAL_INPUT_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
