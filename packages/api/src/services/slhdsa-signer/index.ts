/**
 * SLH-DSA signer abstraction (ALGORITHM.md §13.1).
 *
 * The hot signing path used to read SLH-DSA private key bytes off the
 * API server's local disk and sign in-process. That works for dev but
 * is the wrong threat model for production: a single API-server
 * compromise yields the keys.
 *
 * This module decouples "I have a Merkle root, please sign it" from
 * "where do the private bytes live". Two backends ship today:
 *
 *   - LocalSlhDsaSigner — loads the key from disk and signs in-process.
 *     Used in dev and in the protocol test suite. Documented as the
 *     fallback only — production deployments must use the HTTP backend.
 *
 *   - HttpSlhDsaSigner — POSTs the message to a separate signer service
 *     (`packages/signer-service/`) running on its own host with private
 *     network access only. The API server has no copy of the key.
 *
 * Future backends (KMS, HashiCorp Vault, hardware HSM) implement the
 * same interface without touching call sites.
 *
 * The interface is narrow on purpose: only `signRoot` and
 * `getPublicKey`. Any backend that respects "I will sign this exact
 * payload with the key behind this id" satisfies it. Adding methods
 * here forces every backend to implement them, so resist the urge.
 */

export interface SlhDsaSigner {
  /**
   * Sign the given message with the private key identified by `keyId`.
   * Returns the SLH-DSA-SHA2-128s signature (7,856 bytes).
   *
   * Implementations MUST NOT mutate the input buffer. Callers MUST NOT
   * assume the returned buffer is reused — backends may return a fresh
   * allocation per call.
   */
  signRoot(keyId: string, message: Buffer): Promise<Buffer>;

  /**
   * Return the SLH-DSA public key (32 bytes) for `keyId`. Used by tests
   * and reconciliation paths that verify a previously-signed root
   * without touching the database.
   */
  getPublicKey(keyId: string): Promise<Buffer>;
}

export { LocalSlhDsaSigner } from './local.js';
export { HttpSlhDsaSigner } from './http.js';
