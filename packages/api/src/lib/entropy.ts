import { randomBytes } from "crypto";

/**
 * Single-source secure entropy helper (AUDIT-FINDING-017 + 023).
 *
 * The hot crypto paths in QRAuth (signing key generation, batch nonces,
 * per-leaf nonces, MAC secret derivation) go through this helper instead
 * of calling `randomBytes` directly. This keeps the call sites identical
 * so a future upgrade to a real multi-source combiner (KMS + HSM + OS)
 * is a one-file change rather than a sweep.
 *
 * Previously this module claimed to be a "multi-source entropy combiner"
 * with the shape `OS_CSPRNG XOR HMAC_DRBG(OS_CSPRNG || HSM_RNG)`. The
 * HSM source was a stub that pulled from `randomBytes` again, so the
 * final output was `OS_CSPRNG XOR HMAC_SHA3(OS_CSPRNG || OS_CSPRNG)` —
 * structurally a single-source expansion, not a combiner. The audit
 * flagged the documentation/implementation gap (Finding-017) and the
 * NIST SP 800-90A compliance claim in the `hmacDrbg` helper's name
 * (Finding-023).
 *
 * Decision: delete the combiner, shrink this to a thin, honestly-named
 * wrapper over `crypto.randomBytes`. On Linux this backs onto
 * `getrandom(2)`, which is the kernel CSPRNG pool — strong in practice.
 * Callers keep the same signature.
 *
 * If and when a real KMS/HSM entropy source is provisioned, this module
 * is the single place to re-introduce the combiner shape.
 */
export async function generateSecureEntropy(bytes: number): Promise<Buffer> {
  if (!Number.isInteger(bytes) || bytes <= 0) {
    throw new Error(`generateSecureEntropy: bytes must be a positive integer, got ${bytes}`);
  }
  return randomBytes(bytes);
}
