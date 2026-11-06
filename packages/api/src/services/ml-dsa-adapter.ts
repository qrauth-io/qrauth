import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { generateSecureEntropy } from '../lib/entropy.js';

/**
 * ML-DSA-44 adapter.
 *
 * ML-DSA (FIPS 204, formerly CRYSTALS-Dilithium) is the lattice-based PQC
 * signature scheme. Compared to SLH-DSA the trade-offs are:
 *   - Signatures: 2,420 bytes (vs 7,856 for SLH-DSA-128s) — 3.2× smaller
 *   - Sign latency: ~5–10 ms (vs ~50–500 ms for SLH-DSA) — much faster
 *   - Security model: lattice hardness (vs hash preimage)
 *
 * That makes ML-DSA the right tool for interactive operations where
 * latency matters: WebAuthn bridge signing, JWT signatures, ephemeral
 * session tokens. SLH-DSA stays the right tool for the long-lived QR
 * signing path where the conservative hash-only assumption matters and a
 * one-off batch sign latency is fine.
 *
 * This adapter mirrors the surface of `slhdsa-adapter.ts` so call sites
 * can swap parameter sets later without touching the call shape.
 *
 * Library: `@noble/post-quantum` (audited, pure-TS, no WASM).
 */

export const MLDSA_PARAM_SET = 'ml-dsa-44' as const;
export const MLDSA_LENGTHS = {
  publicKey: 1312,
  secretKey: 2560,
  signature: 2420,
  seed: 32,
} as const;

export interface MlDsaKeyPair {
  publicKey: Buffer;
  privateKey: Buffer;
}

// AUDIT-FINDING-003: server-side ML-DSA keygen is gone. The WebAuthn
// bridge keypair is now generated in the browser and only the public
// half reaches the server. Dev scripts that need a keypair call
// `mlDsaKeyPairFromSeed` with a freshly generated seed (see
// `scripts/smoke-hybrid.ts` for an example).

/**
 * Sign a message with an ML-DSA private key.
 *
 * Argument order matches `@noble/post-quantum`: `sign(message, secretKey)`.
 * Verification expects `verify(signature, message, publicKey)` with the
 * same library — see `mlDsaVerify` below.
 */
export async function mlDsaSign(privateKey: Buffer, message: Buffer): Promise<Buffer> {
  if (privateKey.length !== MLDSA_LENGTHS.secretKey) {
    throw new Error(
      `mlDsaSign: privateKey length ${privateKey.length}, expected ${MLDSA_LENGTHS.secretKey}`,
    );
  }
  const signature = ml_dsa44.sign(message, privateKey);
  return Buffer.from(signature);
}

/**
 * Verify an ML-DSA signature. Returns false (never throws) for malformed
 * inputs so verifiers can treat input validation and signature failure
 * uniformly.
 */
export async function mlDsaVerify(
  publicKey: Buffer,
  message: Buffer,
  signature: Buffer,
): Promise<boolean> {
  if (publicKey.length !== MLDSA_LENGTHS.publicKey) return false;
  if (signature.length !== MLDSA_LENGTHS.signature) return false;
  try {
    return ml_dsa44.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

/**
 * Deterministic keygen for protocol test vectors. Never call this in
 * production — the seed must come from `generateSecureEntropy` for real keys.
 */
export function mlDsaKeyPairFromSeed(seed: Buffer): MlDsaKeyPair {
  if (seed.length !== MLDSA_LENGTHS.seed) {
    throw new Error(`mlDsaKeyPairFromSeed: seed must be ${MLDSA_LENGTHS.seed} bytes`);
  }
  const { publicKey, secretKey } = ml_dsa44.keygen(seed);
  return {
    publicKey: Buffer.from(publicKey),
    privateKey: Buffer.from(secretKey),
  };
}
