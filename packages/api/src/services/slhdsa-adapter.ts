import { slh_dsa_sha2_128s } from "@noble/post-quantum/slh-dsa.js";
import { generateSecureEntropy } from "../lib/entropy.js";

/**
 * SLH-DSA-SHA2-128s adapter.
 *
 * SLH-DSA (FIPS 205, formerly SPHINCS+) is the conservative hash-based PQC
 * signature scheme: its security reduces entirely to hash function preimage
 * resistance, with no algebraic structure. Trade-off is signature size
 * (7,856 bytes) and signing latency (~5–50ms) — acceptable for batch root
 * signing, fatal for per-QR signing.
 *
 * Parameter set choice: `sha2-128s` per ALGORITHM.md §13.6.
 *   - Public key: 32 bytes
 *   - Secret key: 64 bytes
 *   - Signature: 7,856 bytes
 *   - 128-bit post-quantum security
 *
 * Library: `@noble/post-quantum` (audited, pure-TS, no WASM).
 *
 * The exported surface is intentionally narrow: keygen, sign, verify. All
 * other SLH-DSA features (prehash, deterministic mode toggles) stay inside
 * this module so call sites cannot accidentally use them.
 */

export const SLHDSA_PARAM_SET = "slh-dsa-sha2-128s" as const;
export const SLHDSA_LENGTHS = {
  publicKey: 32,
  secretKey: 64,
  signature: 7856,
  seed: 48,
} as const;

export interface SlhDsaKeyPair {
  publicKey: Buffer;
  privateKey: Buffer;
}

/**
 * Generate a fresh SLH-DSA keypair using the multi-source entropy combiner.
 *
 * The seed is 48 bytes (3x16) per FIPS 205. We pull it through
 * `generateSecureEntropy` so the keypair inherits whatever HSM/KMS entropy
 * source is configured for the deployment.
 */
export async function slhDsaGenerateKeyPair(): Promise<SlhDsaKeyPair> {
  const seed = await generateSecureEntropy(SLHDSA_LENGTHS.seed);
  const { publicKey, secretKey } = slh_dsa_sha2_128s.keygen(seed);
  return {
    publicKey: Buffer.from(publicKey),
    privateKey: Buffer.from(secretKey),
  };
}

/**
 * Sign a message with an SLH-DSA private key.
 *
 * Note the argument order matches `@noble/post-quantum`: `sign(message, secretKey)`.
 * The randomized variant is used (via the library default) — this provides
 * additional defense against fault attacks at no security cost.
 */
export async function slhDsaSign(privateKey: Buffer, message: Buffer): Promise<Buffer> {
  if (privateKey.length !== SLHDSA_LENGTHS.secretKey) {
    throw new Error(
      `slhDsaSign: privateKey length ${privateKey.length}, expected ${SLHDSA_LENGTHS.secretKey}`,
    );
  }
  const signature = slh_dsa_sha2_128s.sign(message, privateKey);
  return Buffer.from(signature);
}

/**
 * Verify an SLH-DSA signature. Constant-time inside the library.
 */
export async function slhDsaVerify(
  publicKey: Buffer,
  message: Buffer,
  signature: Buffer,
): Promise<boolean> {
  if (publicKey.length !== SLHDSA_LENGTHS.publicKey) return false;
  if (signature.length !== SLHDSA_LENGTHS.signature) return false;
  return slh_dsa_sha2_128s.verify(signature, message, publicKey);
}

/**
 * Deterministic keygen for protocol test vectors. Never call this in
 * production — the seed must come from `generateSecureEntropy` for real keys.
 */
export function slhDsaKeyPairFromSeed(seed: Buffer): SlhDsaKeyPair {
  if (seed.length !== SLHDSA_LENGTHS.seed) {
    throw new Error(`slhDsaKeyPairFromSeed: seed must be ${SLHDSA_LENGTHS.seed} bytes`);
  }
  const { publicKey, secretKey } = slh_dsa_sha2_128s.keygen(seed);
  return {
    publicKey: Buffer.from(publicKey),
    privateKey: Buffer.from(secretKey),
  };
}
