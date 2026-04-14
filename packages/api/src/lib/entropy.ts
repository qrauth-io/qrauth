import { randomBytes, createHmac } from "crypto";

/**
 * Multi-source entropy combiner.
 *
 * The hot crypto paths in QRAuth (signing key generation, batch nonces,
 * per-leaf nonces, MAC secret derivation) MUST go through this helper instead
 * of calling `randomBytes` directly. This makes the implementation switchable:
 * a single edit upgrades every call site to consume HSM/KMS entropy or
 * additional sources.
 *
 * Design (per ALGORITHM.md §5):
 *   final_bytes = OS_CSPRNG XOR HMAC_DRBG(OS_CSPRNG || HSM_RNG)
 *
 * Security reduces to `max(OS_CSPRNG, HSM_RNG)`: if either source is strong,
 * the output is strong. The HSM source is currently a stub that pulls from
 * `randomBytes` again; the KMS integration lands in Phase 1.5 once the
 * deployment HSM is provisioned. The combiner shape is already in place so
 * that swap is a one-line change inside `kmsGenerateRandom`.
 */
export async function generateSecureEntropy(bytes: number): Promise<Buffer> {
  if (!Number.isInteger(bytes) || bytes <= 0) {
    throw new Error(`generateSecureEntropy: bytes must be a positive integer, got ${bytes}`);
  }

  const [osEntropy, hsmEntropy] = await Promise.all([
    Promise.resolve(randomBytes(bytes * 2)),
    kmsGenerateRandom(bytes * 2),
  ]);

  const drbgOutput = hmacDrbg(osEntropy, hsmEntropy, bytes);
  return xorBuffers(osEntropy.subarray(0, bytes), drbgOutput);
}

/**
 * HMAC-DRBG-style stretch over two seeds.
 *
 * Not a full NIST SP 800-90A DRBG (no reseed counter, no personalization
 * string) — this is the "instantiate + generate one block" path. We chain
 * blocks for outputs longer than 32 bytes to handle large key requests
 * (SLH-DSA seeds: 48 bytes; root signing keys: 64 bytes).
 */
function hmacDrbg(seed1: Buffer, seed2: Buffer, outputBytes: number): Buffer {
  const seed = Buffer.concat([seed1, seed2]);
  const key = createHmac("sha3-256", seed).update("qrauth-drbg-v1").digest();

  const chunks: Buffer[] = [];
  let counter = 0;
  let produced = 0;
  while (produced < outputBytes) {
    const counterBuf = Buffer.alloc(4);
    counterBuf.writeUInt32BE(++counter, 0);
    const block = createHmac("sha3-256", key).update(counterBuf).digest();
    chunks.push(block);
    produced += block.length;
  }
  return Buffer.concat(chunks).subarray(0, outputBytes);
}

/**
 * XOR two buffers. The second buffer is allowed to be shorter than the first
 * and is repeated cyclically — this only matters when the DRBG output length
 * differs from the OS entropy slice, which it never does in `generateSecureEntropy`,
 * but defending against the edge case avoids a footgun for future callers.
 */
function xorBuffers(a: Buffer, b: Buffer): Buffer {
  const result = Buffer.allocUnsafe(a.length);
  for (let i = 0; i < a.length; i++) result[i] = a[i] ^ b[i % b.length];
  return result;
}

/**
 * Stub for hardware/KMS entropy. Replace with AWS KMS `GenerateRandom`,
 * Vault `sys/tools/random`, or YubiHSM RNG once the deployment HSM is
 * provisioned. Returning OS entropy keeps the security floor at
 * `OS_CSPRNG` until then — never weaker than the current state.
 */
async function kmsGenerateRandom(bytes: number): Promise<Buffer> {
  return randomBytes(bytes);
}
