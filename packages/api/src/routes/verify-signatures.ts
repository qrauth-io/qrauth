/**
 * Signature verification decision tree for `GET /:token` (AUDIT-FINDING-001
 * plus canonical-form unification from Findings 011/019/020/021).
 *
 * Lives in its own file so the unit tests can import it without pulling the
 * full verify route (Fastify plugin, renderers, Prisma, queue wiring) into
 * the test's transitive graph. The rule it enforces is the hot-path
 * invariant from the audit: the MAC leg is a *fast-reject pre-filter only*,
 * and for hybrid rows the ECDSA and Merkle/SLH-DSA legs both run on every
 * request regardless of whether the MAC matched.
 *
 * The caller passes in a pre-built canonical string (produced via
 * `canonicalizeCore`) plus spy-able dependency functions. Tests replace the
 * deps with `vi.fn` spies; the route handler wires them to the real
 * MacService / SigningService / HybridSigningService.
 */
import type { QRCode } from '@prisma/client';
import { ALG_VERSION_POLICY } from '@qrauth/shared';
import type { MerkleNode } from '../services/merkle-signing.js';

/** Minimal shape of a QR row consumed by the signature decision tree. */
export type SignatureVerifyRow = Pick<
  QRCode,
  | 'token'
  | 'organizationId'
  | 'macTokenMac'
  | 'macKeyVersion'
  | 'algVersion'
  | 'merkleBatchId'
  | 'merkleLeafHash'
  | 'merkleLeafNonce'
  | 'signature'
> & {
  merklePath: unknown;
  signingKey: { publicKey: string };
};

export interface SignatureVerifyDeps {
  /** Recompute the MAC over the canonical payload and compare. */
  verifyMac(input: {
    organizationId: string;
    canonicalPayload: string;
    storedMac: string;
    keyVersion: number | null;
  }): Promise<boolean>;

  /** Verify the ECDSA-P256 leg against the org's signing public key. */
  verifyEcdsa(publicKeyPem: string, signature: string, canonical: string): boolean;

  /**
   * Verify the Merkle/SLH-DSA leg: recompute the leaf from `coreCanonical`
   * and `nonce`, compare it with `storedLeafHash`, walk the inclusion proof
   * from the recomputed leaf, and verify the batch-root signature.
   */
  verifyHybridLeg(input: {
    organizationId: string;
    coreCanonical: string;
    nonce: string;
    storedLeafHash: string;
    merklePath: MerkleNode[];
    batchId: string;
  }): Promise<{ ok: true } | { ok: false; reason: string }>;
}

export interface SignatureVerifyOutcome {
  /** True iff both asymmetric legs (ECDSA + Merkle/SLH-DSA when applicable) verified. */
  signatureValid: boolean;
  /** True when the Merkle/SLH-DSA leg verified. */
  merkleProofValid: boolean;
  /** Batch id of the SignedBatch backing this row, if any. */
  merkleBatchId: string | null;
  /** PQC failure reason, when the Merkle leg rejected. */
  pqcReason: string | null;
  /** True iff the MAC pre-filter rejected — the caller should fail closed. */
  macRejected: boolean;
}

/**
 * Run the three-leg verification decision tree for a QR row.
 *
 * Contract (AUDIT-FINDING-001 + canonical-form unification):
 *   1. If the row has `macTokenMac` and recomputation MISSES → `macRejected: true`,
 *      neither ECDSA nor Merkle/SLH-DSA runs, caller returns a signature-invalid
 *      failure. This is the audit's "fast-reject only" pre-filter.
 *   2. Otherwise (MAC hit, or no MAC on the row) → run the ECDSA leg, then
 *      run the Merkle/SLH-DSA leg if the row is hybrid. Both must succeed for
 *      `signatureValid: true`.
 *
 * `coreCanonical` is the unified canonical core string the row is bound to —
 * the caller computes it once via `canonicalizeCore(...)` and the MAC + ECDSA
 * legs both verify against the same byte string. The Merkle leg recomputes
 * the leaf from the same core plus the row's stored nonce; the stored leaf
 * hash is only compared against, never trusted.
 *
 * A hybrid row MUST carry a batch id, leaf hash, nonce and inclusion path;
 * if any is missing, verification fails (`MERKLE_FIELDS_MISSING`). Hybrid is
 * the only alg version with a verifier; any other version that reaches this
 * function fails (`ALG_VERSION_UNSUPPORTED`).
 *
 * The function never throws for cryptographic failure; it encodes it in the
 * returned outcome so the caller can log once and build a consistent
 * response. It may throw if the deps themselves raise — that surfaces as a
 * 500 at the route level.
 */
export async function verifyRowSignatures(
  row: SignatureVerifyRow,
  coreCanonical: string,
  deps: SignatureVerifyDeps,
): Promise<SignatureVerifyOutcome> {
  if (row.macTokenMac) {
    const macOk = await deps.verifyMac({
      organizationId: row.organizationId,
      canonicalPayload: coreCanonical,
      storedMac: row.macTokenMac,
      keyVersion: row.macKeyVersion,
    });
    if (!macOk) {
      return {
        signatureValid: false,
        merkleProofValid: false,
        merkleBatchId: row.merkleBatchId ?? null,
        pqcReason: 'MAC_PREFILTER_REJECTED',
        macRejected: true,
      };
    }
  }

  // Asymmetric verification runs regardless of whether the MAC matched.
  const ecdsaValid = deps.verifyEcdsa(row.signingKey.publicKey, row.signature, coreCanonical);

  let merkleProofValid = false;
  let pqcReason: string | null = null;
  const merkleBatchId: string | null = row.merkleBatchId ?? null;

  const leg = row.algVersion === ALG_VERSION_POLICY.hybrid ? hybridLegInputs(row) : null;
  if (row.algVersion !== ALG_VERSION_POLICY.hybrid) {
    pqcReason = 'ALG_VERSION_UNSUPPORTED';
  } else if (!leg) {
    pqcReason = 'MERKLE_FIELDS_MISSING';
  } else {
    const result = await deps.verifyHybridLeg({
      organizationId: row.organizationId,
      coreCanonical,
      ...leg,
    });
    if (result.ok) merkleProofValid = true;
    else pqcReason = result.reason;
  }

  return {
    signatureValid: ecdsaValid && merkleProofValid,
    merkleProofValid,
    merkleBatchId,
    pqcReason,
    macRejected: false,
  };
}

/**
 * Extract the Merkle-leg inputs from a hybrid row, or `null` when any of
 * them is missing or malformed (the caller then fails closed).
 */
function hybridLegInputs(row: SignatureVerifyRow): {
  nonce: string;
  storedLeafHash: string;
  merklePath: MerkleNode[];
  batchId: string;
} | null {
  const { merkleBatchId, merkleLeafHash, merkleLeafNonce, merklePath } = row;
  if (!merkleBatchId || !merkleLeafHash || !merkleLeafNonce) return null;
  if (!Array.isArray(merklePath)) return null;
  return {
    nonce: merkleLeafNonce,
    storedLeafHash: merkleLeafHash,
    merklePath: merklePath as MerkleNode[],
    batchId: merkleBatchId,
  };
}
