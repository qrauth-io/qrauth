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

  /** Verify the Merkle inclusion proof + SLH-DSA batch-root signature. */
  verifyHybridLeg(input: {
    leafHash: string;
    merklePath: MerkleNode[];
    batchId: string;
  }): Promise<{ ok: true } | { ok: false; reason: string }>;
}

export interface SignatureVerifyOutcome {
  /** True iff both asymmetric legs (ECDSA + Merkle/SLH-DSA when applicable) verified. */
  signatureValid: boolean;
  /** True when no Merkle leg exists (legacy row) or the leg verified. */
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
 * legs both verify against the same byte string. The Merkle leg uses the
 * leaf hash persisted on the row and verifies the inclusion proof against
 * the batch root.
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

  let merkleProofValid = true;
  let pqcReason: string | null = null;
  let merkleBatchId: string | null = row.merkleBatchId ?? null;

  const isHybridRow =
    row.algVersion === 'hybrid-ecdsa-slhdsa-v1' &&
    row.merkleBatchId != null &&
    row.merkleLeafHash != null &&
    row.merklePath != null;

  if (isHybridRow) {
    merkleBatchId = row.merkleBatchId;
    const result = await deps.verifyHybridLeg({
      leafHash: row.merkleLeafHash as string,
      merklePath: row.merklePath as MerkleNode[],
      batchId: row.merkleBatchId as string,
    });
    if (!result.ok) {
      merkleProofValid = false;
      pqcReason = result.reason;
    }
  }

  return {
    signatureValid: ecdsaValid && merkleProofValid,
    merkleProofValid,
    merkleBatchId,
    pqcReason,
    macRejected: false,
  };
}
