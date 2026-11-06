/**
 * Unit tests for the signature-verification decision tree (AUDIT-FINDING-001
 * plus canonical-form unification AUDIT-FINDING-011/019/020/021).
 *
 * Acceptance criterion from AUDIT1.md §Finding-001:
 *   "Every hybrid row's verification exercises both the ECDSA verify and the
 *    Merkle/SLH-DSA verify on every request (asserted by a test spy)."
 *
 * The helper `verifyRowSignatures` accepts its three verification legs as
 * callable dependencies. These tests substitute `vi.fn` spies for each leg
 * and assert the audit's invariant holds for every branch of the decision
 * tree: MAC hit, MAC miss, no MAC. They also pin that a hybrid row needs
 * every Merkle field, and that only the hybrid alg version has a verifier.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  verifyRowSignatures,
  type SignatureVerifyRow,
  type SignatureVerifyDeps,
} from '../../src/routes/verify-signatures.js';

function hybridRow(overrides: Partial<SignatureVerifyRow> = {}): SignatureVerifyRow {
  const base = {
    token: 'tok-hybrid-1',
    organizationId: 'org-1',
    macTokenMac: 'deadbeef'.repeat(8),
    macKeyVersion: 1,
    algVersion: 'hybrid-ecdsa-slhdsa-v1',
    merkleBatchId: 'batch-1',
    merkleLeafHash: 'ab'.repeat(32),
    merkleLeafNonce: 'cd'.repeat(32),
    merklePath: [{ hash: '00'.repeat(32), position: 'right' }],
    signature: 'sig-bytes',
    signingKey: { publicKey: '-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----' },
  };
  return { ...base, ...overrides } as SignatureVerifyRow;
}


function spies(): SignatureVerifyDeps & {
  verifyMac: ReturnType<typeof vi.fn>;
  verifyEcdsa: ReturnType<typeof vi.fn>;
  verifyHybridLeg: ReturnType<typeof vi.fn>;
} {
  return {
    verifyMac: vi.fn(async () => true),
    verifyEcdsa: vi.fn(() => true),
    verifyHybridLeg: vi.fn(async () => ({ ok: true }) as const),
  };
}

const CANONICAL = 'hybrid-ecdsa-slhdsa-v1|tok|org-1|dest|none|';

describe('verifyRowSignatures (AUDIT-FINDING-001 + 011)', () => {
  let deps: ReturnType<typeof spies>;
  beforeEach(() => {
    deps = spies();
  });

  describe('hybrid row with MAC present', () => {
    it('runs BOTH asymmetric legs when MAC matches', async () => {
      deps.verifyMac.mockResolvedValueOnce(true);

      const out = await verifyRowSignatures(hybridRow(), CANONICAL, deps);

      expect(deps.verifyMac).toHaveBeenCalledTimes(1);
      expect(deps.verifyEcdsa).toHaveBeenCalledTimes(1);
      expect(deps.verifyHybridLeg).toHaveBeenCalledTimes(1);
      expect(out.signatureValid).toBe(true);
      expect(out.merkleProofValid).toBe(true);
      expect(out.macRejected).toBe(false);
    });

    it('hands the Merkle leg the canonical core and stored nonce, not just the stored leaf', async () => {
      const row = hybridRow();
      await verifyRowSignatures(row, CANONICAL, deps);

      expect(deps.verifyHybridLeg).toHaveBeenCalledWith({
        organizationId: row.organizationId,
        coreCanonical: CANONICAL,
        nonce: row.merkleLeafNonce,
        storedLeafHash: row.merkleLeafHash,
        merklePath: row.merklePath,
        batchId: row.merkleBatchId,
      });
    });

    it('passes the same canonical string to both MAC and ECDSA legs', async () => {
      await verifyRowSignatures(hybridRow(), CANONICAL, deps);

      expect(deps.verifyMac).toHaveBeenCalledWith(
        expect.objectContaining({ canonicalPayload: CANONICAL }),
      );
      expect(deps.verifyEcdsa).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(String),
        CANONICAL,
      );
    });

    it('fast-rejects (neither asymmetric leg runs) when MAC misses', async () => {
      deps.verifyMac.mockResolvedValueOnce(false);

      const out = await verifyRowSignatures(hybridRow(), CANONICAL, deps);

      expect(deps.verifyMac).toHaveBeenCalledTimes(1);
      expect(deps.verifyEcdsa).not.toHaveBeenCalled();
      expect(deps.verifyHybridLeg).not.toHaveBeenCalled();
      expect(out.signatureValid).toBe(false);
      expect(out.macRejected).toBe(true);
      expect(out.pqcReason).toBe('MAC_PREFILTER_REJECTED');
    });

    it('signatureValid is false when ECDSA leg fails, even if MAC + Merkle pass', async () => {
      deps.verifyEcdsa.mockReturnValueOnce(false);

      const out = await verifyRowSignatures(hybridRow(), CANONICAL, deps);

      expect(deps.verifyEcdsa).toHaveBeenCalledTimes(1);
      expect(deps.verifyHybridLeg).toHaveBeenCalledTimes(1);
      expect(out.signatureValid).toBe(false);
    });

    it('signatureValid is false when Merkle/SLH-DSA leg fails, even if MAC + ECDSA pass', async () => {
      deps.verifyHybridLeg.mockResolvedValueOnce({ ok: false, reason: 'BATCH_SIGNATURE_INVALID' });

      const out = await verifyRowSignatures(hybridRow(), CANONICAL, deps);

      expect(deps.verifyEcdsa).toHaveBeenCalledTimes(1);
      expect(deps.verifyHybridLeg).toHaveBeenCalledTimes(1);
      expect(out.signatureValid).toBe(false);
      expect(out.merkleProofValid).toBe(false);
      expect(out.pqcReason).toBe('BATCH_SIGNATURE_INVALID');
    });
  });

  describe('hybrid row with no MAC', () => {
    it('runs BOTH asymmetric legs', async () => {
      const row = hybridRow({ macTokenMac: null, macKeyVersion: null });

      const out = await verifyRowSignatures(row, CANONICAL, deps);

      expect(deps.verifyMac).not.toHaveBeenCalled();
      expect(deps.verifyEcdsa).toHaveBeenCalledTimes(1);
      expect(deps.verifyHybridLeg).toHaveBeenCalledTimes(1);
      expect(out.signatureValid).toBe(true);
    });
  });

  describe('hybrid row with missing Merkle fields fails closed', () => {
    const missing: Array<[string, Partial<SignatureVerifyRow>]> = [
      ['merkleLeafNonce', { merkleLeafNonce: null }],
      ['merklePath', { merklePath: null }],
      ['merkleLeafHash', { merkleLeafHash: null }],
      ['merkleBatchId', { merkleBatchId: null }],
      ['all Merkle fields', {
        merkleBatchId: null,
        merkleLeafHash: null,
        merkleLeafNonce: null,
        merklePath: null,
      }],
    ];

    for (const [field, overrides] of missing) {
      it(`rejects when ${field} is missing, even with a valid ECDSA leg`, async () => {
        const row = hybridRow({ macTokenMac: null, macKeyVersion: null, ...overrides });

        const out = await verifyRowSignatures(row, CANONICAL, deps);

        expect(deps.verifyEcdsa).toHaveBeenCalledTimes(1);
        expect(deps.verifyHybridLeg).not.toHaveBeenCalled();
        expect(out.signatureValid).toBe(false);
        expect(out.merkleProofValid).toBe(false);
        expect(out.pqcReason).toBe('MERKLE_FIELDS_MISSING');
      });
    }

    it('rejects when merklePath is not an array', async () => {
      const row = hybridRow({ merklePath: { hash: 'x' } as unknown as null });

      const out = await verifyRowSignatures(row, CANONICAL, deps);

      expect(deps.verifyHybridLeg).not.toHaveBeenCalled();
      expect(out.signatureValid).toBe(false);
      expect(out.pqcReason).toBe('MERKLE_FIELDS_MISSING');
    });
  });

  describe('alg version without a verifier', () => {
    it('fails a reserved non-hybrid version without running the Merkle leg', async () => {
      const row = hybridRow({
        algVersion: 'slhdsa-sha2-128s-v1',
        merkleBatchId: null,
        merkleLeafHash: null,
        merkleLeafNonce: null,
        merklePath: null,
      });

      const out = await verifyRowSignatures(row, CANONICAL, deps);

      expect(deps.verifyHybridLeg).not.toHaveBeenCalled();
      expect(out.signatureValid).toBe(false);
      expect(out.merkleProofValid).toBe(false);
      expect(out.pqcReason).toBe('ALG_VERSION_UNSUPPORTED');
    });
  });
});
