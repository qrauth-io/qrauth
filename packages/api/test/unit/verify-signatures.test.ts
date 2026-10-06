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
 * tree: MAC hit, MAC miss, no MAC.
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
    merkleLeafHash: 'abc123',
    merklePath: [{ hash: '00'.repeat(32), position: 'right' }],
    signature: 'sig-bytes',
    signingKey: { publicKey: '-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----' },
  };
  return { ...base, ...overrides } as SignatureVerifyRow;
}

/** A row with no Merkle batch — used to exercise the non-hybrid branch. */
function macOnlyRow(overrides: Partial<SignatureVerifyRow> = {}): SignatureVerifyRow {
  return hybridRow({
    algVersion: 'hybrid-ecdsa-slhdsa-v1',
    merkleBatchId: null,
    merkleLeafHash: null,
    merklePath: null,
    ...overrides,
  });
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

  describe('row with no Merkle batch (non-hybrid branch)', () => {
    it('runs ECDSA but not the Merkle leg', async () => {
      const out = await verifyRowSignatures(
        macOnlyRow({ macTokenMac: null, macKeyVersion: null }),
        CANONICAL,
        deps,
      );

      expect(deps.verifyEcdsa).toHaveBeenCalledTimes(1);
      expect(deps.verifyHybridLeg).not.toHaveBeenCalled();
      expect(out.signatureValid).toBe(true);
      expect(out.merkleProofValid).toBe(true);
      expect(out.merkleBatchId).toBeNull();
    });
  });
});
