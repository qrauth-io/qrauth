import type { PrismaClient, SignedBatch as PrismaSignedBatch } from '@prisma/client';
import { SigningService } from './signing.js';
import { BatchSigner, type BatchSignResult } from './batch-signer.js';
import {
  ALGORITHM_VERSION_HYBRID,
  ALGORITHM_VERSION_PQC,
  verifyMerkleProof,
  type MerkleNode,
  type QRPayloadInput,
} from './merkle-signing.js';
import { slhDsaVerify } from './slhdsa-adapter.js';

/**
 * Marker for a QR row whose ECDSA leg is signed but whose Merkle/SLH-DSA leg
 * is still in flight inside the batcher. Used by routes that take the async
 * issuance path to flag rows the verifier should treat as ECDSA-only until
 * the upgrade lands.
 */
export const ALGORITHM_VERSION_PENDING = 'ecdsa-pending-slhdsa-v1' as const;

/**
 * Hybrid signing service (ALGORITHM.md §6.4).
 *
 * Wraps the legacy ECDSA `SigningService` with the new SLH-DSA + Merkle batch
 * pipeline. For each QR code being issued we:
 *
 *   1. Sign the canonical payload with ECDSA-P256 — same call the existing
 *      route used to make. Output goes into `QRCode.signature` unchanged.
 *
 *   2. Build a Merkle batch around the same logical payload, sign the root
 *      with SLH-DSA-SHA2-128s, persist a `SignedBatch` row.
 *
 *   3. Return both signatures plus the per-token merkle inclusion proof.
 *      The caller persists those onto the `QRCode` row.
 *
 * The batch model is single-leaf today (one QR per Merkle tree). True
 * batching is a downstream optimization (ALGORITHM.md §6.2) that doesn't
 * require schema changes — only a queue + flush trigger. Keeping the
 * single-leaf shape here avoids a queue dependency for MVP and lets the
 * verification path exercise the full Merkle/SLH-DSA codepath from day one.
 */

export interface HybridSignInput {
  organizationId: string;
  signingKeyDbId: string;
  signingKeyId: string;       // file-system / hex keyId paired with PEM + slhdsa file
  token: string;
  destinationUrl: string;
  geoHash: string;            // legacy single-string geohash, signed by ECDSA leg
  expiresAt: string;          // ISO 8601, empty string for non-expiring
  contentHash: string;
  // Geo components for the canonical PQC payload — different shape from the
  // legacy ECDSA `geoHash` because the hash-native canonical form needs the
  // raw lat/lng/radius (it derives its own SHA3 geo hash internally).
  lat: number | null;
  lng: number | null;
  radiusM: number | null;
  expiresAtDate: Date | null;
}

export interface HybridSignOutput {
  algVersion: typeof ALGORITHM_VERSION_HYBRID;
  ecdsaSignature: string;
  batchId: string;
  merkleRoot: string;
  rootSignature: string;
  leafIndex: number;
  leafHash: string;
  leafNonce: string;
  merklePath: MerkleNode[];
}

export class HybridSigningService {
  constructor(
    private prisma: PrismaClient,
    private signingService: SigningService,
    private batchSigner: BatchSigner,
  ) {}

  /**
   * Sign one QR payload through both legs of the hybrid model:
   *   - ECDSA leg runs synchronously (~1ms) so the legacy verifier still
   *     produces identical bytes.
   *   - Merkle/SLH-DSA leg is delegated to the BatchSigner, which groups
   *     concurrent enqueues into a single SLH-DSA sign per flush window.
   *     Per-QR latency is dominated by the batcher's wait time, not the
   *     SLH-DSA cost.
   *
   * Throws when the signing key has no SLH-DSA secret on disk — that means
   * the key predates the PQC layer and the caller should fall back to the
   * legacy `signingService.signQRCode` path explicitly. Failing loudly here
   * keeps the contract obvious; silently degrading would mask broken keys.
   */
  async signSingleQR(input: HybridSignInput): Promise<HybridSignOutput> {
    // Pre-flight: confirm the SLH-DSA key exists before we charge for the
    // ECDSA sign and join a batch we can't complete. This adds one fs read
    // per QR but keeps the failure mode crisp.
    const slhPair = await this.signingService.loadSlhDsaKeyPair(input.signingKeyId);
    if (!slhPair) {
      throw new Error(
        `HybridSigningService: signing key "${input.signingKeyId}" has no SLH-DSA material. ` +
          'Generate a fresh key (createKeyPair) or rotate this one.',
      );
    }

    // 1. ECDSA leg — identical bytes to what the legacy path produced. This
    //    keeps existing verifiers (third parties holding the public key)
    //    able to verify the QR with no software change.
    const ecdsaSignature = await this.signingService.signQRCode(
      input.signingKeyId,
      input.token,
      input.destinationUrl,
      input.geoHash,
      input.expiresAt,
      input.contentHash,
    );

    // 2. Merkle/SLH-DSA leg via the batcher. The canonical payload uses the
    //    hash-native geo encoding from packages/shared/src/canonical.ts;
    //    verification must reproduce these exact inputs.
    const merklePayload: QRPayloadInput = {
      token: input.token,
      tenantId: input.organizationId,
      destinationUrl: input.destinationUrl,
      lat: input.lat,
      lng: input.lng,
      radiusM: input.radiusM,
      // Empty expiry → epoch sentinel so cross-language SDKs don't have to
      // special-case nullables. The ECDSA leg already accepts empty string
      // here; we use a fixed sentinel string for the Merkle leg so it is
      // deterministic and reproducible.
      expiresAt: input.expiresAtDate ?? new Date(0),
    };

    const batchResult = await this.batchSigner.enqueue({
      organizationId: input.organizationId,
      signingKeyDbId: input.signingKeyDbId,
      signingKeyId: input.signingKeyId,
      payload: merklePayload,
    });

    return {
      algVersion: batchResult.algVersion,
      ecdsaSignature,
      batchId: batchResult.batchId,
      merkleRoot: batchResult.merkleRoot,
      rootSignature: batchResult.rootSignature,
      leafIndex: batchResult.leafIndex,
      leafHash: batchResult.leafHash,
      leafNonce: batchResult.leafNonce,
      merklePath: batchResult.merklePath,
    };
  }

  /**
   * Async issuance variant. Returns the ECDSA signature synchronously and
   * hands back a pending promise for the Merkle/SLH-DSA leg.
   *
   * The caller persists a QR row immediately with `algVersion =
   * 'ecdsa-pending-slhdsa-v1'` and the merkle fields nulled, then attaches a
   * `.then()` handler to `merklePromise` that updates the row with the
   * inclusion proof + flips `algVersion` to `'hybrid-ecdsa-slhdsa-v1'` once
   * the batch flushes.
   *
   * Verification of pending rows succeeds via the ECDSA leg alone — the
   * gating in `routes/verify.ts` only enters the hybrid branch when the
   * merkle fields are populated, so a pending row simply skips the PQC
   * check until the upgrade lands. This is a transient weakening of the
   * defense-in-depth posture, not a hole: the row is no weaker than it
   * would be under pure ECDSA signing.
   *
   * Throws synchronously if the signing key has no SLH-DSA material —
   * same contract as `signSingleQR`.
   */
  async signSingleQRAsync(input: HybridSignInput): Promise<{
    ecdsaSignature: string;
    merklePromise: Promise<BatchSignResult>;
  }> {
    // Pre-flight: confirm the SLH-DSA key exists. Same reasoning as the
    // sync path — fail loudly rather than enqueue a job that can't complete.
    const slhPair = await this.signingService.loadSlhDsaKeyPair(input.signingKeyId);
    if (!slhPair) {
      throw new Error(
        `HybridSigningService: signing key "${input.signingKeyId}" has no SLH-DSA material. ` +
          'Generate a fresh key (createKeyPair) or rotate this one.',
      );
    }

    const ecdsaSignature = await this.signingService.signQRCode(
      input.signingKeyId,
      input.token,
      input.destinationUrl,
      input.geoHash,
      input.expiresAt,
      input.contentHash,
    );

    const merklePayload: QRPayloadInput = {
      token: input.token,
      tenantId: input.organizationId,
      destinationUrl: input.destinationUrl,
      lat: input.lat,
      lng: input.lng,
      radiusM: input.radiusM,
      expiresAt: input.expiresAtDate ?? new Date(0),
    };

    // Fire the enqueue but do NOT await — the caller will attach to the
    // returned promise after persisting the QR row.
    const merklePromise = this.batchSigner.enqueue({
      organizationId: input.organizationId,
      signingKeyDbId: input.signingKeyDbId,
      signingKeyId: input.signingKeyId,
      payload: merklePayload,
    });

    return { ecdsaSignature, merklePromise };
  }

  /**
   * Verify the SLH-DSA + Merkle leg of a hybrid-signed QR.
   *
   * The ECDSA leg is verified separately by the existing
   * `SigningService.verifyQRCode` path; this method only validates what the
   * legacy verifier cannot. Both legs MUST pass for a hybrid-signed QR to be
   * considered authentic — see ALGORITHM.md §6.4.
   *
   * Returns `null` on success, or a short error code on failure.
   */
  async verifyHybridLeg(args: {
    leafHash: string;
    merklePath: MerkleNode[];
    batchId: string;
  }): Promise<{ ok: true; batch: PrismaSignedBatch } | { ok: false; reason: string }> {
    const batch = await this.prisma.signedBatch.findUnique({
      where: { batchId: args.batchId },
      include: { signingKey: true },
    });
    if (!batch) return { ok: false, reason: 'BATCH_NOT_FOUND' };
    if (!batch.signingKey.slhdsaPublicKey) {
      return { ok: false, reason: 'BATCH_KEY_HAS_NO_SLHDSA' };
    }

    const merkleOk = verifyMerkleProof(args.leafHash, args.merklePath, batch.merkleRoot);
    if (!merkleOk) return { ok: false, reason: 'MERKLE_PROOF_INVALID' };

    const slhdsaOk = await slhDsaVerify(
      Buffer.from(batch.signingKey.slhdsaPublicKey, 'base64'),
      Buffer.from(batch.merkleRoot, 'hex'),
      Buffer.from(batch.rootSignature, 'base64'),
    );
    if (!slhdsaOk) return { ok: false, reason: 'BATCH_SIGNATURE_INVALID' };

    return { ok: true, batch };
  }
}

export { ALGORITHM_VERSION_HYBRID, ALGORITHM_VERSION_PQC };
