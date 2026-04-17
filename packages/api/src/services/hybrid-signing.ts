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
import {
  canonicalizeCore,
  canonicalGeoHash,
  computeDestHash,
  ALG_VERSION_POLICY,
} from '@qrauth/shared';

/**
 * AUDIT-FINDING-001: process-local LRU for SLH-DSA batch-root verification.
 *
 * Now that the hot path runs the Merkle/SLH-DSA leg on every request (no more
 * MAC fast-accept bypass), the SLH-DSA root signature check dominates cost
 * per-QR (~3–5 ms on commodity hardware, vs ~50 µs for Merkle path
 * verification). A `SignedBatch` row is immutable once written — its
 * merkleRoot, rootSignature and associated public key never change — so a
 * single successful verification is valid for the batch's lifetime.
 *
 * Cache shape: in-process Map with insertion-order eviction when the bound
 * is exceeded. Values carry an absolute expiry; entries past expiry are
 * treated as missing and lazily evicted on read. Only successful
 * verifications are cached — a failing batch is a forensic event and we
 * want every call to log it until an operator fixes it.
 *
 * Bounds (per AUDIT1.md Finding-001 scoping block): 10_000 entries, 1 h TTL.
 * At 10k entries the Map itself is ~1 MB resident, which is fine.
 */
const BATCH_ROOT_CACHE_MAX_ENTRIES = 10_000;
const BATCH_ROOT_CACHE_TTL_MS = 3600 * 1000;

class BatchRootVerifyCache {
  private readonly entries = new Map<string, number>(); // batchId → expiresAtMs

  get(batchId: string): boolean {
    const expiresAt = this.entries.get(batchId);
    if (expiresAt === undefined) return false;
    if (expiresAt <= Date.now()) {
      this.entries.delete(batchId);
      return false;
    }
    // Touch for LRU: re-insert to the tail of insertion order.
    this.entries.delete(batchId);
    this.entries.set(batchId, expiresAt);
    return true;
  }

  set(batchId: string): void {
    const expiresAt = Date.now() + BATCH_ROOT_CACHE_TTL_MS;
    if (this.entries.has(batchId)) {
      this.entries.delete(batchId);
    } else if (this.entries.size >= BATCH_ROOT_CACHE_MAX_ENTRIES) {
      // Evict oldest insertion.
      const oldest = this.entries.keys().next().value;
      if (oldest !== undefined) this.entries.delete(oldest);
    }
    this.entries.set(batchId, expiresAt);
  }

  clear(): void {
    this.entries.clear();
  }

  size(): number {
    return this.entries.size;
  }
}

const batchRootCache = new BatchRootVerifyCache();

/** Test-only: reset batch-root cache state between runs. */
export function __resetBatchRootCache(): void {
  batchRootCache.clear();
}

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
  /** Content type stored on the QR row (`"url"`, `"vcard"`, …). */
  contentType: string;
  /** Destination URL — signed for URL QRs via computeDestHash. */
  destinationUrl: string;
  /** Hex content hash for non-URL QRs; empty string for URL QRs. */
  contentHashHex: string;
  /** ISO 8601 string, `''` for non-expiring. */
  expiresAt: string;
  /** Geo components for hash-native canonical form. */
  lat: number | null;
  lng: number | null;
  radiusM: number | null;
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

    // 1. ECDSA leg — signs the unified canonical core (AUDIT-FINDING-011).
    //    Input bytes are identical to the Merkle leg's pre-nonce form, so a
    //    drift bug in either leg surfaces immediately.
    const ecdsaAlgVersion = ALG_VERSION_POLICY.hybrid;
    const destHash = await computeDestHash(
      input.contentType,
      input.destinationUrl,
      input.contentHashHex,
    );
    const geoHash = await canonicalGeoHash(input.lat, input.lng, input.radiusM);
    const coreCanonical = canonicalizeCore({
      algVersion: ecdsaAlgVersion,
      token: input.token,
      tenantId: input.organizationId,
      destHash,
      geoHash,
      expiresAt: input.expiresAt,
    });
    const ecdsaSignature = await this.signingService.signCanonical(
      input.signingKeyId,
      coreCanonical,
    );

    // 2. Merkle/SLH-DSA leg via the batcher. The canonical payload input
    //    carries algVersion + content-type metadata; the batcher/leaf-hash
    //    helper reconstructs the same core string and appends the nonce.
    const merklePayload: QRPayloadInput = {
      algVersion: ecdsaAlgVersion,
      token: input.token,
      tenantId: input.organizationId,
      contentType: input.contentType,
      destinationUrl: input.destinationUrl,
      contentHashHex: input.contentHashHex,
      lat: input.lat,
      lng: input.lng,
      radiusM: input.radiusM,
      expiresAt: input.expiresAt,
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

    const ecdsaAlgVersion = ALG_VERSION_POLICY.hybrid;
    const destHash = await computeDestHash(
      input.contentType,
      input.destinationUrl,
      input.contentHashHex,
    );
    const geoHash = await canonicalGeoHash(input.lat, input.lng, input.radiusM);
    const coreCanonical = canonicalizeCore({
      algVersion: ecdsaAlgVersion,
      token: input.token,
      tenantId: input.organizationId,
      destHash,
      geoHash,
      expiresAt: input.expiresAt,
    });
    const ecdsaSignature = await this.signingService.signCanonical(
      input.signingKeyId,
      coreCanonical,
    );

    const merklePayload: QRPayloadInput = {
      algVersion: ecdsaAlgVersion,
      token: input.token,
      tenantId: input.organizationId,
      contentType: input.contentType,
      destinationUrl: input.destinationUrl,
      contentHashHex: input.contentHashHex,
      lat: input.lat,
      lng: input.lng,
      radiusM: input.radiusM,
      expiresAt: input.expiresAt,
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

    // Batch-root verification is the dominant cost on the hot path. A
    // SignedBatch is immutable once written, so a prior success is a valid
    // proof for the batch's lifetime — cache it in-process for 1h. Misses
    // fall through to a full SLH-DSA verify; failures are never cached.
    //
    // AUDIT-FINDING-010: the signer service prepends `qrauth:merkle-root:v1:`
    // to the message before signing. The verifier reconstructs the same
    // prefixed input so a caller that strips the prefix on its side
    // produces a verification failure.
    let slhdsaOk = batchRootCache.get(args.batchId);
    if (!slhdsaOk) {
      const prefixedRoot = Buffer.concat([
        Buffer.from('qrauth:merkle-root:v1:', 'utf8'),
        Buffer.from(batch.merkleRoot, 'hex'),
      ]);
      slhdsaOk = await slhDsaVerify(
        Buffer.from(batch.signingKey.slhdsaPublicKey, 'base64'),
        prefixedRoot,
        Buffer.from(batch.rootSignature, 'base64'),
      );
      if (slhdsaOk) batchRootCache.set(args.batchId);
    }
    if (!slhdsaOk) return { ok: false, reason: 'BATCH_SIGNATURE_INVALID' };

    return { ok: true, batch };
  }
}

export { ALGORITHM_VERSION_HYBRID, ALGORITHM_VERSION_PQC };
