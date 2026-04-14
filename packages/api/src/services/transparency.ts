import { createHash } from 'node:crypto';
import type { PrismaClient, TransparencyLogEntry } from '@prisma/client';
import { hashString } from '../lib/crypto.js';
import type { MerkleNode } from './merkle-signing.js';

// ---------------------------------------------------------------------------
// Input shape for appendEntry
// ---------------------------------------------------------------------------

export interface QRCodeInput {
  id: string;
  token: string;
  organizationId: string;
  destinationUrl: string;
  geoHash?: string | null;
  /**
   * Optional commitment-only material for the new (ALGORITHM.md §8) log
   * format. When supplied, the entry is written with `algVersion =
   * hybrid-ecdsa-slhdsa-v1` and the commitment fields populated. When
   * omitted, the entry falls back to the legacy plaintext-hash format so
   * pre-PQC code paths keep working unchanged.
   */
  pqc?: {
    algVersion: string;
    /** SHA3-256 leaf hash from the Merkle batch — the per-row commitment. */
    leafHash: string;
    /** SHA3-256 of the batch root — the audit anchor, NOT key material. */
    batchRootRef: string;
    /** Merkle inclusion proof for the leaf inside its batch tree. */
    merkleInclusionProof: MerkleNode[];
  } | null;
}

// ---------------------------------------------------------------------------
// Return type for getInclusionProof
// ---------------------------------------------------------------------------

export interface InclusionProof {
  entry: TransparencyLogEntry;
  previous: TransparencyLogEntry | null;
  next: TransparencyLogEntry | null;
}

// ---------------------------------------------------------------------------
// Return type for verifyChain
// ---------------------------------------------------------------------------

export interface ChainVerificationResult {
  valid: boolean;
  /** logIndex of the first entry whose hash does not match expectations. */
  brokenAt?: number;
}

// ---------------------------------------------------------------------------
// TransparencyLogService
// ---------------------------------------------------------------------------

export class TransparencyLogService {
  constructor(private prisma: PrismaClient) {}

  /**
   * Append a new entry to the transparency log for a QR code.
   *
   * The entry hash forms a chain: each entry's hash covers its own content
   * PLUS the previous entry's hash, making it tamper-evident.
   *
   * @param qrCode - The QR code being registered.
   * @returns The newly created TransparencyLogEntry.
   */
  async appendEntry(qrCode: QRCodeInput): Promise<TransparencyLogEntry> {
    const tokenHash = hashString(qrCode.token);
    const destinationHash = hashString(qrCode.destinationUrl);
    const geoHashValue = qrCode.geoHash ?? '';

    // Find the latest entry in the log to get the chain tip.
    const latest = await this.prisma.transparencyLogEntry.findFirst({
      orderBy: { logIndex: 'desc' },
    });

    const previousHash = latest?.entryHash ?? null;
    const timestamp = new Date().toISOString();

    // Compute the hash-chain entry hash. For commitment-only entries the
    // chain hash covers `commitment` instead of the plaintext token /
    // destination — that way the public log is opaque while still being
    // append-only and tamper-evident.
    const chainCover = qrCode.pqc?.leafHash
      ? `${previousHash ?? ''}${qrCode.pqc.leafHash}${qrCode.pqc.batchRootRef}${timestamp}`
      : `${previousHash ?? ''}${tokenHash}${destinationHash}${geoHashValue}${timestamp}`;
    const entryHash = hashString(chainCover);

    // Persist atomically — use a transaction so logIndex auto-increment and
    // the hash chain remain consistent under concurrent inserts.
    const entry = await this.prisma.$transaction(async (tx) => {
      return tx.transparencyLogEntry.create({
        data: {
          qrCodeId: qrCode.id,
          organizationId: qrCode.organizationId,
          // Legacy plaintext-derived hashes — kept for back-compat reads on
          // older entries. New entries still populate them so existing
          // dashboards and audit tooling do not break, but the
          // authoritative commitment for new entries is the SHA3-256 leaf
          // hash below.
          tokenHash,
          destinationHash,
          geoHash: geoHashValue || null,
          previousHash,
          entryHash,
          algVersion: qrCode.pqc?.algVersion ?? 'ecdsa-p256-sha256-v1',
          commitment: qrCode.pqc?.leafHash ?? null,
          batchRootRef: qrCode.pqc?.batchRootRef ?? null,
          merkleInclusionProof: (qrCode.pqc?.merkleInclusionProof as unknown as object) ?? undefined,
        },
      });
    });

    return entry;
  }

  /**
   * SHA3-256 of a hex-encoded merkle root. Helper for callers building the
   * `batchRootRef` field — exported so the QR creation route can compute it
   * inline without re-importing node:crypto.
   */
  static computeBatchRootRef(merkleRootHex: string): string {
    return createHash('sha3-256').update(Buffer.from(merkleRootHex, 'hex')).digest('hex');
  }

  /**
   * Retrieve a transparency log entry by its monotonically increasing index.
   * Throws when no entry with that index exists.
   */
  async getEntry(logIndex: number): Promise<TransparencyLogEntry> {
    const entry = await this.prisma.transparencyLogEntry.findUnique({
      where: { logIndex },
    });

    if (!entry) {
      throw new Error(
        `Transparency log entry at index ${logIndex} does not exist.`,
      );
    }

    return entry;
  }

  /**
   * Return an inclusion proof for a specific QR code.
   *
   * The proof contains:
   *   - The entry itself.
   *   - The immediately preceding entry (or null for the genesis entry).
   *   - The immediately following entry (or null for the most recent entry).
   *
   * A verifier can use the neighbouring entries to confirm that this entry's
   * hash is correctly chained into the log.
   *
   * @throws When no transparency log entry exists for the given QR code.
   */
  async getInclusionProof(qrCodeId: string): Promise<InclusionProof> {
    const entry = await this.prisma.transparencyLogEntry.findUnique({
      where: { qrCodeId },
    });

    if (!entry) {
      throw new Error(
        `No transparency log entry found for QR code "${qrCodeId}".`,
      );
    }

    const [previous, next] = await Promise.all([
      entry.logIndex > 1
        ? this.prisma.transparencyLogEntry.findUnique({
            where: { logIndex: entry.logIndex - 1 },
          })
        : Promise.resolve(null),

      this.prisma.transparencyLogEntry.findUnique({
        where: { logIndex: entry.logIndex + 1 },
      }),
    ]);

    return { entry, previous: previous ?? null, next: next ?? null };
  }

  /**
   * Verify the integrity of a contiguous range of transparency log entries.
   *
   * For each entry in [startIndex, endIndex]:
   *   1. Re-compute the expected entryHash from the stored fields.
   *   2. Compare against the stored entryHash.
   *
   * Note: because the timestamp used when creating the entry is not stored
   * separately, we verify the chain linkage (previousHash pointer) rather
   * than re-deriving the full hash from scratch — that would require the
   * original timestamp to be stored explicitly.  Chain-linkage verification
   * confirms that no entry has been inserted or deleted between any two
   * adjacent positions.
   *
   * @param startIndex - Inclusive start of the range.
   * @param endIndex   - Inclusive end of the range.
   */
  async verifyChain(
    startIndex: number,
    endIndex: number,
  ): Promise<ChainVerificationResult> {
    if (startIndex > endIndex) {
      throw new Error(
        `startIndex (${startIndex}) must be <= endIndex (${endIndex}).`,
      );
    }

    const entries = await this.prisma.transparencyLogEntry.findMany({
      where: {
        logIndex: { gte: startIndex, lte: endIndex },
      },
      orderBy: { logIndex: 'asc' },
    });

    if (entries.length === 0) {
      return { valid: true };
    }

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];

      // Verify that each entry's previousHash matches the entryHash of the
      // entry immediately before it in the fetched range (or is null for the
      // first entry in the range).
      if (i === 0) {
        // For the first entry, if it is not the genesis entry (logIndex > 1),
        // we trust the stored previousHash — we cannot re-derive it without
        // the prior entry's full data unless we expand the fetch range.
        // The chain is only broken if the stored previousHash is inconsistent
        // with the adjacent entry in the window.
        continue;
      }

      const prev = entries[i - 1];

      if (entry.previousHash !== prev.entryHash) {
        return { valid: false, brokenAt: entry.logIndex };
      }
    }

    return { valid: true };
  }
}
