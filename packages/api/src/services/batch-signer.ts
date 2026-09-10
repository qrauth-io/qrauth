import type { PrismaClient } from '@prisma/client';
import {
  ALGORITHM_VERSION_HYBRID,
  issueBatchWithSigner,
  type MerkleNode,
  type QRPayloadInput,
} from './merkle-signing.js';
import type { SlhDsaSigner } from './slhdsa-signer/index.js';

/**
 * In-process Merkle batch signer (ALGORITHM.md §6.2).
 *
 * The hybrid signing pipeline used to issue a fresh single-leaf Merkle batch
 * for every QR — one SLH-DSA sign per QR, ~2.3 seconds wall-clock each. That
 * works for low volume but doesn't scale: a 100-QR bulk import would block
 * for over three minutes.
 *
 * BatchSigner amortizes the SLH-DSA cost by accumulating pending leaves and
 * signing one Merkle root per flush. Each enqueue() returns a promise that
 * resolves when the batch the leaf landed in completes — the caller waits
 * exactly the time it takes to fill the batch (or hit the time bound),
 * plus one SLH-DSA sign for the whole group.
 *
 * Flush triggers (whichever fires first):
 *   - `maxBatchSize` items have queued for a given signing key
 *   - `maxWaitMs` has elapsed since the first item joined the queue
 *   - The process is shutting down — `flushAll()` runs in the onClose hook
 *
 * Per-key queues: the queue is keyed by `signingKeyDbId`. Two orgs cannot
 * land in the same batch because each org has its own signing key, and the
 * SLH-DSA root signature is bound to a single key. This also guarantees
 * `items[0].organizationId` is the org for the entire batch.
 *
 * Failure mode: if the SLH-DSA sign or the SignedBatch insert throws, the
 * batcher rejects every queued promise with the same error. The caller is
 * expected to surface this as a 5xx and let the client retry — there is no
 * automatic retry inside the batcher (a stuck queue would block all other
 * QRs for the same org).
 *
 * NOT durable across restarts. A SIGKILL with items in-flight loses them.
 * The graceful shutdown path (`onClose` → `flushAll`) handles SIGTERM
 * cleanly. For higher durability requirements, swap this for a BullMQ-backed
 * batcher in Phase 3.
 */

export interface BatchSignerOptions {
  /** Hard ceiling on items per Merkle tree. SLH-DSA sign cost is roughly
   *  flat in batch size, so larger batches are strictly better for
   *  throughput — bounded only by RAM and the latency budget. */
  maxBatchSize: number;
  /** Maximum time the first item in a queue waits before forcing a flush.
   *  Sets the upper bound on per-QR latency for low-traffic orgs. */
  maxWaitMs: number;
}

export interface BatchSignResult {
  algVersion: typeof ALGORITHM_VERSION_HYBRID;
  batchId: string;
  merkleRoot: string;
  rootSignature: string;
  leafIndex: number;
  leafHash: string;
  leafNonce: string;
  merklePath: MerkleNode[];
}

interface PendingItem {
  organizationId: string;
  signingKeyDbId: string;
  payload: QRPayloadInput;
  resolve: (out: BatchSignResult) => void;
  reject: (err: Error) => void;
}

interface PerKeyQueue {
  signingKeyId: string;
  items: PendingItem[];
  timer: NodeJS.Timeout | null;
  /** Promise of the in-flight flush, if any. Subsequent enqueues during the
   *  flush land in a fresh items[] and wait for the next flush. */
  inFlight: Promise<void> | null;
}

const DEFAULT_OPTIONS: BatchSignerOptions = {
  maxBatchSize: 64,
  maxWaitMs: 200,
};

export class BatchSigner {
  private queues = new Map<string, PerKeyQueue>();
  private opts: BatchSignerOptions;
  private closed = false;

  constructor(
    private prisma: PrismaClient,
    private signer: SlhDsaSigner,
    opts: Partial<BatchSignerOptions> = {},
  ) {
    this.opts = { ...DEFAULT_OPTIONS, ...opts };
  }

  /**
   * Enqueue a single QR payload for hybrid Merkle signing. The returned
   * promise resolves with the per-leaf material (inclusion proof + the
   * shared batch metadata) once the leaf's batch has been signed and
   * persisted.
   */
  enqueue(args: {
    organizationId: string;
    signingKeyDbId: string;
    signingKeyId: string;
    payload: QRPayloadInput;
  }): Promise<BatchSignResult> {
    if (this.closed) {
      return Promise.reject(new Error('BatchSigner: closed'));
    }

    return new Promise<BatchSignResult>((resolve, reject) => {
      const queueKey = args.signingKeyDbId;
      let q = this.queues.get(queueKey);
      if (!q) {
        q = { signingKeyId: args.signingKeyId, items: [], timer: null, inFlight: null };
        this.queues.set(queueKey, q);
      }

      q.items.push({
        organizationId: args.organizationId,
        signingKeyDbId: args.signingKeyDbId,
        payload: args.payload,
        resolve,
        reject,
      });

      // Size trigger fires immediately, time trigger arms on first item.
      if (q.items.length >= this.opts.maxBatchSize) {
        if (q.timer) {
          clearTimeout(q.timer);
          q.timer = null;
        }
        // Don't await — let the caller's promise pick up the result.
        void this.flushQueue(queueKey);
      } else if (!q.timer) {
        q.timer = setTimeout(() => {
          q!.timer = null;
          void this.flushQueue(queueKey);
        }, this.opts.maxWaitMs);
      }
    });
  }

  /**
   * Flush every per-key queue, awaiting all in-flight signs. Called from
   * the fastify onClose hook so SIGTERM drains pending work instead of
   * hanging client requests forever.
   */
  async flushAll(): Promise<void> {
    this.closed = true;
    const flushes: Promise<void>[] = [];
    for (const queueKey of this.queues.keys()) {
      flushes.push(this.flushQueue(queueKey));
    }
    await Promise.all(flushes);
  }

  /**
   * Drain a single per-key queue. Safe to call concurrently — if a flush is
   * already in flight for this key, we wait for it instead of starting a
   * second one (otherwise two batches would race on the same SignedBatch
   * insert and item ordering).
   */
  private async flushQueue(queueKey: string): Promise<void> {
    const q = this.queues.get(queueKey);
    if (!q) return;

    if (q.inFlight) {
      // Another caller is already flushing this queue. Wait for it, then
      // check whether new items have arrived since (the size-trigger path
      // can stack multiple flush calls).
      await q.inFlight;
      if (q.items.length === 0) return;
    }

    if (q.items.length === 0) return;

    // Snapshot the pending items and clear the queue + timer.
    const items = q.items.splice(0, q.items.length);
    if (q.timer) {
      clearTimeout(q.timer);
      q.timer = null;
    }

    const flush = this.runFlush(q.signingKeyId, items);
    q.inFlight = flush.finally(() => {
      // Clear the in-flight pointer when we're done so the next enqueue
      // can arm a fresh timer.
      if (q.inFlight === flush) q.inFlight = null;
    });
    await q.inFlight;
  }

  private async runFlush(signingKeyId: string, items: PendingItem[]): Promise<void> {
    try {
      // Delegate the actual SLH-DSA signing to the configured signer.
      // In production this reaches out over HTTP to the standalone
      // signer service and the API server never holds private bytes
      // (ALGORITHM.md §13.1). In dev / tests it's a LocalSlhDsaSigner
      // that loads from disk in-process.
      const payloads = items.map((i) => i.payload);
      const batch = await issueBatchWithSigner(payloads, this.signer, signingKeyId);

      // Single SignedBatch row per flush. All items in a batch share the
      // same org because the queue is keyed by signingKeyDbId and each org
      // has its own signing key — no cross-tenant leakage possible.
      const orgId = items[0].organizationId;
      const signingKeyDbId = items[0].signingKeyDbId;

      await this.prisma.signedBatch.create({
        data: {
          batchId: batch.batchId,
          organizationId: orgId,
          signingKeyId: signingKeyDbId,
          algVersion: ALGORITHM_VERSION_HYBRID,
          merkleRoot: batch.merkleRoot,
          rootSignature: batch.rootSignature,
          tokenCount: batch.tokenCount,
          issuedAt: new Date(batch.issuedAt),
        },
      });

      for (let i = 0; i < items.length; i++) {
        const tok = batch.tokens[i];
        items[i].resolve({
          algVersion: ALGORITHM_VERSION_HYBRID,
          batchId: batch.batchId,
          merkleRoot: batch.merkleRoot,
          rootSignature: batch.rootSignature,
          leafIndex: tok.leafIndex,
          leafHash: tok.leafHash,
          leafNonce: tok.nonce,
          merklePath: tok.merklePath,
        });
      }
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      for (const item of items) item.reject(error);
    }
  }
}
