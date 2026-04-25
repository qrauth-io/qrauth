/**
 * Pending-reconciler helper (AUDIT-2 N-1, post-discovery amendment).
 *
 * Context. QR codes issued via the async-merkle path transit the
 * `ecdsa-pending-slhdsa-v1` state while `BatchSigner` collects them
 * into a Merkle batch and signs the root. Happy-path promotion is
 * handled by the route's `pendingMerkle.then()` inline handler
 * (`routes/qrcodes.ts`). If the process crashes between enqueue and
 * flush, or the SLH-DSA sign fails, the row is stuck in pending.
 * `createReconcileWorker` in `workers/index.ts` is the rescue path:
 * every 60 s it finds rows older than 5 min still in pending and
 * re-enqueues them through the same `BatchSigner` the live path
 * uses, re-trying them on each subsequent tick.
 *
 * What this module adds. The rescue path has no hard timeout — a
 * row that permanently fails rescue (bad signing key, SLH-DSA stub
 * throwing, etc.) would loop forever. N-1's revoke branch is the
 * terminal state: any pending row older than 1 hour is assumed
 * orphaned beyond rescue, revoked with a structured reason, and
 * surfaced to the issuing organization via an app-level
 * `qrcode.revoked` webhook so they know to re-issue. This module
 * exports the helper `revokeOrphanedPending` that implements that
 * terminal step. It is called from the existing rescue worker AFTER
 * the rescue loop on every tick, so a single tick first tries to
 * rescue eligible rows and then revokes any that have reached the
 * 1-hour mark. There is no race between rescue and revoke because
 * the thresholds are strictly ordered (5 min rescue, 1 h revoke).
 *
 * The helper is a pure function: dependencies are injected, the
 * clock is overridable (so unit tests can exercise the age-based
 * branching without sleeping), and the revoke thresholds are
 * parameterised with production-correct defaults. All the observable
 * side effects (DB mutation, webhook emission, counter log line)
 * are reachable from a single call in a unit test.
 */
import type { PrismaClient } from '@prisma/client';
import { ALGORITHM_VERSION_PENDING } from './hybrid-signing.js';
import type { WebhookService } from './webhook.js';

// ---------------------------------------------------------------------------
// Constants — pinned by the N-1 amendment
// ---------------------------------------------------------------------------

/**
 * Structured reason recorded on `QRCode.revocationReason` when the
 * reconciler revokes an orphaned pending row. Integrators match on
 * this exact string to distinguish automatic revokes from
 * user-driven revokes (which leave the column null).
 */
export const ORPHANED_PENDING_REVOCATION_REASON = 'ORPHANED_PENDING_MERKLE' as const;

/**
 * Default age threshold for the revoke branch. Rows in the pending
 * state with `createdAt` older than `now - 1 hour` are treated as
 * orphaned. This is deliberately an order of magnitude longer than
 * the existing rescue path's 5-minute window so there is no race
 * between rescue and revoke on the same row.
 */
export const ORPHANED_PENDING_THRESHOLD_MS = 60 * 60 * 1000;

/** App-level webhook event name. Not the M-13 security webhook. */
export const ORPHANED_PENDING_WEBHOOK_EVENT = 'qrcode.revoked' as const;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PendingReconcilerDeps {
  prisma: PrismaClient;
  webhookService: WebhookService;
  /** Structured log sink. Defaults to `console` when omitted. */
  logger?: {
    info: (...args: unknown[]) => void;
    warn: (...args: unknown[]) => void;
  };
}

export interface RevokeOrphanedOptions {
  /**
   * Rows whose `createdAt` is older than `nowMs - thresholdMs` are
   * revoked. Default: 1 hour. The E2E and unit tests override this
   * to exercise the revoke branch without sleeping.
   */
  thresholdMs?: number;
  /** Clock override. Default: `Date.now()`. */
  nowMs?: number;
  /** Max rows processed per invocation. Default: 100. */
  batchLimit?: number;
}

export interface RevokeOrphanedResult {
  /** Rows observed by the SELECT as eligible (status ACTIVE + pending + aged). */
  scanned: number;
  /** Rows whose CAS-style UPDATE landed. */
  revoked: number;
  /** Webhooks successfully enqueued (matches `revoked` on the happy path). */
  webhooksEmitted: number;
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/**
 * Revoke every pending QR row older than the revoke threshold.
 *
 * Behaviour per row:
 *   1. SELECT: find rows with `algVersion = pending`, `status =
 *      ACTIVE`, and `createdAt < cutoff`. Only ACTIVE rows are
 *      candidates — already-revoked rows must not be double-revoked.
 *   2. CAS UPDATE: update only if status is STILL ACTIVE and
 *      algVersion is STILL pending. This guards against a concurrent
 *      admin revoke, a late rescue-path promotion, or another
 *      reconciler tick from stepping on our toes.
 *   3. Webhook emit: app-level `qrcode.revoked` via the caller-supplied
 *      `webhookService`. Emission failure is logged but never aborts
 *      the loop — the DB revoke is the authoritative state; the
 *      webhook is operator notification and can be retried by the
 *      normal webhook-delivery machinery.
 *   4. Counter log line: a distinctive `[pending-reconciler] pqc_orphaned`
 *      prefix lets operator log pipelines alert on sustained revoke
 *      activity without requiring a metrics framework.
 */
export async function revokeOrphanedPending(
  deps: PendingReconcilerDeps,
  opts: RevokeOrphanedOptions = {},
): Promise<RevokeOrphanedResult> {
  const nowMs = opts.nowMs ?? Date.now();
  const thresholdMs = opts.thresholdMs ?? ORPHANED_PENDING_THRESHOLD_MS;
  const batchLimit = opts.batchLimit ?? 100;
  const cutoff = new Date(nowMs - thresholdMs);
  const logger = deps.logger ?? console;

  const candidates = await deps.prisma.qRCode.findMany({
    where: {
      algVersion: ALGORITHM_VERSION_PENDING,
      status: 'ACTIVE',
      createdAt: { lt: cutoff },
    },
    select: {
      id: true,
      token: true,
      organizationId: true,
      createdAt: true,
    },
    take: batchLimit,
  });

  let revoked = 0;
  let webhooksEmitted = 0;

  for (const row of candidates) {
    // CAS: only revoke if still ACTIVE + still pending. Another
    // reconciler tick, an admin action, or a late rescue-path
    // promotion could have moved the row between SELECT and now.
    const { count } = await deps.prisma.qRCode.updateMany({
      where: {
        id: row.id,
        status: 'ACTIVE',
        algVersion: ALGORITHM_VERSION_PENDING,
      },
      data: {
        status: 'REVOKED',
        revokedAt: new Date(nowMs),
        revocationReason: ORPHANED_PENDING_REVOCATION_REASON,
      },
    });
    if (count === 0) {
      // Lost the CAS race. Skip — whoever moved the row owns the
      // terminal state now.
      continue;
    }
    revoked++;

    // App-level webhook. Fire-and-forget enqueue; the webhook-delivery
    // worker handles retries and persistence. An emission failure
    // (Redis down, no app configured) must not abort the revoke.
    try {
      await deps.webhookService.emit(row.organizationId, {
        event: ORPHANED_PENDING_WEBHOOK_EVENT,
        data: {
          qrCodeId: row.id,
          token: row.token,
          organizationId: row.organizationId,
          revocationReason: ORPHANED_PENDING_REVOCATION_REASON,
          revokedAt: new Date(nowMs).toISOString(),
          reason:
            'QR code expired in ecdsa-pending-slhdsa-v1 state without successful merkle batch completion; re-issue required.',
          originalCreatedAt: row.createdAt.toISOString(),
          thresholdMs,
        },
      });
      webhooksEmitted++;
    } catch (err) {
      logger.warn(
        `[pending-reconciler] qrcode.revoked webhook emit failed for qr=${row.id} org=${row.organizationId}:`,
        err instanceof Error ? err.message : err,
      );
    }

    // AUDIT-2 N-1 counter. Structured log line — no metrics framework
    // in place yet, so this is the observability surface. Prefix lets
    // operator log pipelines alert on sustained revoke activity.
    logger.info(
      `[pending-reconciler] pqc_orphaned qr=${row.id} org=${row.organizationId} reason=${ORPHANED_PENDING_REVOCATION_REASON} ageMs=${nowMs - row.createdAt.getTime()}`,
    );
  }

  return { scanned: candidates.length, revoked, webhooksEmitted };
}
