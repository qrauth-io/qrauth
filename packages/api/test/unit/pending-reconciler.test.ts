/**
 * Unit tests for the N-1 pending-reconciler revoke branch.
 *
 * The helper `revokeOrphanedPending` is a pure function: it takes
 * `{prisma, webhookService, logger}` as dependencies and a
 * `{thresholdMs, nowMs, batchLimit}` options bag, then does its
 * work and returns a summary. These tests substitute in a tiny
 * in-memory Prisma stub and a spy webhook service so the three
 * acceptance-criterion branches of the revoke path can be
 * exercised without touching a real database or the BullMQ
 * worker.
 *
 * Cases covered:
 *   1. 59-min-old pending row — reconciler leaves it alone. The
 *      existing rescue path handles rows in that age range; the
 *      revoke branch must not fire early.
 *   2. 61-min-old pending row — revoker writes REVOKED +
 *      'ORPHANED_PENDING_MERKLE', emits the app-level
 *      `qrcode.revoked` webhook, and emits the pqc_orphaned
 *      counter log line.
 *   3. Already-revoked row — even if its createdAt is old, the
 *      CAS guard refuses to touch it. No double-revoke, no
 *      duplicate webhook.
 *   4. Multiple rows in one call — partitioned correctly by age.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  revokeOrphanedPending,
  ORPHANED_PENDING_REVOCATION_REASON,
  ORPHANED_PENDING_THRESHOLD_MS,
  ORPHANED_PENDING_WEBHOOK_EVENT,
} from '../../src/services/pending-reconciler.js';
import { ALGORITHM_VERSION_PENDING } from '../../src/services/hybrid-signing.js';

// ---------------------------------------------------------------------------
// In-memory Prisma stub
// ---------------------------------------------------------------------------

interface FakeQRCode {
  id: string;
  token: string;
  organizationId: string;
  createdAt: Date;
  status: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
  algVersion: string;
  revokedAt: Date | null;
  revocationReason: string | null;
}

interface FakePrismaFilter {
  where: {
    algVersion?: string;
    status?: 'ACTIVE' | 'REVOKED' | 'EXPIRED';
    createdAt?: { lt: Date };
    id?: string;
  };
}

class FakePrisma {
  rows = new Map<string, FakeQRCode>();

  qRCode = {
    findMany: async (args: FakePrismaFilter & { take?: number; select?: unknown }) => {
      const all = [...this.rows.values()].filter((r) => {
        if (args.where.algVersion && r.algVersion !== args.where.algVersion) return false;
        if (args.where.status && r.status !== args.where.status) return false;
        if (args.where.createdAt && !(r.createdAt < args.where.createdAt.lt)) return false;
        return true;
      });
      const out = args.take != null ? all.slice(0, args.take) : all;
      // Match the real Prisma `select` shape that revokeOrphanedPending
      // uses: id, token, organizationId, createdAt.
      return out.map((r) => ({
        id: r.id,
        token: r.token,
        organizationId: r.organizationId,
        createdAt: r.createdAt,
      }));
    },
    updateMany: async (args: FakePrismaFilter & { data: Partial<FakeQRCode> }) => {
      let count = 0;
      for (const r of this.rows.values()) {
        if (args.where.id && r.id !== args.where.id) continue;
        if (args.where.algVersion && r.algVersion !== args.where.algVersion) continue;
        if (args.where.status && r.status !== args.where.status) continue;
        Object.assign(r, args.data);
        count++;
      }
      return { count };
    },
  };
}

// ---------------------------------------------------------------------------
// Spy webhook service
// ---------------------------------------------------------------------------

interface WebhookCall {
  organizationId: string;
  event: string;
  data: Record<string, unknown>;
}

class SpyWebhookService {
  calls: WebhookCall[] = [];
  // Match WebhookService.emit shape.
  emit = vi.fn(async (organizationId: string, event: { event: string; data: Record<string, unknown> }) => {
    this.calls.push({ organizationId, event: event.event, data: event.data });
  });
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const NOW = new Date('2026-04-15T12:00:00.000Z').getTime();

function makePending(id: string, ageMs: number): FakeQRCode {
  return {
    id,
    token: `tok_${id}`,
    organizationId: `org_${id}`,
    createdAt: new Date(NOW - ageMs),
    status: 'ACTIVE',
    algVersion: ALGORITHM_VERSION_PENDING,
    revokedAt: null,
    revocationReason: null,
  };
}

function makeSilentLogger() {
  return { info: vi.fn(), warn: vi.fn() };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('revokeOrphanedPending (AUDIT-2 N-1)', () => {
  let prisma: FakePrisma;
  let webhookService: SpyWebhookService;
  let logger: ReturnType<typeof makeSilentLogger>;

  beforeEach(() => {
    prisma = new FakePrisma();
    webhookService = new SpyWebhookService();
    logger = makeSilentLogger();
  });

  function deps() {
    // Cast to never because the fake Prisma only implements the two
    // methods the helper touches — TS would otherwise reject the
    // partial PrismaClient shape.
    return {
      prisma: prisma as never,
      webhookService: webhookService as never,
      logger,
    };
  }

  it('leaves a 59-minute-old pending row alone', async () => {
    prisma.rows.set('young', makePending('young', 59 * 60 * 1000));

    const result = await revokeOrphanedPending(deps(), { nowMs: NOW });

    expect(result.scanned).toBe(0);
    expect(result.revoked).toBe(0);
    expect(result.webhooksEmitted).toBe(0);

    const row = prisma.rows.get('young')!;
    expect(row.status).toBe('ACTIVE');
    expect(row.revocationReason).toBeNull();
    expect(webhookService.calls).toHaveLength(0);
    expect(logger.info).not.toHaveBeenCalled();
  });

  it('revokes a 61-minute-old pending row, writes the reason, emits the webhook, and logs the counter', async () => {
    prisma.rows.set('old', makePending('old', 61 * 60 * 1000));

    const result = await revokeOrphanedPending(deps(), { nowMs: NOW });

    expect(result.scanned).toBe(1);
    expect(result.revoked).toBe(1);
    expect(result.webhooksEmitted).toBe(1);

    const row = prisma.rows.get('old')!;
    expect(row.status).toBe('REVOKED');
    expect(row.revocationReason).toBe(ORPHANED_PENDING_REVOCATION_REASON);
    expect(row.revokedAt).not.toBeNull();

    // App-level webhook emission — NOT the M-13 security webhook.
    expect(webhookService.calls).toHaveLength(1);
    const [call] = webhookService.calls;
    expect(call.organizationId).toBe('org_old');
    expect(call.event).toBe(ORPHANED_PENDING_WEBHOOK_EVENT);
    expect(call.data.qrCodeId).toBe('old');
    expect(call.data.token).toBe('tok_old');
    expect(call.data.revocationReason).toBe(ORPHANED_PENDING_REVOCATION_REASON);
    expect(typeof call.data.reason).toBe('string');
    expect(call.data.reason).toContain('merkle batch');

    // pqc_orphaned counter log line.
    expect(logger.info).toHaveBeenCalledTimes(1);
    const logLine = (logger.info as unknown as { mock: { calls: unknown[][] } }).mock.calls[0][0] as string;
    expect(logLine).toContain('pqc_orphaned');
    expect(logLine).toContain('qr=old');
    expect(logLine).toContain(`reason=${ORPHANED_PENDING_REVOCATION_REASON}`);
  });

  it('leaves an already-revoked row alone (no double-revoke, no duplicate webhook)', async () => {
    // Row is ancient enough by createdAt but has already been marked
    // REVOKED by some other path (user action, admin). The CAS UPDATE
    // must refuse to touch it.
    const preRevoked: FakeQRCode = {
      ...makePending('prev', 99 * 60 * 1000),
      status: 'REVOKED',
      revokedAt: new Date(NOW - 10 * 60 * 1000),
      revocationReason: null, // user-driven revoke — no reason set
    };
    prisma.rows.set('prev', preRevoked);

    const result = await revokeOrphanedPending(deps(), { nowMs: NOW });

    // Pre-revoked rows are filtered out at SELECT time (the helper
    // queries `status: 'ACTIVE'`), so nothing is scanned.
    expect(result.scanned).toBe(0);
    expect(result.revoked).toBe(0);
    expect(result.webhooksEmitted).toBe(0);

    const row = prisma.rows.get('prev')!;
    expect(row.status).toBe('REVOKED');
    // The helper must NOT have rewritten the reason — the user-driven
    // revoke's null stays intact.
    expect(row.revocationReason).toBeNull();
    expect(webhookService.calls).toHaveLength(0);
    expect(logger.info).not.toHaveBeenCalled();
  });

  it('partitions a mixed batch by age — only rows past the threshold get revoked', async () => {
    prisma.rows.set('young', makePending('young', 10 * 60 * 1000));
    prisma.rows.set('middle', makePending('middle', 59 * 60 * 1000));
    prisma.rows.set('old1', makePending('old1', 61 * 60 * 1000));
    prisma.rows.set('old2', makePending('old2', 2 * 60 * 60 * 1000));
    prisma.rows.set('non-pending', {
      ...makePending('np', 99 * 60 * 1000),
      algVersion: 'hybrid-ecdsa-slhdsa-v1', // not pending — must not match
    });

    const result = await revokeOrphanedPending(deps(), { nowMs: NOW });

    expect(result.scanned).toBe(2);
    expect(result.revoked).toBe(2);
    expect(result.webhooksEmitted).toBe(2);

    expect(prisma.rows.get('young')!.status).toBe('ACTIVE');
    expect(prisma.rows.get('middle')!.status).toBe('ACTIVE');
    expect(prisma.rows.get('old1')!.status).toBe('REVOKED');
    expect(prisma.rows.get('old2')!.status).toBe('REVOKED');
    expect(prisma.rows.get('non-pending')!.status).toBe('ACTIVE');

    expect(webhookService.calls.map((c) => c.data.qrCodeId).sort()).toEqual(['old1', 'old2']);
  });

  it('respects the default 1-hour production threshold when no override is passed', async () => {
    // Default thresholdMs should be exactly 1 hour.
    expect(ORPHANED_PENDING_THRESHOLD_MS).toBe(60 * 60 * 1000);

    prisma.rows.set('just-under', makePending('just-under', 59 * 60 * 1000 + 59_000));
    prisma.rows.set('just-over', makePending('just-over', 60 * 60 * 1000 + 1_000));

    const result = await revokeOrphanedPending(deps(), { nowMs: NOW });

    expect(result.revoked).toBe(1);
    expect(prisma.rows.get('just-under')!.status).toBe('ACTIVE');
    expect(prisma.rows.get('just-over')!.status).toBe('REVOKED');
  });

  it('keeps the DB revoke even when webhook emission fails', async () => {
    prisma.rows.set('old', makePending('old', 61 * 60 * 1000));
    webhookService.emit.mockImplementationOnce(async () => {
      throw new Error('redis down');
    });

    const result = await revokeOrphanedPending(deps(), { nowMs: NOW });

    expect(result.revoked).toBe(1);
    expect(result.webhooksEmitted).toBe(0);
    expect(prisma.rows.get('old')!.status).toBe('REVOKED');
    expect(prisma.rows.get('old')!.revocationReason).toBe(ORPHANED_PENDING_REVOCATION_REASON);

    expect(logger.warn).toHaveBeenCalledTimes(1);
    const warnLine = (logger.warn as unknown as { mock: { calls: unknown[][] } }).mock.calls[0][0] as string;
    expect(warnLine).toContain('qrcode.revoked webhook emit failed');
    // Counter log line still fires — the DB revoke is authoritative.
    expect(logger.info).toHaveBeenCalledTimes(1);
  });
});
