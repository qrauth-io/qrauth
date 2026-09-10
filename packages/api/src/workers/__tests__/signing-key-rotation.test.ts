import { describe, it, expect, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FakeSigningKeyPrisma } from '../../services/__tests__/fake-signing-key-prisma.js';

/**
 * The cleanup worker's signing-key lifecycle steps
 * (docs/ops/signing-key-rotation-loop.md, defect 2): the hourly job found
 * stale key ROWS but then rotated by ORG, so the stale key was never the key
 * that got rotated. Its trigger condition never cleared and it minted one
 * ES256 key per hour, forever (~223 accumulated in production).
 *
 * The second-run assertion below is the direct test against that loop: a
 * single stale key must cause exactly ONE rotation, after which the trigger
 * condition is gone.
 */

vi.mock('../../lib/queue.js', () => ({
  webhookQueue: { add: async () => ({ id: 'job' }) },
  scanQueue: {},
  fraudQueue: {},
  alertQueue: {},
  cleanupQueue: {},
  reconcileQueue: {},
  createQueueConnection: () => {
    throw new Error('unit tests must not open Redis connections');
  },
  closeQueues: async () => {},
}));

process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'unit-test-secret-0123456789abcdef';
process.env.ECDSA_PRIVATE_KEY_PATH = mkdtempSync(join(tmpdir(), 'qrauth-worker-rotation-'));

const { SigningService } = await import('../../services/signing.js');
const rotationModule = await import('../signing-key-rotation.js');
const { rotateStaleSigningKeys } = rotationModule;

const DAY_MS = 24 * 60 * 60 * 1000;
const NOW = new Date('2026-09-07T12:00:00Z');
const daysBefore = (n: number) => new Date(NOW.getTime() - n * DAY_MS);

describe('rotateStaleSigningKeys — the hourly loop must converge', () => {
  it('with one stale and one fresh ACTIVE key, the first run produces exactly one new key and a second run produces none', async () => {
    const db = new FakeSigningKeyPrisma();
    // Production shape: stale ES256 (past the 90-day cutoff) + fresh RS256
    // (the RSA bootstrap key, newest ACTIVE row).
    const stale = db.seedKey({
      organizationId: 'org-platform',
      algorithm: 'ES256',
      createdAt: daysBefore(100),
    });
    const fresh = db.seedKey({
      organizationId: 'org-platform',
      algorithm: 'RS256',
      createdAt: daysBefore(9),
    });
    const service = new SigningService(db.asPrisma());
    const rowsBefore = db.rows.length;

    const firstRun = await rotateStaleSigningKeys(db.asPrisma(), service, NOW);

    expect(firstRun).toHaveLength(1);
    expect(db.rows.length).toBe(rowsBefore + 1);
    // The STALE key is the one that must have been rotated…
    const staleAfter = await db.signingKey.findUnique({ where: { keyId: stale.keyId } });
    expect(staleAfter?.status).toBe('ROTATED');
    // …and the fresh RS256 key must be untouched.
    const freshAfter = await db.signingKey.findUnique({ where: { keyId: fresh.keyId } });
    expect(freshAfter?.status).toBe('ACTIVE');
    // The replacement matches the algorithm of the key it replaced.
    const replacement = await db.signingKey.findUnique({ where: { keyId: firstRun[0].newKeyId } });
    expect(replacement?.algorithm).toBe('ES256');

    // THE loop assertion: the trigger condition has cleared — a second run
    // (same clock) must mint nothing.
    const secondRun = await rotateStaleSigningKeys(db.asPrisma(), service, NOW);

    expect(secondRun).toHaveLength(0);
    expect(db.rows.length).toBe(rowsBefore + 1);
  });

  it('rotates a normal single-key org once and then goes quiet', async () => {
    const db = new FakeSigningKeyPrisma();
    db.seedKey({
      organizationId: 'org-normal',
      algorithm: 'ES256',
      createdAt: daysBefore(91),
    });
    const service = new SigningService(db.asPrisma());

    const firstRun = await rotateStaleSigningKeys(db.asPrisma(), service, NOW);
    const secondRun = await rotateStaleSigningKeys(db.asPrisma(), service, NOW);

    expect(firstRun).toHaveLength(1);
    expect(secondRun).toHaveLength(0);
    expect(db.activeKeys('org-normal')).toHaveLength(1);
  });

  it('leaves fresh keys alone entirely', async () => {
    const db = new FakeSigningKeyPrisma();
    db.seedKey({
      organizationId: 'org-fresh',
      algorithm: 'ES256',
      createdAt: daysBefore(10),
    });
    const service = new SigningService(db.asPrisma());

    const rotations = await rotateStaleSigningKeys(db.asPrisma(), service, NOW);

    expect(rotations).toHaveLength(0);
    expect(db.rows).toHaveLength(1);
  });
});

describe('revokeExpiredRotatedKeys — bounded JWKS via grace-window pruning', () => {
  it('revokes ROTATED keys past the grace window, leaves recent ROTATED / ACTIVE / REVOKED rows alone', async () => {
    // Lazy import: the export is part of the fix, not the pre-fix worker.
    const { revokeExpiredRotatedKeys } = rotationModule as unknown as {
      revokeExpiredRotatedKeys: (db: unknown, now: Date) => Promise<{ count: number }>;
    };
    expect(typeof revokeExpiredRotatedKeys).toBe('function');

    const db = new FakeSigningKeyPrisma();
    const expired = db.seedKey({
      organizationId: 'org-1',
      algorithm: 'ES256',
      status: 'ROTATED',
      createdAt: daysBefore(200),
      rotatedAt: daysBefore(40),
    });
    const inGrace = db.seedKey({
      organizationId: 'org-1',
      algorithm: 'ES256',
      status: 'ROTATED',
      createdAt: daysBefore(100),
      rotatedAt: daysBefore(10),
    });
    const active = db.seedKey({ organizationId: 'org-1', algorithm: 'ES256' });
    const alreadyRevoked = db.seedKey({
      organizationId: 'org-1',
      algorithm: 'ES256',
      status: 'REVOKED',
      createdAt: daysBefore(300),
      rotatedAt: daysBefore(250),
      revokedAt: daysBefore(200),
    });

    const { count } = await revokeExpiredRotatedKeys(db.asPrisma(), NOW);

    expect(count).toBe(1);
    expect((await db.signingKey.findUnique({ where: { keyId: expired.keyId } }))?.status).toBe('REVOKED');
    expect((await db.signingKey.findUnique({ where: { keyId: expired.keyId } }))?.revokedAt).toEqual(NOW);
    expect((await db.signingKey.findUnique({ where: { keyId: inGrace.keyId } }))?.status).toBe('ROTATED');
    expect((await db.signingKey.findUnique({ where: { keyId: active.keyId } }))?.status).toBe('ACTIVE');
    expect((await db.signingKey.findUnique({ where: { keyId: alreadyRevoked.keyId } }))?.revokedAt).toEqual(
      alreadyRevoked.revokedAt,
    );
  });

  it('sweeps uniformly — no reference guard: every past-grace ROTATED key is revoked, and a second run is a no-op', async () => {
    // A qr_codes/signed_batches reference guard was proposed and REJECTED
    // before shipping (2026-09-08 design note in
    // docs/ops/signing-key-rotation-loop.md): publication is time-bounded
    // separately, every status-filtered verifier is bounded far below the
    // grace window, QR/batch verification is FK-resolved and status-blind,
    // and a guard would have pinned rows ROTATED forever — muddying the
    // retained-count drain that step 7 of the runbook watches. This test
    // pins the uniform sweep so the guard cannot quietly come back.
    const { revokeExpiredRotatedKeys } = rotationModule as unknown as {
      revokeExpiredRotatedKeys: (db: unknown, now: Date) => Promise<{ count: number }>;
    };

    const db = new FakeSigningKeyPrisma();
    const old1 = db.seedKey({
      organizationId: 'org-1',
      algorithm: 'ES256',
      status: 'ROTATED',
      createdAt: daysBefore(400),
      rotatedAt: daysBefore(365),
    });
    const old2 = db.seedKey({
      organizationId: 'org-1',
      algorithm: 'ES256',
      status: 'ROTATED',
      createdAt: daysBefore(200),
      rotatedAt: daysBefore(31),
    });

    const { count } = await revokeExpiredRotatedKeys(db.asPrisma(), NOW);

    expect(count).toBe(2);
    expect((await db.signingKey.findUnique({ where: { keyId: old1.keyId } }))?.status).toBe('REVOKED');
    expect((await db.signingKey.findUnique({ where: { keyId: old2.keyId } }))?.status).toBe('REVOKED');

    const second = await revokeExpiredRotatedKeys(db.asPrisma(), NOW);
    expect(second.count).toBe(0);
  });
});
