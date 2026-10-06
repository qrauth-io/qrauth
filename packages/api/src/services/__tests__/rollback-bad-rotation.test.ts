import { describe, it, expect } from 'vitest';
import { FakeSigningKeyPrisma } from './fake-signing-key-prisma.js';

// The script imports config at module load — set throwaways before importing.
process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'unit-test-secret-0123456789abcdef';

// Importing the script must NOT execute its CLI (main is gated on
// direct invocation) — these imports pull only the exported functions.
const { planRollback, executeRollback } = await import(
  '../../../scripts/rollback-bad-rotation.js'
);

/**
 * scripts/rollback-bad-rotation.ts — the recovery instrument for a rotation
 * whose signer push left an unusable envelope (runbook step 6b). Pinned
 * here: every refusal path, and the one-transaction swap that keeps the
 * partial unique index satisfied at every point.
 */

const NOW = new Date('2026-09-08T15:00:00Z');

function badRotationFixture() {
  const db = new FakeSigningKeyPrisma();
  const restore = db.seedKey({
    organizationId: 'org-platform',
    algorithm: 'RS256',
    status: 'ROTATED',
    createdAt: new Date('2026-06-01T11:00:00Z'),
    rotatedAt: new Date('2026-09-08T13:04:00Z'),
  });
  const bad = db.seedKey({
    organizationId: 'org-platform',
    algorithm: 'RS256',
    status: 'ACTIVE',
    createdAt: new Date('2026-09-08T13:04:00Z'),
  });
  return { db, bad, restore };
}

describe('planRollback — refusal paths', () => {
  it('refuses when bad and restore are the same key', async () => {
    const { db, bad } = badRotationFixture();
    await expect(
      planRollback(db.asPrisma(), { badKeyId: bad.keyId, restoreKeyId: bad.keyId }),
    ).rejects.toThrow(/same key/);
  });

  it('refuses when either key does not exist', async () => {
    const { db, bad, restore } = badRotationFixture();
    await expect(
      planRollback(db.asPrisma(), { badKeyId: 'nope', restoreKeyId: restore.keyId }),
    ).rejects.toThrow(/not found/);
    await expect(
      planRollback(db.asPrisma(), { badKeyId: bad.keyId, restoreKeyId: 'nope' }),
    ).rejects.toThrow(/not found/);
  });

  it('refuses a cross-organization swap', async () => {
    const { db, bad } = badRotationFixture();
    const foreign = db.seedKey({
      organizationId: 'org-other',
      algorithm: 'RS256',
      status: 'ROTATED',
      rotatedAt: NOW,
    });
    await expect(
      planRollback(db.asPrisma(), { badKeyId: bad.keyId, restoreKeyId: foreign.keyId }),
    ).rejects.toThrow(/different organizations/);
  });

  it('refuses an algorithm mismatch', async () => {
    const { db, bad } = badRotationFixture();
    const es = db.seedKey({
      organizationId: 'org-platform',
      algorithm: 'ES256',
      status: 'ROTATED',
      rotatedAt: NOW,
    });
    await expect(
      planRollback(db.asPrisma(), { badKeyId: bad.keyId, restoreKeyId: es.keyId }),
    ).rejects.toThrow(/Algorithm mismatch/);
  });

  it('refuses when the bad key is not ACTIVE', async () => {
    const { db, restore } = badRotationFixture();
    const alreadyRotated = db.seedKey({
      organizationId: 'org-platform',
      algorithm: 'RS256',
      status: 'ROTATED',
      rotatedAt: NOW,
    });
    await expect(
      planRollback(db.asPrisma(), { badKeyId: alreadyRotated.keyId, restoreKeyId: restore.keyId }),
    ).rejects.toThrow(/not ACTIVE/);
  });

  it('refuses when the restore target is not ROTATED (REVOKED needs deliberate review)', async () => {
    const { db, bad } = badRotationFixture();
    const revoked = db.seedKey({
      organizationId: 'org-platform',
      algorithm: 'RS256',
      status: 'REVOKED',
      rotatedAt: new Date('2026-08-29T07:00:00Z'),
      revokedAt: NOW,
    });
    await expect(
      planRollback(db.asPrisma(), { badKeyId: bad.keyId, restoreKeyId: revoked.keyId }),
    ).rejects.toThrow(/not ROTATED/);
  });
});

describe('executeRollback — the one-transaction swap', () => {
  it('demotes the bad key and restores the target atomically, clearing rotatedAt/revokedAt', async () => {
    const { db, bad, restore } = badRotationFixture();
    const plan = await planRollback(db.asPrisma(), {
      badKeyId: bad.keyId,
      restoreKeyId: restore.keyId,
    });

    await executeRollback(db.asPrisma(), plan, NOW);

    const badAfter = await db.signingKey.findUnique({ where: { keyId: bad.keyId } });
    const restoreAfter = await db.signingKey.findUnique({ where: { keyId: restore.keyId } });
    expect(badAfter?.status).toBe('ROTATED');
    expect(badAfter?.rotatedAt).toEqual(NOW);
    expect(restoreAfter?.status).toBe('ACTIVE');
    expect(restoreAfter?.rotatedAt).toBeNull();
    expect(restoreAfter?.revokedAt).toBeNull();
    // Invariant held: exactly one ACTIVE RS256 key at the end.
    expect(db.activeKeys('org-platform')).toHaveLength(1);
  });

  it('throws (and applies nothing) when the bad key stopped being ACTIVE after planning', async () => {
    const { db, bad, restore } = badRotationFixture();
    const plan = await planRollback(db.asPrisma(), {
      badKeyId: bad.keyId,
      restoreKeyId: restore.keyId,
    });
    // Concurrent change between plan and execute.
    await db.signingKey.update({
      where: { id: bad.id },
      data: { status: 'ROTATED', rotatedAt: NOW },
    });

    await expect(executeRollback(db.asPrisma(), plan, NOW)).rejects.toThrow(/not ACTIVE/);
    const restoreAfter = await db.signingKey.findUnique({ where: { keyId: restore.keyId } });
    expect(restoreAfter?.status).toBe('ROTATED'); // untouched
  });

  it('throws when the restore target stopped being ROTATED after planning', async () => {
    const { db, bad, restore } = badRotationFixture();
    const plan = await planRollback(db.asPrisma(), {
      badKeyId: bad.keyId,
      restoreKeyId: restore.keyId,
    });
    await db.signingKey.update({
      where: { id: restore.id },
      data: { status: 'REVOKED', revokedAt: NOW },
    });

    await expect(executeRollback(db.asPrisma(), plan, NOW)).rejects.toThrow(/not ROTATED/);
  });
});
