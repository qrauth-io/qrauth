import { describe, it, expect, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FakeSigningKeyPrisma } from './fake-signing-key-prisma.js';

/**
 * Algorithm-scoped signing-key rotation (docs/ops/signing-key-rotation-loop.md,
 * defect 1): `getActiveKey`/`rotateKey` must never let the ES256 path consume
 * or replace an RS256 key. The production incident: the platform org's only
 * RS256 key was the newest ACTIVE row, so an algorithm-blind `rotateKey`
 * demoted it and minted a hardcoded-ES256 replacement — silently killing
 * every RS256 OIDC client.
 *
 * Real crypto (ECDSA + SLH-DSA + RSA keygen, at-rest encryption to a temp
 * dir); only the DB and the BullMQ queues are faked, per the CI api-unit
 * contract (no DB/Redis connections).
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
process.env.ECDSA_PRIVATE_KEY_PATH = mkdtempSync(join(tmpdir(), 'qrauth-signing-rotation-'));

const { SigningService } = await import('../signing.js');

const DAY_MS = 24 * 60 * 60 * 1000;
const daysAgo = (n: number) => new Date(Date.now() - n * DAY_MS);

function bothAlgsOrg() {
  const db = new FakeSigningKeyPrisma();
  const es256 = db.seedKey({
    organizationId: 'org-1',
    algorithm: 'ES256',
    createdAt: daysAgo(100),
  });
  // RS256 minted later (the RSA bootstrap script) — the NEWEST active row,
  // exactly the shape that triggered the incident.
  const rs256 = db.seedKey({
    organizationId: 'org-1',
    algorithm: 'RS256',
    createdAt: daysAgo(9),
  });
  const service = new SigningService(db.asPrisma());
  return { db, es256, rs256, service };
}

describe('SigningService.getActiveKey — algorithm scoped', () => {
  it('returns the ES256 key by default even when an RS256 key is newer', async () => {
    const { es256, service } = bothAlgsOrg();

    const key = await service.getActiveKey('org-1');

    expect(key.keyId).toBe(es256.keyId);
    expect(key.algorithm).toBe('ES256');
  });

  it('returns the RS256 key when RS256 is requested', async () => {
    const { rs256, service } = bothAlgsOrg();

    const key = await service.getActiveKey('org-1', 'RS256');

    expect(key.keyId).toBe(rs256.keyId);
  });

  it('throws for the ES256 path when the org holds only an RS256 key (RS256 unreachable from ES256 consumers)', async () => {
    const db = new FakeSigningKeyPrisma();
    db.seedKey({ organizationId: 'org-rsa-only', algorithm: 'RS256' });
    const service = new SigningService(db.asPrisma());

    await expect(service.getActiveKey('org-rsa-only')).rejects.toThrow(/No active/i);
  });
});

describe('SigningService.rotateKey — same-algorithm replacement', () => {
  it('rotates only the ES256 key and leaves the RS256 key ACTIVE', async () => {
    const { db, es256, rs256, service } = bothAlgsOrg();

    const newKey = await service.rotateKey('org-1');

    const rs256After = await db.signingKey.findUnique({ where: { keyId: rs256.keyId } });
    const es256After = await db.signingKey.findUnique({ where: { keyId: es256.keyId } });
    expect(rs256After?.status).toBe('ACTIVE');
    expect(es256After?.status).toBe('ROTATED');
    expect(newKey.algorithm).toBe('ES256');
    expect(newKey.status).toBe('ACTIVE');
    expect(newKey.slhdsaPublicKey).toBeTruthy();
  });

  it('rotates the RS256 key into a new ACTIVE RS256 key, leaving ES256 untouched', async () => {
    const { db, es256, rs256, service } = bothAlgsOrg();

    const newKey = await service.rotateKey('org-1', 'RS256');

    const rs256After = await db.signingKey.findUnique({ where: { keyId: rs256.keyId } });
    const es256After = await db.signingKey.findUnique({ where: { keyId: es256.keyId } });
    expect(rs256After?.status).toBe('ROTATED');
    expect(es256After?.status).toBe('ACTIVE');
    expect(newKey.algorithm).toBe('RS256');
    expect(newKey.status).toBe('ACTIVE');
    // RSA OIDC keys carry no SLH-DSA leg.
    expect(newKey.slhdsaPublicKey).toBeNull();
    // The replacement RSA public key must be a real SPKI PEM.
    expect(newKey.publicKey).toContain('BEGIN PUBLIC KEY');
  });
});

describe('rotation probe — verify-then-commit (canary mechanism 1)', () => {
  // The signer "succeeds" but its signatures are garbage — the exact shape of
  // a 2xx push that left an unusable envelope. Base64url-valid so the verify
  // path runs and returns false rather than erroring on decode.
  const garbageSig = 'QUFBQUFBQUFBQUFBQUFBQQ';

  it('an ES256 rotation aborts before ANY write when the new key cannot produce a valid signature', async () => {
    const { db, es256 } = bothAlgsOrg();
    const badEcdsa = { signCanonical: async () => garbageSig, signJws: async () => garbageSig };
    const service = new SigningService(db.asPrisma(), badEcdsa);
    const rowsBefore = db.rows.length;

    await expect(service.rotateKey('org-1')).rejects.toThrow(/does NOT verify against its own public key/);

    // Nothing committed: the old key still signs, no new row exists.
    expect((await db.signingKey.findUnique({ where: { keyId: es256.keyId } }))?.status).toBe('ACTIVE');
    expect(db.rows.length).toBe(rowsBefore);
  });

  it('an RS256 rotation aborts before ANY write on an unusable envelope', async () => {
    const { db, rs256 } = bothAlgsOrg();
    const badRsa = { signJws: async () => garbageSig };
    const service = new SigningService(db.asPrisma(), undefined, badRsa);
    const rowsBefore = db.rows.length;

    await expect(service.rotateKey('org-1', 'RS256')).rejects.toThrow(/does NOT verify against its own public key/);

    expect((await db.signingKey.findUnique({ where: { keyId: rs256.keyId } }))?.status).toBe('ACTIVE');
    expect(db.rows.length).toBe(rowsBefore);
  });

  it('a signer that errors outright also aborts before commit, with the sign-probe message', async () => {
    const { db, es256 } = bothAlgsOrg();
    const deadEcdsa = {
      signCanonical: async () => {
        throw new Error('signer unreachable');
      },
      signJws: async () => {
        throw new Error('signer unreachable');
      },
    };
    const service = new SigningService(db.asPrisma(), deadEcdsa);

    await expect(service.rotateKey('org-1')).rejects.toThrow(/sign probe with new ES256 key/);
    expect((await db.signingKey.findUnique({ where: { keyId: es256.keyId } }))?.status).toBe('ACTIVE');
  });
});

describe('SigningService.rotateKeyById — rotates exactly the named key', () => {
  it('demotes the given stale key (not the newest) and mints a same-algorithm replacement', async () => {
    const { db, es256, rs256, service } = bothAlgsOrg();

    const newKey = await service.rotateKeyById(es256.keyId);

    const es256After = await db.signingKey.findUnique({ where: { keyId: es256.keyId } });
    const rs256After = await db.signingKey.findUnique({ where: { keyId: rs256.keyId } });
    expect(es256After?.status).toBe('ROTATED');
    expect(rs256After?.status).toBe('ACTIVE');
    expect(newKey.algorithm).toBe('ES256');
  });

  it('refuses to rotate a key that is not ACTIVE', async () => {
    const db = new FakeSigningKeyPrisma();
    const rotated = db.seedKey({
      organizationId: 'org-1',
      algorithm: 'ES256',
      status: 'ROTATED',
      rotatedAt: daysAgo(1),
    });
    const service = new SigningService(db.asPrisma());

    await expect(service.rotateKeyById(rotated.keyId)).rejects.toThrow(/not ACTIVE/i);
  });
});
