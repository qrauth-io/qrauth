import { describe, it, expect, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FakeSigningKeyPrisma } from '../../services/__tests__/fake-signing-key-prisma.js';

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
process.env.ECDSA_PRIVATE_KEY_PATH = mkdtempSync(join(tmpdir(), 'qrauth-canary-test-'));

const { SigningService } = await import('../../services/signing.js');
const {
  runSigningCanary,
  evaluateCanaryForHealth,
  CANARY_LATEST_KEY,
  CANARY_STICKY_KEY,
  STALE_ALARM_AFTER_MS,
  UNKNOWN_ALARM_AFTER_MS,
} = await import('../signing-canary.js');
const { QRAUTH_PLATFORM_ORG_SLUG } = await import('../../lib/oidc-signing-keys.js');

/**
 * Signing canary (mechanism 2) — the drift detector for "ACTIVE row exists
 * but the key cannot actually sign". Pins the OK path with REAL crypto
 * (mint → sign via the real local signer → verify under the PUBLISHED JWK),
 * every failure classification, staleSince carry-over, and the sticky rule:
 * STALE and UNKNOWN never mask a recorded FAILED.
 */

const NOW = new Date('2026-09-10T12:00:00Z');
const PLATFORM_ORG = 'org-platform';

class FakeStore {
  map = new Map<string, string>();
  failing = false;
  async get(key: string): Promise<string | null> {
    if (this.failing) throw new Error('redis unavailable');
    return this.map.get(key) ?? null;
  }
  async set(key: string, value: string): Promise<void> {
    if (this.failing) throw new Error('redis unavailable');
    this.map.set(key, value);
  }
  latest() {
    return JSON.parse(this.map.get(CANARY_LATEST_KEY) ?? 'null');
  }
  sticky() {
    return JSON.parse(this.map.get(CANARY_STICKY_KEY) ?? 'null');
  }
}

async function provisionedPlatform() {
  const db = new FakeSigningKeyPrisma();
  db.seedOrg(PLATFORM_ORG, QRAUTH_PLATFORM_ORG_SLUG);
  const service = new SigningService(db.asPrisma());
  // Real keygen + envelopes on disk, so the real local signers can sign.
  await service.createKeyPair(PLATFORM_ORG);
  await service.createRsaKeyPair(PLATFORM_ORG);
  return { db, service };
}

describe('runSigningCanary — probe outcomes', () => {
  it('OK for both algorithms with real crypto: signs via the real path, verifies under the published JWK', async () => {
    const { db, service } = await provisionedPlatform();
    const store = new FakeStore();

    const result = await runSigningCanary(db.asPrisma(), service, store, NOW);

    expect(result.ES256?.status).toBe('OK');
    expect(result.RS256?.status).toBe('OK');
    expect(result.ES256?.lastSuccessAt).toBe(NOW.toISOString());
    // Definitive outcomes are recorded in both LATEST and STICKY.
    expect(store.latest().RS256.status).toBe('OK');
    expect(store.sticky().RS256.status).toBe('OK');
  });

  it('FAILED(no_active_key) when an advertised algorithm has no ACTIVE key', async () => {
    const db = new FakeSigningKeyPrisma();
    db.seedOrg(PLATFORM_ORG, QRAUTH_PLATFORM_ORG_SLUG);
    const service = new SigningService(db.asPrisma());
    await service.createKeyPair(PLATFORM_ORG); // ES256 only
    const store = new FakeStore();

    const result = await runSigningCanary(db.asPrisma(), service, store, NOW);

    expect(result.ES256?.status).toBe('OK');
    expect(result.RS256).toMatchObject({ status: 'FAILED', reason: 'no_active_key' });
    expect(store.sticky().RS256.status).toBe('FAILED');
  });

  it('FAILED(signature_invalid_under_published_jwk) when the signer returns garbage — the unusable-envelope shape', async () => {
    const { db } = await provisionedPlatform();
    const garbage = { signJws: async () => 'QUFBQUFBQUFBQUFBQUFBQQ', signCanonical: async () => 'x' };
    const badService = new SigningService(db.asPrisma(), garbage, garbage);
    const store = new FakeStore();

    const result = await runSigningCanary(db.asPrisma(), badService, store, NOW);

    expect(result.ES256).toMatchObject({
      status: 'FAILED',
      reason: 'signature_invalid_under_published_jwk',
    });
    expect(result.RS256?.status).toBe('FAILED');
  });

  it('FAILED(signer_rejected) on a definitive signer 4xx', async () => {
    const { db } = await provisionedPlatform();
    const rejecting = {
      signJws: async () => {
        throw new Error('signJws kid: signer returned 404 {"error":"unknown_key"}');
      },
      signCanonical: async () => 'x',
    };
    const badService = new SigningService(db.asPrisma(), rejecting, rejecting);
    const store = new FakeStore();

    const result = await runSigningCanary(db.asPrisma(), badService, store, NOW);

    expect(result.ES256?.status).toBe('FAILED');
    expect(result.ES256?.reason).toMatch(/signer_rejected/);
  });

  it('STALE on transport failure; staleSince survives across runs; sticky keeps the last definitive OK', async () => {
    const { db, service } = await provisionedPlatform();
    const store = new FakeStore();
    // Run 1: healthy — records sticky OK.
    await runSigningCanary(db.asPrisma(), service, store, NOW);

    const unreachable = {
      signJws: async () => {
        throw new Error('fetch failed: connect ECONNREFUSED 10.0.0.9:8443');
      },
      signCanonical: async () => 'x',
    };
    const deadService = new SigningService(db.asPrisma(), unreachable, unreachable);

    const t1 = new Date(NOW.getTime() + 60 * 60 * 1000);
    const run2 = await runSigningCanary(db.asPrisma(), deadService, store, t1);
    expect(run2.ES256?.status).toBe('STALE');
    expect(run2.ES256?.staleSince).toBe(t1.toISOString());
    // lastSuccessAt carried from the healthy run.
    expect(run2.ES256?.lastSuccessAt).toBe(NOW.toISOString());

    const t2 = new Date(NOW.getTime() + 2 * 60 * 60 * 1000);
    const run3 = await runSigningCanary(db.asPrisma(), deadService, store, t2);
    // The streak's start is preserved, not reset.
    expect(run3.ES256?.staleSince).toBe(t1.toISOString());
    // STALE never overwrites the definitive record.
    expect(store.sticky().ES256.status).toBe('OK');
  });
});

describe('evaluateCanaryForHealth — the /health rules', () => {
  const okState = {
    ES256: { status: 'OK' as const, kid: 'a', lastSuccessAt: NOW.toISOString(), checkedAt: NOW.toISOString() },
    RS256: { status: 'OK' as const, kid: 'b', lastSuccessAt: NOW.toISOString(), checkedAt: NOW.toISOString() },
  };

  it('all OK → ok, no degrade', () => {
    const v = evaluateCanaryForHealth({ latest: okState, sticky: okState, unknownSince: null, now: NOW });
    expect(v).toMatchObject({ status: 'ok', degrade: false, reasons: [] });
  });

  it('FAILED degrades immediately with a per-alg reason', () => {
    const latest = { ...okState, RS256: { status: 'FAILED' as const, kid: 'b', reason: 'kid_unpublished', checkedAt: NOW.toISOString() } };
    const v = evaluateCanaryForHealth({ latest, sticky: okState, unknownSince: null, now: NOW });
    expect(v.degrade).toBe(true);
    expect(v.reasons.join(' ')).toContain('canary_failed:RS256:kid_unpublished');
  });

  it('STALE never masks a recorded FAILED (sticky wins)', () => {
    const latest = { ...okState, RS256: { status: 'STALE' as const, kid: 'b', reason: 'signer_unreachable: x', staleSince: NOW.toISOString(), checkedAt: NOW.toISOString() } };
    const sticky = { ...okState, RS256: { status: 'FAILED' as const, kid: 'b', reason: 'signature_invalid_under_published_jwk', checkedAt: NOW.toISOString() } };
    const v = evaluateCanaryForHealth({ latest, sticky, unknownSince: null, now: NOW });
    expect(v.perAlg.RS256?.status).toBe('failed');
    expect(v.degrade).toBe(true);
  });

  it('STALE degrades only beyond the threshold', () => {
    const staleSince = new Date(NOW.getTime() - STALE_ALARM_AFTER_MS - 1000).toISOString();
    const latest = { ...okState, ES256: { status: 'STALE' as const, kid: 'a', staleSince, checkedAt: NOW.toISOString() } };
    const over = evaluateCanaryForHealth({ latest, sticky: okState, unknownSince: null, now: NOW });
    expect(over.degrade).toBe(true);
    expect(over.reasons.join(' ')).toContain('canary_stale:ES256');

    const recent = { ...okState, ES256: { status: 'STALE' as const, kid: 'a', staleSince: NOW.toISOString(), checkedAt: NOW.toISOString() } };
    const under = evaluateCanaryForHealth({ latest: recent, sticky: okState, unknownSince: null, now: NOW });
    expect(under.degrade).toBe(false);
    expect(under.status).toBe('stale');
  });

  it('UNKNOWN degrades only beyond its own threshold — and never masks a recorded FAILED', () => {
    const fresh = evaluateCanaryForHealth({ latest: null, sticky: null, unknownSince: NOW, now: NOW });
    expect(fresh).toMatchObject({ status: 'unknown', degrade: false });

    const longAgo = new Date(NOW.getTime() - UNKNOWN_ALARM_AFTER_MS - 1000);
    const aged = evaluateCanaryForHealth({ latest: null, sticky: null, unknownSince: longAgo, now: NOW });
    expect(aged.degrade).toBe(true);
    expect(aged.reasons.join(' ')).toContain('canary_unknown');

    const sticky = { RS256: { status: 'FAILED' as const, kid: 'b', reason: 'kid_unpublished', checkedAt: NOW.toISOString() } };
    const masked = evaluateCanaryForHealth({ latest: null, sticky, unknownSince: NOW, now: NOW });
    expect(masked.status).toBe('failed');
    expect(masked.degrade).toBe(true);
  });
});
