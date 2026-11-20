import { describe, it, expect, vi, afterEach } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * T4-A: signer-push error propagation in `SigningService.createKeyPair`.
 *
 * Before T4-A, `pushKeysToSigner` logged-and-swallowed every failure, so a
 * broken/unreachable signer left a DB row the signer could never sign with —
 * a silent failure for the rotation worker and the OIDC bootstrap script.
 * The fix makes the push THROW; `createKeyPair` awaits it, so the error now
 * surfaces to the caller. These tests pin both directions:
 *   1. http backend + failing push  → createKeyPair rejects, no DB row written.
 *   2. local backend (success path)  → no signer contact, key created.
 *
 * The signer URL/token are captured at module load (`signerPushUrl` consts in
 * signing.ts), so each test sets env, `vi.resetModules()`, then dynamically
 * imports the service for a fresh read.
 */

// Keep the transitive `security-webhook → lib/queue` import off Redis.
vi.mock('../../lib/queue.js', () => ({
  webhookQueue: { add: vi.fn(async () => ({ id: 'job_1' })) },
  closeQueues: vi.fn(async () => {}),
}));

function fakePrisma(createImpl: () => Promise<unknown>) {
  return {
    signingKey: { create: vi.fn(createImpl) },
    // The fire-and-forget signing-key.created webhook reads the org; return a
    // row with no configured endpoint so the enqueue cleanly no-ops.
    organization: { findUnique: vi.fn(async () => null) },
  } as never;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  delete process.env.SLH_DSA_SIGNER;
  delete process.env.SLH_DSA_SIGNER_URL;
  delete process.env.SLH_DSA_SIGNER_TOKEN;
  delete process.env.ECDSA_SIGNER;
});

describe('SigningService.createKeyPair — signer-push error propagation (T4-A)', () => {
  it('rejects when the signer push returns a non-2xx, and writes no DB row', async () => {
    vi.resetModules();
    process.env.ECDSA_PRIVATE_KEY_PATH = mkdtempSync(join(tmpdir(), 'qrauth-keys-'));
    process.env.SLH_DSA_SIGNER = 'http';
    process.env.SLH_DSA_SIGNER_URL = 'http://signer.test';
    process.env.SLH_DSA_SIGNER_TOKEN = 'test-token';

    const fetchMock = vi.fn(async () => ({
      ok: false,
      status: 502,
      text: async () => 'signer down',
    }));
    vi.stubGlobal('fetch', fetchMock);

    const { SigningService } = await import('../signing.js');
    const prisma = fakePrisma(async () => {
      throw new Error('prisma.signingKey.create must not run after a failed push');
    });
    const svc = new SigningService(prisma);

    await expect(svc.createKeyPair('org_1')).rejects.toThrow(/signer returned 502/);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    // The push happens before the DB write — a failed push must not leave a row.
    expect((prisma as unknown as { signingKey: { create: ReturnType<typeof vi.fn> } }).signingKey.create)
      .not.toHaveBeenCalled();
  });

  it('rejects when the signer push connection throws (transport error)', async () => {
    vi.resetModules();
    process.env.ECDSA_PRIVATE_KEY_PATH = mkdtempSync(join(tmpdir(), 'qrauth-keys-'));
    process.env.SLH_DSA_SIGNER = 'http';
    process.env.SLH_DSA_SIGNER_URL = 'http://signer.test';
    process.env.SLH_DSA_SIGNER_TOKEN = 'test-token';

    vi.stubGlobal('fetch', vi.fn(async () => {
      throw new Error('ECONNREFUSED');
    }));

    const { SigningService } = await import('../signing.js');
    const svc = new SigningService(fakePrisma(async () => ({})));

    await expect(svc.createKeyPair('org_1')).rejects.toThrow(/ECONNREFUSED/);
  });

  it('success path: local backend never contacts a signer and returns the row', async () => {
    vi.resetModules();
    process.env.ECDSA_PRIVATE_KEY_PATH = mkdtempSync(join(tmpdir(), 'qrauth-keys-'));
    process.env.SLH_DSA_SIGNER = 'local';
    process.env.ECDSA_SIGNER = 'local';
    delete process.env.SLH_DSA_SIGNER_URL;
    delete process.env.SLH_DSA_SIGNER_TOKEN;

    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const { SigningService } = await import('../signing.js');
    const row = {
      id: 'sk_1',
      organizationId: 'org_1',
      keyId: 'kid-local',
      algorithm: 'ES256',
      status: 'ACTIVE',
      slhdsaAlgorithm: 'slh-dsa-sha2-128s',
      createdAt: new Date('2026-01-02T03:04:05.000Z'),
    };
    const svc = new SigningService(fakePrisma(async () => row));

    const result = await svc.createKeyPair('org_1');

    expect(result).toEqual(row);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
