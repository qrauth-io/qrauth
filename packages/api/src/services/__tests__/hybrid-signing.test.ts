import { describe, it, expect, vi, beforeAll, beforeEach } from 'vitest';
import type { HybridSigningService as HybridSigningServiceType, HybridSignInput } from '../hybrid-signing.js';

/**
 * Backend-aware SLH-DSA pre-flight guard (#60, follow-up to PR #59).
 *
 * Regression fixture for the production 500 on 2026-04-20T14:47Z, where
 * `assertSlhDsaMaterialAvailable` unconditionally read the local
 * `.slhdsa.enc` envelope and broke every QR issuance on `SLH_DSA_SIGNER=http`
 * (per ADR-001, zero private key material on the API host).
 *
 * PR #59 short-circuited the guard on `config.slhdsaSigner.backend === 'http'`.
 * These tests pin that behavior on both entry points — `signSingleQR` and
 * `signSingleQRAsync` — and keep the `local` branch honest so dev never
 * silently slides into the http path without its error message.
 *
 * Strategy: mutable `vi.hoisted()` config mock, flip `backend` per test.
 * The signing/batch dependencies are hand-rolled stubs — we assert on
 * call-counts for `loadSlhDsaKeyPair`, so we don't need real crypto.
 */

// Shared mutable config object the vi.mock factory closes over.
const mockConfig = vi.hoisted(() => ({
  slhdsaSigner: {
    backend: 'local' as 'local' | 'http',
    url: undefined as string | undefined,
    token: undefined as string | undefined,
  },
}));

vi.mock('../../lib/config.js', () => ({
  config: mockConfig,
}));

beforeAll(() => {
  // Peer modules (notably @qrauth/shared via canonicalizeCore / computeDestHash)
  // don't read these directly, but the api package's config loader does — set
  // them so any transitive import doesn't zod-throw during module init.
  process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
  process.env.REDIS_URL = 'redis://localhost:6379';
  process.env.JWT_SECRET = 'a'.repeat(32);
  process.env.ANIMATED_QR_SECRET = 'a'.repeat(64);
});

describe('HybridSigningService — assertSlhDsaMaterialAvailable (backend-aware pre-flight)', () => {
  let HybridSigningService: typeof HybridSigningServiceType;

  let loadSlhDsaKeyPair: ReturnType<typeof vi.fn>;
  let signCanonical: ReturnType<typeof vi.fn>;
  let enqueue: ReturnType<typeof vi.fn>;

  const baseInput: HybridSignInput = {
    organizationId: 'org-test',
    signingKeyDbId: 'db-key-01',
    signingKeyId: 'key-01',
    token: 'token-01',
    contentType: 'url',
    destinationUrl: 'https://example.com',
    contentHashHex: '',
    expiresAt: '',
    lat: null,
    lng: null,
    radiusM: null,
  };

  beforeAll(async () => {
    const mod = await import('../hybrid-signing.js');
    HybridSigningService = mod.HybridSigningService;
  });

  beforeEach(() => {
    // Fresh stubs per test so call-counts are isolated.
    loadSlhDsaKeyPair = vi.fn();
    signCanonical = vi.fn().mockResolvedValue('stub-ecdsa-sig-hex');
    // batchSigner.enqueue rejects — we never exercise the batcher from this
    // test. signSingleQR's happy path awaits it; we catch the rejection in
    // the http-branch tests since the contract under test is what happens
    // BEFORE the batcher is reached.
    enqueue = vi.fn().mockRejectedValue(new Error('batchSigner.enqueue not under test'));

    // Reset config to the default each test; individual tests flip it.
    mockConfig.slhdsaSigner.backend = 'local';
  });

  function makeService() {
    const signingService = {
      loadSlhDsaKeyPair,
      signCanonical,
    };
    const batchSigner = { enqueue };
    return new HybridSigningService(
      {} as never,
      signingService as never,
      batchSigner as never,
    );
  }

  describe('signSingleQR', () => {
    it('does not touch the filesystem when backend is http (regression guard for PR #59)', async () => {
      mockConfig.slhdsaSigner.backend = 'http';
      const svc = makeService();

      // The guard short-circuits on http; we then proceed into the ECDSA
      // leg and the Merkle/SLH-DSA enqueue, which our stub rejects. The
      // promise rejection is expected and irrelevant to this assertion —
      // the contract under test is that `loadSlhDsaKeyPair` was never
      // called, i.e. no local key-file read happened.
      await expect(svc.signSingleQR(baseInput)).rejects.toThrow(
        /batchSigner\.enqueue not under test/,
      );

      expect(loadSlhDsaKeyPair).not.toHaveBeenCalled();
      // ECDSA leg still fires on http — only the PQC pre-flight is skipped.
      expect(signCanonical).toHaveBeenCalledTimes(1);
    });

    it('throws on backend=local when SLH-DSA material is missing', async () => {
      mockConfig.slhdsaSigner.backend = 'local';
      loadSlhDsaKeyPair.mockResolvedValue(null);
      const svc = makeService();

      await expect(svc.signSingleQR(baseInput)).rejects.toThrow(
        /has no SLH-DSA material/,
      );
      expect(loadSlhDsaKeyPair).toHaveBeenCalledTimes(1);
      expect(loadSlhDsaKeyPair).toHaveBeenCalledWith('key-01');
      // Guard throws before ECDSA signing is attempted.
      expect(signCanonical).not.toHaveBeenCalled();
      expect(enqueue).not.toHaveBeenCalled();
    });

    it('passes the guard on backend=local when SLH-DSA material is present', async () => {
      mockConfig.slhdsaSigner.backend = 'local';
      loadSlhDsaKeyPair.mockResolvedValue({
        publicKey: Buffer.alloc(0),
        privateKey: Buffer.alloc(0),
      });
      const svc = makeService();

      // Guard succeeds → ECDSA leg fires → batchSigner stub rejects. Same
      // as the http happy-path, but we additionally assert that the local
      // file read WAS attempted exactly once.
      await expect(svc.signSingleQR(baseInput)).rejects.toThrow(
        /batchSigner\.enqueue not under test/,
      );
      expect(loadSlhDsaKeyPair).toHaveBeenCalledTimes(1);
      expect(loadSlhDsaKeyPair).toHaveBeenCalledWith('key-01');
    });
  });

  describe('signSingleQRAsync', () => {
    it('does not touch the filesystem when backend is http', async () => {
      mockConfig.slhdsaSigner.backend = 'http';
      const svc = makeService();

      // signSingleQRAsync returns `{ ecdsaSignature, merklePromise }`
      // WITHOUT awaiting the merkle promise, so the function itself
      // resolves cleanly even when the batcher stub rejects. We attach a
      // catch handler to the returned promise to avoid an unhandled
      // rejection warning.
      const { ecdsaSignature, merklePromise } = await svc.signSingleQRAsync(baseInput);
      merklePromise.catch(() => { /* batchSigner stub rejects, as designed */ });

      expect(ecdsaSignature).toBe('stub-ecdsa-sig-hex');
      expect(loadSlhDsaKeyPair).not.toHaveBeenCalled();
      expect(signCanonical).toHaveBeenCalledTimes(1);
    });

    it('throws synchronously on backend=local when SLH-DSA material is missing', async () => {
      mockConfig.slhdsaSigner.backend = 'local';
      loadSlhDsaKeyPair.mockResolvedValue(null);
      const svc = makeService();

      await expect(svc.signSingleQRAsync(baseInput)).rejects.toThrow(
        /has no SLH-DSA material/,
      );
      expect(loadSlhDsaKeyPair).toHaveBeenCalledTimes(1);
      expect(signCanonical).not.toHaveBeenCalled();
      expect(enqueue).not.toHaveBeenCalled();
    });

    it('passes the guard on backend=local when SLH-DSA material is present', async () => {
      mockConfig.slhdsaSigner.backend = 'local';
      loadSlhDsaKeyPair.mockResolvedValue({
        publicKey: Buffer.alloc(0),
        privateKey: Buffer.alloc(0),
      });
      const svc = makeService();

      const { ecdsaSignature, merklePromise } = await svc.signSingleQRAsync(baseInput);
      merklePromise.catch(() => { /* stub rejects */ });

      expect(ecdsaSignature).toBe('stub-ecdsa-sig-hex');
      expect(loadSlhDsaKeyPair).toHaveBeenCalledTimes(1);
      expect(loadSlhDsaKeyPair).toHaveBeenCalledWith('key-01');
    });
  });
});
