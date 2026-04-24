import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import {
  CACHE_MAX,
  CACHE_TTL_MS,
  SignerKeyError,
  createKeyCaches,
} from '../key-cache.js';
import { __resetMasterKeyCache, encryptAtRest } from '../key-at-rest.js';

/**
 * Unit tests for the signer key caches (Audit-4 A4-I1).
 *
 * Covers:
 *  - Hit / miss counters increment on the correct paths.
 *  - TTL expiry evicts with reason 'expire' → `evictionsTtl` increments.
 *  - LRU cap evicts with reason 'evict' → `evictionsLru` increments.
 *  - Caller-driven `.delete()` fires dispose with reason 'delete' but
 *    does NOT increment either eviction counter (the distinction matters
 *    for the provisioning invalidation path).
 *  - Unknown keyId (404) throws SignerKeyError and does not populate.
 *  - Invalid keyId (path-traversal shape) throws SignerKeyError(400) and
 *    does not populate.
 *  - snapshot() shape is stable and reflects current counter state.
 *
 * We write real encrypted envelopes into a temp directory so the loaders
 * exercise the same decryptAtRest path production does. The master key
 * cache is reset before each test so there's no cross-contamination.
 */

function writeSlhdsaKey(dir: string, keyId: string): Buffer {
  const secret = randomBytes(64); // SLH-DSA-SHA2-128s secret size
  const envelope = encryptAtRest(secret);
  writeFileSync(join(dir, `${keyId}.slhdsa.enc`), envelope, { mode: 0o600 });
  return secret;
}

function writeEcdsaPem(dir: string, keyId: string): string {
  // Minimal PEM-shaped content. The loader only checks for the
  // '-----BEGIN' marker, not the actual key validity, because key-shape
  // validation lives downstream at `createSign(pem)` time. That keeps
  // this cache module independent of the real key generation path.
  const pem =
    '-----BEGIN PRIVATE KEY-----\n' +
    Buffer.from(randomBytes(48)).toString('base64') +
    '\n-----END PRIVATE KEY-----\n';
  const envelope = encryptAtRest(Buffer.from(pem, 'utf8'));
  writeFileSync(join(dir, `${keyId}.ecdsa.enc`), envelope, { mode: 0o600 });
  return pem;
}

describe('createKeyCaches', () => {
  let dir: string;

  beforeEach(() => {
    __resetMasterKeyCache();
    process.env.SIGNER_MASTER_KEY = Buffer.from(randomBytes(32)).toString('base64');
    dir = mkdtempSync(join(tmpdir(), 'signer-cache-test-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    delete process.env.SIGNER_MASTER_KEY;
    __resetMasterKeyCache();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe('hit / miss counters', () => {
    it('loadPrivateKey: first call is a miss, second is a hit', async () => {
      const keyId = 'slhdsa-key-1';
      const expected = writeSlhdsaKey(dir, keyId);
      const caches = createKeyCaches(dir);

      const first = await caches.loadPrivateKey(keyId);
      expect(first.equals(expected)).toBe(true);
      expect(caches.slhdsaStats.misses).toBe(1);
      expect(caches.slhdsaStats.hits).toBe(0);

      const second = await caches.loadPrivateKey(keyId);
      expect(second.equals(expected)).toBe(true);
      expect(caches.slhdsaStats.misses).toBe(1);
      expect(caches.slhdsaStats.hits).toBe(1);
    });

    it('loadEcdsaPem: first call is a miss, second is a hit', async () => {
      const keyId = 'ecdsa-key-1';
      const expected = writeEcdsaPem(dir, keyId);
      const caches = createKeyCaches(dir);

      const first = await caches.loadEcdsaPem(keyId);
      expect(first).toBe(expected);
      expect(caches.ecdsaStats.misses).toBe(1);
      expect(caches.ecdsaStats.hits).toBe(0);

      const second = await caches.loadEcdsaPem(keyId);
      expect(second).toBe(expected);
      expect(caches.ecdsaStats.misses).toBe(1);
      expect(caches.ecdsaStats.hits).toBe(1);
    });

    it('hit and miss counters are cache-scoped — SLH-DSA load does not bump ECDSA counters', async () => {
      const keyId = 'slhdsa-only';
      writeSlhdsaKey(dir, keyId);
      const caches = createKeyCaches(dir);

      await caches.loadPrivateKey(keyId);
      await caches.loadPrivateKey(keyId);

      expect(caches.slhdsaStats.hits).toBe(1);
      expect(caches.slhdsaStats.misses).toBe(1);
      expect(caches.ecdsaStats.hits).toBe(0);
      expect(caches.ecdsaStats.misses).toBe(0);
    });
  });

  describe('TTL expiry', () => {
    it('advances past CACHE_TTL_MS and the next access registers as a miss with evictionsTtl++', async () => {
      // lru-cache@11 uses `performance.now()` as its time source
      // (verified in node_modules/.../lru-cache/dist/esm/index.js:6-10).
      // vitest's fake timers do not stub `performance.now` across the
      // supported toFake options on this version, so we stub it
      // directly — small, explicit, restored in afterEach via
      // vi.useRealTimers (which also reverts spies set through vi.spyOn).
      const origNow = performance.now.bind(performance);
      let offset = 0;
      vi.spyOn(performance, 'now').mockImplementation(() => origNow() + offset);

      const keyId = 'expiring-key';
      writeSlhdsaKey(dir, keyId);
      const caches = createKeyCaches(dir);

      // Populate the cache.
      await caches.loadPrivateKey(keyId);
      expect(caches.slhdsaStats.misses).toBe(1);
      expect(caches.keyCache.size).toBe(1);

      // Advance the monotonic clock past the TTL. lru-cache treats the
      // entry as expired on the next `.get()` and fires `dispose` with
      // reason 'expire' before returning undefined.
      offset += CACHE_TTL_MS + 1;

      await caches.loadPrivateKey(keyId);
      expect(caches.slhdsaStats.misses).toBe(2);
      expect(caches.slhdsaStats.hits).toBe(0);
      expect(caches.slhdsaStats.evictionsTtl).toBe(1);
      expect(caches.slhdsaStats.evictionsLru).toBe(0);
    });
  });

  describe('LRU cap eviction', () => {
    it('evictions fire with reason "evict" once the cap is exceeded, and the oldest entries are the ones removed', () => {
      const caches = createKeyCaches(dir);

      // Fill exactly to CACHE_MAX, then push 3 more — expect 3 LRU
      // evictions, all of them naming the three oldest keys.
      for (let i = 0; i < CACHE_MAX + 3; i += 1) {
        caches.keyCache.set(`k${i}`, Buffer.from([i & 0xff]));
      }

      expect(caches.keyCache.size).toBe(CACHE_MAX);
      expect(caches.slhdsaStats.evictionsLru).toBe(3);
      expect(caches.slhdsaStats.evictionsTtl).toBe(0);

      // LRU ordering: `k0..k2` were inserted first and never touched, so
      // they should be the three evicted. `k3` (now the oldest surviving)
      // and `k${CACHE_MAX + 2}` (the newest) must still be present.
      expect(caches.keyCache.has('k0')).toBe(false);
      expect(caches.keyCache.has('k1')).toBe(false);
      expect(caches.keyCache.has('k2')).toBe(false);
      expect(caches.keyCache.has('k3')).toBe(true);
      expect(caches.keyCache.has(`k${CACHE_MAX + 2}`)).toBe(true);
    });

    it('touching an entry via get() promotes it past newer entries and spares it from cap eviction', () => {
      const caches = createKeyCaches(dir);

      for (let i = 0; i < CACHE_MAX; i += 1) {
        caches.keyCache.set(`k${i}`, Buffer.from([i & 0xff]));
      }

      // Touch `k0` so it becomes the most-recently-used. The next
      // insertion must evict `k1` (the new oldest) instead of `k0`.
      caches.keyCache.get('k0');
      caches.keyCache.set('k-new', Buffer.from([0xff]));

      expect(caches.keyCache.size).toBe(CACHE_MAX);
      expect(caches.slhdsaStats.evictionsLru).toBe(1);
      expect(caches.keyCache.has('k0')).toBe(true);
      expect(caches.keyCache.has('k1')).toBe(false);
      expect(caches.keyCache.has('k-new')).toBe(true);
    });
  });

  describe('caller-driven deletion (provisioning path)', () => {
    it('.delete() fires dispose with reason "delete" — NOT counted as eviction', async () => {
      const keyId = 'prov-key';
      writeSlhdsaKey(dir, keyId);
      const caches = createKeyCaches(dir);

      await caches.loadPrivateKey(keyId);
      expect(caches.keyCache.size).toBe(1);

      caches.keyCache.delete(keyId);

      expect(caches.keyCache.size).toBe(0);
      expect(caches.slhdsaStats.evictionsLru).toBe(0);
      expect(caches.slhdsaStats.evictionsTtl).toBe(0);
    });

    it('deleting both caches (as POST /v1/keys/:keyId does) leaves both counters at zero', async () => {
      const keyId = 'dual-prov-key';
      writeSlhdsaKey(dir, keyId);
      writeEcdsaPem(dir, keyId);
      const caches = createKeyCaches(dir);

      await caches.loadPrivateKey(keyId);
      await caches.loadEcdsaPem(keyId);

      caches.keyCache.delete(keyId);
      caches.ecdsaKeyCache.delete(keyId);

      expect(caches.keyCache.size).toBe(0);
      expect(caches.ecdsaKeyCache.size).toBe(0);
      expect(caches.slhdsaStats.evictionsLru).toBe(0);
      expect(caches.slhdsaStats.evictionsTtl).toBe(0);
      expect(caches.ecdsaStats.evictionsLru).toBe(0);
      expect(caches.ecdsaStats.evictionsTtl).toBe(0);
    });

    it('.set() replacement fires dispose with reason "set" — NOT counted as eviction', () => {
      const caches = createKeyCaches(dir);

      caches.keyCache.set('k', Buffer.from([1]));
      caches.keyCache.set('k', Buffer.from([2])); // same key, different value

      expect(caches.keyCache.size).toBe(1);
      expect(caches.slhdsaStats.evictionsLru).toBe(0);
      expect(caches.slhdsaStats.evictionsTtl).toBe(0);
    });
  });

  describe('error paths do not populate cache', () => {
    it('404 on missing SLH-DSA file throws SignerKeyError and leaves cache empty', async () => {
      const caches = createKeyCaches(dir);
      await expect(caches.loadPrivateKey('no-such-key')).rejects.toBeInstanceOf(
        SignerKeyError,
      );
      expect(caches.keyCache.size).toBe(0);
      // Miss still increments — caller asked for it, we looked, it wasn't
      // there. The read attempt itself counts as a miss regardless of
      // whether disk had the file.
      expect(caches.slhdsaStats.misses).toBe(1);
      expect(caches.slhdsaStats.hits).toBe(0);
    });

    it('404 on missing ECDSA file throws SignerKeyError and leaves cache empty', async () => {
      const caches = createKeyCaches(dir);
      await expect(caches.loadEcdsaPem('no-such-key')).rejects.toBeInstanceOf(
        SignerKeyError,
      );
      expect(caches.ecdsaKeyCache.size).toBe(0);
      expect(caches.ecdsaStats.misses).toBe(1);
    });

    it('invalid keyId shape throws 400 and does not populate', async () => {
      const caches = createKeyCaches(dir);
      await expect(caches.loadPrivateKey('../etc/passwd')).rejects.toMatchObject({
        code: 'invalid_key_id',
        status: 400,
      });
      await expect(caches.loadEcdsaPem('weird/slash')).rejects.toMatchObject({
        code: 'invalid_key_id',
        status: 400,
      });
      expect(caches.keyCache.size).toBe(0);
      expect(caches.ecdsaKeyCache.size).toBe(0);
    });

    it('corrupted envelope (unreadable cipher) throws 500 and does not populate', async () => {
      const keyId = 'corrupt-key';
      writeFileSync(
        join(dir, `${keyId}.slhdsa.enc`),
        'qrauth-kek-v1\0not-valid-base64\0also-not\0nope\0',
      );
      const caches = createKeyCaches(dir);
      await expect(caches.loadPrivateKey(keyId)).rejects.toMatchObject({
        code: 'key_corrupted',
        status: 500,
      });
      expect(caches.keyCache.size).toBe(0);
    });
  });

  describe('snapshot()', () => {
    it('returns the declared shape with current counter values', async () => {
      const keyId = 'snapshot-key';
      writeSlhdsaKey(dir, keyId);
      writeEcdsaPem(dir, keyId);
      const caches = createKeyCaches(dir);

      await caches.loadPrivateKey(keyId); // 1 miss
      await caches.loadPrivateKey(keyId); // 1 hit
      await caches.loadEcdsaPem(keyId); // 1 miss

      const snap = caches.snapshot();
      expect(snap).toEqual({
        caches: {
          slhdsa: {
            entries: 1,
            hits: 1,
            misses: 1,
            evictions: { ttl: 0, lru: 0 },
          },
          ecdsa: {
            entries: 1,
            hits: 0,
            misses: 1,
            evictions: { ttl: 0, lru: 0 },
          },
        },
        config: { ttlMs: CACHE_TTL_MS, max: CACHE_MAX },
      });
    });
  });
});
