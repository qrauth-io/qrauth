/**
 * In-process key caches for the signer service (Audit-4 A4-I1).
 *
 * The signer loads encrypted key envelopes off local disk, decrypts, and
 * keeps the result in memory so repeat sign requests for the same keyId
 * skip the readFile + AES-GCM-decrypt round-trip. Previously this was two
 * ad-hoc `Map<string, ...>` instances in `server.ts` with no bound and no
 * TTL — entries accumulated over process lifetime and stale public keys
 * lingered after signer-side key rotation. This module replaces that with
 * a bounded, TTL-capped LRU pair, plus hit/miss/eviction counters for
 * observability.
 *
 * Eviction strategy: lazy. We do not set `ttlAutopurge` — expired entries
 * are removed on next access, which keeps the common-path cost at zero
 * and matches the original "disk is the source of truth" semantics.
 *
 * This module is factored out of `server.ts` so it can be unit-tested
 * without firing the module-load side effects of the server entrypoint
 * (the `SIGNER_TOKEN` gate and the `listen()` IIFE).
 */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { LRUCache } from 'lru-cache';
import { decryptAtRest } from './key-at-rest.js';

/** 1 hour. Bounds post-rotation staleness — signing keys rotate on a
 *  90-day cadence, so 1h is two orders of magnitude tighter than the
 *  rotation interval without taxing the disk on the hot path. */
export const CACHE_TTL_MS = 60 * 60 * 1000;

/** 10,000 entries per cache. ~4 MB worst-case resident with PEM values;
 *  higher than any plausible org × rotation-history product. LRU cap
 *  floors the worst case if key churn spikes unexpectedly. */
export const CACHE_MAX = 10_000;

// Cache-internal types. Not exported — the factory's return type is
// inferred at the call site, so server.ts never names these shapes.
// Keeping them unexported means adjacent work streams (e.g. A4-M2 MAC
// session state on the signer) cannot pick them up by mistake.
interface CacheStats {
  hits: number;
  misses: number;
  evictionsTtl: number;
  evictionsLru: number;
}

function makeStats(): CacheStats {
  return { hits: 0, misses: 0, evictionsTtl: 0, evictionsLru: 0 };
}

export class SignerKeyError extends Error {
  constructor(public code: string, public status: number) {
    super(code);
  }
}

interface CachesSnapshot {
  caches: {
    slhdsa: {
      entries: number;
      hits: number;
      misses: number;
      evictions: { ttl: number; lru: number };
    };
    ecdsa: {
      entries: number;
      hits: number;
      misses: number;
      evictions: { ttl: number; lru: number };
    };
  };
  config: { ttlMs: number; max: number };
}

interface KeyCaches {
  keyCache: LRUCache<string, Buffer>;
  ecdsaKeyCache: LRUCache<string, string>;
  slhdsaStats: CacheStats;
  ecdsaStats: CacheStats;
  loadPrivateKey(keyId: string): Promise<Buffer>;
  loadEcdsaPem(keyId: string): Promise<string>;
  snapshot(): CachesSnapshot;
}

export function createKeyCaches(keysDir: string): KeyCaches {
  const slhdsaStats = makeStats();
  const ecdsaStats = makeStats();

  const keyCache = new LRUCache<string, Buffer>({
    max: CACHE_MAX,
    ttl: CACHE_TTL_MS,
    ttlAutopurge: false,
    dispose: (_value, _key, reason) => {
      // DisposeReason is 'evict' | 'set' | 'delete' | 'expire' | 'fetch'
      // (lru-cache@11, verified against dist/esm/index.d.ts). Only count
      // unsolicited removals — 'set' and 'delete' are caller-driven and
      // would produce misleading eviction metrics if counted.
      if (reason === 'evict') slhdsaStats.evictionsLru += 1;
      else if (reason === 'expire') slhdsaStats.evictionsTtl += 1;
    },
  });

  const ecdsaKeyCache = new LRUCache<string, string>({
    max: CACHE_MAX,
    ttl: CACHE_TTL_MS,
    ttlAutopurge: false,
    dispose: (_value, _key, reason) => {
      if (reason === 'evict') ecdsaStats.evictionsLru += 1;
      else if (reason === 'expire') ecdsaStats.evictionsTtl += 1;
    },
  });

  async function loadPrivateKey(keyId: string): Promise<Buffer> {
    const cached = keyCache.get(keyId);
    if (cached !== undefined) {
      slhdsaStats.hits += 1;
      return cached;
    }
    slhdsaStats.misses += 1;

    // Defend against path traversal: keyIds must look like UUIDs / hex
    // strings, not paths. Anything outside [a-zA-Z0-9._-] is rejected.
    if (!/^[a-zA-Z0-9._-]+$/.test(keyId)) {
      throw new SignerKeyError('invalid_key_id', 400);
    }

    const encPath = join(keysDir, `${keyId}.slhdsa.enc`);
    let envelope: string;
    try {
      envelope = await readFile(encPath, 'utf8');
    } catch {
      throw new SignerKeyError('key_not_found', 404);
    }

    let secret: Buffer;
    try {
      secret = decryptAtRest(envelope.trim());
    } catch {
      throw new SignerKeyError('key_corrupted', 500);
    }
    if (secret.length !== 64) {
      // SLH-DSA-SHA2-128s secret keys are exactly 64 bytes per FIPS 205.
      throw new SignerKeyError('key_corrupted', 500);
    }
    keyCache.set(keyId, secret);
    return secret;
  }

  async function loadEcdsaPem(keyId: string): Promise<string> {
    const cached = ecdsaKeyCache.get(keyId);
    if (cached !== undefined) {
      ecdsaStats.hits += 1;
      return cached;
    }
    ecdsaStats.misses += 1;

    if (!/^[a-zA-Z0-9._-]+$/.test(keyId)) {
      throw new SignerKeyError('invalid_key_id', 400);
    }

    const encPath = join(keysDir, `${keyId}.ecdsa.enc`);
    let envelope: string;
    try {
      envelope = await readFile(encPath, 'utf8');
    } catch {
      throw new SignerKeyError('key_not_found', 404);
    }

    let pem: string;
    try {
      pem = decryptAtRest(envelope.trim()).toString('utf8');
    } catch {
      throw new SignerKeyError('key_corrupted', 500);
    }
    if (!pem.includes('-----BEGIN')) {
      throw new SignerKeyError('key_corrupted', 500);
    }
    ecdsaKeyCache.set(keyId, pem);
    return pem;
  }

  function snapshot(): CachesSnapshot {
    return {
      caches: {
        slhdsa: {
          entries: keyCache.size,
          hits: slhdsaStats.hits,
          misses: slhdsaStats.misses,
          evictions: {
            ttl: slhdsaStats.evictionsTtl,
            lru: slhdsaStats.evictionsLru,
          },
        },
        ecdsa: {
          entries: ecdsaKeyCache.size,
          hits: ecdsaStats.hits,
          misses: ecdsaStats.misses,
          evictions: {
            ttl: ecdsaStats.evictionsTtl,
            lru: ecdsaStats.evictionsLru,
          },
        },
      },
      config: { ttlMs: CACHE_TTL_MS, max: CACHE_MAX },
    };
  }

  return {
    keyCache,
    ecdsaKeyCache,
    slhdsaStats,
    ecdsaStats,
    loadPrivateKey,
    loadEcdsaPem,
    snapshot,
  };
}
