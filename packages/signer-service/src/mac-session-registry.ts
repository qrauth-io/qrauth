/**
 * In-process registry for animated-QR MAC sessions (Audit-4 A4-M2,
 * Phase 0).
 *
 * The signer derives a 32-byte frame secret via HKDF on `POST
 * /v1/mac/session` and stores it here keyed by `sessionId`. Per-frame
 * `POST /v1/mac/sign` and `POST /v1/mac/verify` calls look up the
 * stored key and compute HMAC-SHA256 without ever returning the secret
 * to the API. This is the Phase 0 surface — endpoints exist and are
 * tested but production traffic still runs the API-local HMAC path
 * until Phase 1 flips the flag (see ADR-0001).
 *
 * Why a plain Map, not `lru-cache`:
 *   - TTL is authoritative. An entry past `expiresAtMs` MUST read as
 *     absent, not merely de-prioritized by recency. LRU eviction is
 *     the wrong primitive.
 *   - Capacity is small. 100k sessions × ~100 B (key + binding + epoch)
 *     ≈ <10 MB; a Map handles this trivially without the overhead of
 *     LRU bookkeeping.
 *   - Eviction reason is always `expired`. LRU would add an unreachable
 *     `evicted` reason to the observability surface.
 *
 * Capacity guard: `maxEntries` defends against a compromised API
 * bearer token spraying `register()` calls. `register` returns
 * `{ ok: false, reason: 'full' }` when the cap is hit — the HTTP layer
 * translates this to 503 `registry_full`.
 *
 * Sweeper: a `setInterval` removes expired entries proactively so the
 * Map doesn't stay inflated after a burst of short-lived sessions. The
 * lazy expiry check in `get()` is the authoritative source — the sweep
 * is a cleanup optimization, not a correctness mechanism.
 */

export interface MacSessionEntry {
  key: Buffer;
  binding: string;
  expiresAtMs: number;
}

export interface MacSessionStats {
  /** Total successful `register()` calls, including idempotent replays. */
  registered: number;
  /** Total entries dropped via lazy or sweeper eviction. */
  expired: number;
  /** Total `register()` calls rejected because the cap was hit. */
  evictedFull: number;
  /** Total `register()` calls rejected because (binding, ttlSeconds)
   *  disagreed with an existing sessionId. */
  conflicts: number;
}

export interface MacSessionRegistry {
  register(
    sessionId: string,
    binding: string,
    ttlSeconds: number,
    key: Buffer,
  ): { ok: true; expiresAtMs: number } | { ok: false; reason: 'conflict' | 'full' };
  get(sessionId: string): MacSessionEntry | null;
  delete(sessionId: string): boolean;
  size(): number;
  stats(): MacSessionStats;
  startSweeper(): void;
  stopSweeper(): void;
}

export interface CreateMacSessionRegistryOptions {
  maxEntries?: number;
  sweepIntervalMs?: number;
  /** Injected time source. Lets tests advance "now" without touching
   *  global timers. Defaults to `Date.now`. */
  now?: () => number;
}

const DEFAULT_MAX_ENTRIES = 100_000;
const DEFAULT_SWEEP_INTERVAL_MS = 60_000;
const MIN_SWEEP_INTERVAL_MS = 5_000;

export function createMacSessionRegistry(
  opts: CreateMacSessionRegistryOptions = {},
): MacSessionRegistry {
  const maxEntries = opts.maxEntries ?? DEFAULT_MAX_ENTRIES;
  const rawSweepInterval = opts.sweepIntervalMs ?? DEFAULT_SWEEP_INTERVAL_MS;
  const sweepIntervalMs = Math.max(rawSweepInterval, MIN_SWEEP_INTERVAL_MS);
  const now = opts.now ?? Date.now;

  const entries = new Map<string, MacSessionEntry>();
  const counters: MacSessionStats = {
    registered: 0,
    expired: 0,
    evictedFull: 0,
    conflicts: 0,
  };
  let sweeper: NodeJS.Timeout | null = null;

  function dropIfExpired(sessionId: string, entry: MacSessionEntry): boolean {
    if (entry.expiresAtMs <= now()) {
      entries.delete(sessionId);
      counters.expired += 1;
      return true;
    }
    return false;
  }

  return {
    register(sessionId, binding, ttlSeconds, key) {
      const existing = entries.get(sessionId);
      if (existing && !dropIfExpired(sessionId, existing)) {
        // Idempotent on exact match: same binding AND same remaining
        // TTL bucket (the absolute expiresAtMs is what the caller is
        // asserting equivalence over).
        const expectedExpiresAtMs = now() + ttlSeconds * 1000;
        const ttlMatches =
          Math.abs(existing.expiresAtMs - expectedExpiresAtMs) <= 1_000;
        if (existing.binding === binding && ttlMatches) {
          counters.registered += 1;
          return { ok: true, expiresAtMs: existing.expiresAtMs };
        }
        counters.conflicts += 1;
        return { ok: false, reason: 'conflict' };
      }

      if (entries.size >= maxEntries) {
        counters.evictedFull += 1;
        return { ok: false, reason: 'full' };
      }

      const expiresAtMs = now() + ttlSeconds * 1000;
      entries.set(sessionId, { key, binding, expiresAtMs });
      counters.registered += 1;
      return { ok: true, expiresAtMs };
    },

    get(sessionId) {
      const entry = entries.get(sessionId);
      if (!entry) return null;
      if (dropIfExpired(sessionId, entry)) return null;
      return entry;
    },

    delete(sessionId) {
      return entries.delete(sessionId);
    },

    size() {
      return entries.size;
    },

    stats() {
      return { ...counters };
    },

    startSweeper() {
      if (sweeper) return;
      sweeper = setInterval(() => {
        const threshold = now();
        for (const [sessionId, entry] of entries) {
          if (entry.expiresAtMs <= threshold) {
            entries.delete(sessionId);
            counters.expired += 1;
          }
        }
      }, sweepIntervalMs);
      // Don't keep the Node process alive just for the sweeper.
      if (typeof sweeper.unref === 'function') sweeper.unref();
    },

    stopSweeper() {
      if (!sweeper) return;
      clearInterval(sweeper);
      sweeper = null;
    },
  };
}
