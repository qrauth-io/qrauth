import type { FastifyBaseLogger } from 'fastify';
import type { Redis } from 'ioredis';
import { createRequire } from 'node:module';

/**
 * The rate limiter's Redis store, with one addition: when Redis fails, say
 * so. @fastify/rate-limit either lets the request through or rejects it
 * (per route, `skipOnError`) but reports nothing, so an outage that switches
 * most limits off would otherwise be invisible.
 *
 * Logged at warn at most once a minute, with the number of failures since
 * the previous line; `rateLimitStoreFailures()` is the running total for
 * /health or a metrics scrape.
 */

interface IncrResult {
  current: number;
  ttl: number;
}
type IncrCallback = (err: Error | null, result: IncrResult | null) => void;

interface PluginRedisStore {
  incr(key: string, cb: IncrCallback, timeWindow: number, max: number): void;
}
type PluginRedisStoreCtor = new (
  continueExceeding: boolean,
  exponentialBackoff: boolean,
  redis: Redis,
  key: string,
) => PluginRedisStore;

// The plugin ships its store as an internal CommonJS module with no types.
const BaseRedisStore = createRequire(import.meta.url)('@fastify/rate-limit/store/RedisStore') as PluginRedisStoreCtor;

const NAMESPACE = 'qrauth:rl:';
const LOG_INTERVAL_MS = 60_000;

interface StoreOptions {
  continueExceeding?: boolean;
  exponentialBackoff?: boolean;
  routeInfo?: { method: string; url: string };
}

let redisClient: Redis | null = null;
let logger: FastifyBaseLogger | null = null;
let totalFailures = 0;
let failuresSinceLastLog = 0;
let lastLogAt = 0;

/** Total limiter store failures since the process started. */
export function rateLimitStoreFailures(): number {
  return totalFailures;
}

function reportFailure(err: Error): void {
  totalFailures += 1;
  const now = Date.now();
  if (now - lastLogAt < LOG_INTERVAL_MS) {
    failuresSinceLastLog += 1;
    return;
  }
  logger?.warn(
    { err, event: 'rate_limit.store_unavailable', failuresSinceLastLog, totalFailures },
    'rate limiter cannot reach Redis: limits are off for most routes, authentication routes are refused',
  );
  lastLogAt = now;
  failuresSinceLastLog = 0;
}

/** Marks the error a fail-closed route gets while the store is down. */
export const RATE_LIMIT_STORE_UNAVAILABLE = 'RATE_LIMIT_STORE_UNAVAILABLE';
export const STORE_UNAVAILABLE_RETRY_AFTER_SECONDS = 30;

export function isRateLimitStoreUnavailable(error: unknown): boolean {
  return (error as { code?: unknown } | null)?.code === RATE_LIMIT_STORE_UNAVAILABLE;
}

function unavailable(): Error {
  return Object.assign(new Error('Service temporarily unavailable. Try again shortly.'), {
    statusCode: 503,
    code: RATE_LIMIT_STORE_UNAVAILABLE,
  });
}

export class RateLimitRedisStore {
  private readonly inner: PluginRedisStore;
  private readonly prefix: string;

  /** Must be called before the plugin constructs the store. */
  static configure(deps: { redis: Redis; log: FastifyBaseLogger }): void {
    redisClient = deps.redis;
    logger = deps.log;
    totalFailures = 0;
    failuresSinceLastLog = 0;
    lastLogAt = 0;
  }

  constructor(options: StoreOptions, prefix: string = NAMESPACE) {
    if (!redisClient) throw new Error('RateLimitRedisStore.configure() was not called');
    this.prefix = prefix;
    this.inner = new BaseRedisStore(
      options.continueExceeding ?? false,
      options.exponentialBackoff ?? false,
      redisClient,
      prefix,
    );
  }

  incr(key: string, cb: IncrCallback, timeWindow: number, max: number): void {
    const onResult: IncrCallback = (err, result) => {
      if (!err) return cb(null, result);
      reportFailure(err);
      cb(unavailable(), null);
    };
    try {
      this.inner.incr(key, onResult, timeWindow, max);
    } catch (err) {
      onResult(err instanceof Error ? err : new Error(String(err)), null);
    }
  }

  /** One key space per route, as the plugin's own store does. */
  child(routeOptions: StoreOptions): RateLimitRedisStore {
    const route = routeOptions.routeInfo;
    return new RateLimitRedisStore(routeOptions, route ? `${this.prefix}${route.method}${route.url}-` : this.prefix);
  }
}
