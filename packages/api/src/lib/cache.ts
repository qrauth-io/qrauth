import { Redis } from 'ioredis';
import { config } from './config.js';

const KEY_PREFIX = 'vqr:';

function createRedisClient(): Redis {
  const client = new Redis(config.redis.url, {
    // Reconnect with exponential backoff, cap at 30 s.
    retryStrategy(times: number) {
      const delay = Math.min(times * 100, 30_000);
      return delay;
    },
    // Surface connection errors instead of silently swallowing them.
    lazyConnect: false,
    enableReadyCheck: true,
    maxRetriesPerRequest: 3,
  });

  client.on('error', (err: Error) => {
    console.error('[redis] connection error:', err.message);
  });

  client.on('ready', () => {
    if (config.server.isDev) {
      console.info('[redis] connected');
    }
  });

  return client;
}

export const redis = createRedisClient();

function prefixed(key: string): string {
  return `${KEY_PREFIX}${key}`;
}

/**
 * Retrieve a cached value by key.
 * Returns null when the key is absent or the stored JSON is unparseable.
 */
export async function cacheGet<T>(key: string): Promise<T | null> {
  const raw = await redis.get(prefixed(key));
  if (raw === null) return null;

  try {
    return JSON.parse(raw) as T;
  } catch {
    // Corrupted or non-JSON value – treat as a cache miss.
    return null;
  }
}

/**
 * Store a value under key with a TTL in seconds.
 * The value is serialised to JSON before storage.
 */
export async function cacheSet(
  key: string,
  value: unknown,
  ttlSeconds: number,
): Promise<void> {
  await redis.set(prefixed(key), JSON.stringify(value), 'EX', ttlSeconds);
}

/**
 * Delete a cached key. No-op if the key does not exist.
 */
export async function cacheDel(key: string): Promise<void> {
  await redis.del(prefixed(key));
}

export async function disconnectCache(): Promise<void> {
  await redis.quit();
}
