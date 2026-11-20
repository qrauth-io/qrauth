import { createHash } from 'node:crypto';
import { redis } from './cache.js';
import { config } from './config.js';

/**
 * Google Web Risk Lookup API (uris.search) for QR destinations.
 * https://cloud.google.com/web-risk/docs/lookup-api
 *
 * Verdicts are cached in Redis under a hash of the normalized URL. A threat
 * match is cached until the API's expireTime (clamped to 1 minute–24 hours);
 * a clean result carries no expiry, so it is cached for 30 minutes.
 */

const SEARCH_URL = 'https://webrisk.googleapis.com/v1/uris:search';
export const WEB_RISK_THREAT_TYPES = ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'] as const;
export const WEB_RISK_TIMEOUT_MS = 2_000;

const CACHE_PREFIX = 'qrauth:webrisk:';
const CLEAN_TTL_SECONDS = 30 * 60;
const MIN_HIT_TTL_SECONDS = 60;
const MAX_HIT_TTL_SECONDS = 24 * 60 * 60;

export type WebRiskVerdict =
  | { verdict: 'flagged'; threatTypes: string[] }
  | { verdict: 'clean' }
  /** Web Risk is not configured (WEB_RISK_API_KEY unset). */
  | { verdict: 'skipped' }
  /** The API could not be reached in time or answered unexpectedly. */
  | { verdict: 'unavailable'; detail: string };

/**
 * Canonical form used for the cache key: lowercase scheme and host, no
 * fragment, no default port. Returns null for anything that is not http(s).
 */
export function normalizeDestination(url: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
  parsed.hash = '';
  // URL already lowercases scheme and host and drops default ports.
  return parsed.href;
}

export function destinationCacheKey(normalized: string): string {
  return CACHE_PREFIX + createHash('sha256').update(normalized).digest('hex');
}

type CachedVerdict = { threatTypes: string[] };

async function readCache(key: string): Promise<WebRiskVerdict | null> {
  try {
    const raw = await redis.get(key);
    if (!raw) return null;
    const cached = JSON.parse(raw) as CachedVerdict;
    return cached.threatTypes.length > 0 ? { verdict: 'flagged', threatTypes: cached.threatTypes } : { verdict: 'clean' };
  } catch {
    return null; // a cache problem only costs a lookup
  }
}

async function writeCache(key: string, value: CachedVerdict, ttlSeconds: number): Promise<void> {
  try {
    await redis.set(key, JSON.stringify(value), 'EX', ttlSeconds);
  } catch {
    // best effort
  }
}

function hitTtlSeconds(expireTime: unknown, now: number): number {
  const expires = typeof expireTime === 'string' ? Date.parse(expireTime) : NaN;
  if (!Number.isFinite(expires)) return MIN_HIT_TTL_SECONDS;
  const seconds = Math.floor((expires - now) / 1000);
  return Math.min(MAX_HIT_TTL_SECONDS, Math.max(MIN_HIT_TTL_SECONDS, seconds));
}

export interface LookupOptions {
  fetchImpl?: typeof fetch;
  apiKey?: string | null;
  now?: () => number;
}

/** Looks a destination up (cache first). Never throws. */
export async function lookupDestination(url: string, opts: LookupOptions = {}): Promise<WebRiskVerdict> {
  const apiKey = opts.apiKey === undefined ? config.webRisk.apiKey : opts.apiKey;
  if (!apiKey) return { verdict: 'skipped' };
  const normalized = normalizeDestination(url);
  if (!normalized) return { verdict: 'clean' }; // only http(s) destinations are screened

  const key = destinationCacheKey(normalized);
  const cached = await readCache(key);
  if (cached) return cached;

  const query = new URLSearchParams({ key: apiKey, uri: normalized });
  for (const t of WEB_RISK_THREAT_TYPES) query.append('threatTypes', t);

  let res: Response;
  try {
    res = await (opts.fetchImpl ?? fetch)(`${SEARCH_URL}?${query.toString()}`, {
      signal: AbortSignal.timeout(WEB_RISK_TIMEOUT_MS),
    });
  } catch (err) {
    return { verdict: 'unavailable', detail: err instanceof Error ? err.name : 'network error' };
  }
  if (!res.ok) return { verdict: 'unavailable', detail: `HTTP ${res.status}` };

  let body: { threat?: { threatTypes?: unknown; expireTime?: unknown } };
  try {
    body = (await res.json()) as typeof body;
  } catch {
    return { verdict: 'unavailable', detail: 'non-JSON response' };
  }

  const threatTypes = Array.isArray(body.threat?.threatTypes) ? body.threat!.threatTypes.map(String) : [];
  if (threatTypes.length > 0) {
    const now = (opts.now ?? Date.now)();
    await writeCache(key, { threatTypes }, hitTtlSeconds(body.threat?.expireTime, now));
    return { verdict: 'flagged', threatTypes };
  }
  await writeCache(key, { threatTypes: [] }, CLEAN_TTL_SECONDS);
  return { verdict: 'clean' };
}
