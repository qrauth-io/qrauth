import type { FastifyInstance, FastifyRequest } from 'fastify';
import { isIPv6 } from 'node:net';
import { hashString } from './crypto.js';

/**
 * Keys for the rate limiter.
 *
 * The limiter runs at `onRequest`, before `authenticate`, so `request.user`
 * is not set yet. Organization tiers therefore work out the principal here:
 * a bearer token whose signature verifies, or an API key that exists and is
 * not revoked, is counted against its organization; anything else is counted
 * against the caller's network. `authenticate` still makes the access
 * decision afterwards; this only chooses a bucket.
 */

const IPV4_MAPPED_PREFIX = '::ffff:';
const IPV6_NETWORK_HEXTETS = 4;

/** Full eight-group form of an IPv6 address, lower case, no zero compression. */
function expandIpv6(address: string): string[] {
  const [head, tail] = address.toLowerCase().split('::');
  const headGroups = head ? head.split(':') : [];
  const tailGroups = tail ? tail.split(':') : [];
  const missing = Math.max(0, 8 - headGroups.length - tailGroups.length);
  const groups = tail === undefined ? headGroups : [...headGroups, ...Array<string>(missing).fill('0'), ...tailGroups];
  return groups.map((group) => group.replace(/^0+(?=.)/, ''));
}

/**
 * One key per client network: the address itself for IPv4, the /64 for IPv6
 * (a single subscriber normally holds a whole /64 and can rotate within it).
 */
export function networkKey(ip: string): string {
  const withoutZone = ip.split('%')[0];
  if (withoutZone.toLowerCase().startsWith(IPV4_MAPPED_PREFIX) && withoutZone.includes('.')) {
    return withoutZone.slice(IPV4_MAPPED_PREFIX.length);
  }
  if (!isIPv6(withoutZone)) return withoutZone;
  return `${expandIpv6(withoutZone).slice(0, IPV6_NETWORK_HEXTETS).join(':')}::/64`;
}

// --- API key → organization, remembered briefly ----------------------------

/** Loose bound on what an API key can look like (`qrauth_` + 64 hex today). */
const API_KEY_SHAPE = /^[A-Za-z0-9_.-]{16,128}$/;
const API_KEY_CACHE_TTL_MS = 30_000;
const API_KEY_CACHE_MAX_ENTRIES = 5_000;

interface CachedOrg {
  /** Null when the key is unknown or revoked. */
  orgId: string | null;
  expiresAt: number;
}

const apiKeyOrgs = new Map<string, CachedOrg>();

async function orgOfApiKey(fastify: FastifyInstance, rawApiKey: string): Promise<string | null> {
  // Not shaped like anything this API issues: no lookup, no cache entry.
  if (!API_KEY_SHAPE.test(rawApiKey)) return null;
  const keyHash = hashString(rawApiKey);
  const now = Date.now();
  const cached = apiKeyOrgs.get(keyHash);
  if (cached && cached.expiresAt > now) return cached.orgId;

  const apiKey = await fastify.prisma.apiKey.findUnique({
    where: { keyHash },
    select: { organizationId: true, revokedAt: true },
  });
  const orgId = apiKey && apiKey.revokedAt === null ? apiKey.organizationId : null;
  // Bounded: at the cap, the oldest entry makes room (a Map iterates in
  // insertion order).
  if (!apiKeyOrgs.has(keyHash) && apiKeyOrgs.size >= API_KEY_CACHE_MAX_ENTRIES) {
    const oldest = apiKeyOrgs.keys().next();
    if (!oldest.done) apiKeyOrgs.delete(oldest.value);
  }
  apiKeyOrgs.set(keyHash, { orgId, expiresAt: now + API_KEY_CACHE_TTL_MS });
  return orgId;
}

function orgOfBearer(fastify: FastifyInstance, authorization: string): string | null {
  try {
    const payload = fastify.jwt.verify<{ orgId?: unknown }>(authorization.slice('Bearer '.length));
    return typeof payload.orgId === 'string' && payload.orgId.length > 0 ? payload.orgId : null;
  } catch {
    return null;
  }
}

/**
 * Bucket for an organization tier: `org:<id>` for a verified principal,
 * otherwise the caller's network. Never throws; a lookup failure falls back
 * to the network key.
 */
export async function principalKey(fastify: FastifyInstance, request: FastifyRequest): Promise<string> {
  const { authorization } = request.headers;
  const rawApiKey = request.headers['x-api-key'];
  try {
    if (authorization?.startsWith('Bearer ')) {
      const orgId = orgOfBearer(fastify, authorization);
      if (orgId) return `org:${orgId}`;
    } else if (typeof rawApiKey === 'string' && rawApiKey.length > 0) {
      const orgId = await orgOfApiKey(fastify, rawApiKey);
      if (orgId) return `org:${orgId}`;
    }
  } catch (err) {
    request.log.warn({ err, event: 'rate_limit.principal_lookup_failed' }, 'rate limiter could not resolve the principal; using the network key');
  }
  return networkKey(request.ip);
}
