import { createHmac } from 'node:crypto';

import { config } from './config.js';

/**
 * Keyed hash of a client IP address: HMAC-SHA256 under the server secret
 * IP_HASH_KEY, hex, with a version prefix. The same IP gives the same hash
 * under one key, so per-IP signals (scan limits, velocity, clustering)
 * keep working; without the key the hash cannot be recomputed from a
 * candidate IP. The prefix tells these hashes apart from the unkeyed
 * SHA-256 values in older rows, which age out with retention.
 *
 * Used for every stored or compared client IP hash: scans, auth-session
 * approvals, feedback submissions, abuse reports.
 */
export const IP_HASH_PREFIX = 'k1:';

/** The stored form: prefix + 64 hex characters. */
export const IP_HASH_PATTERN = /^k1:[0-9a-f]{64}$/;

const UNKNOWN_IP = 'unknown';

export function keyedHash(key: string, ip: string): string {
  return IP_HASH_PREFIX + createHmac('sha256', key).update(ip, 'utf8').digest('hex');
}

export function hashIp(ip: string | undefined | null): string {
  return keyedHash(config.ipHash.key, ip || UNKNOWN_IP);
}
