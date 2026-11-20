import { createHash } from 'node:crypto';
import { z } from 'zod';
import { cacheGet, cacheIncr, cacheSetIfAbsent } from '../lib/cache.js';
import { constantTimeEqualString } from '../lib/constant-time.js';

/**
 * Living Codes frame-secret possession proof and secret generations.
 *
 * A public (browser) client registers `frameChallenge = base64url(SHA-256(frameVerifier))`
 * when it creates the animated session, and receives the frame secret only by
 * presenting `frameVerifier` in a POST body. The challenge is set once per auth
 * session; a different challenge for the same session is refused.
 *
 * Every issuance of a frame secret starts a new generation. The per-session key
 * is derived from `<authSessionId>_g<generation>`, and verification uses only the
 * current generation, so frames signed with an earlier secret no longer verify.
 */

/** base64url of 32 bytes, no padding. */
export const frameChallengeSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/, 'frameChallenge must be base64url(SHA-256(frameVerifier))');

/** RFC 7636 code-verifier alphabet and length. */
export const frameVerifierSchema = z.string().regex(/^[A-Za-z0-9._~-]{43,128}$/, 'frameVerifier must be 43-128 characters of [A-Za-z0-9._~-]');

/** Query-string names a verifier must never arrive under. */
export const VERIFIER_QUERY_KEYS = ['frameVerifier', 'frame_verifier'] as const;

const challengeKey = (authSessionId: string) => `animated_qr:frame_challenge:${authSessionId}`;
const generationKey = (authSessionId: string) => `animated_qr:generation:${authSessionId}`;

/** Upper bound for every key here; animated sessions live at most 10 minutes. */
export const FRAME_STATE_TTL_SECONDS = 600;

export function challengeForVerifier(verifier: string): string {
  return createHash('sha256').update(verifier, 'ascii').digest('base64url');
}

/**
 * Register the challenge for an auth session, once.
 * 'stored' — this call stored it; 'same' — an identical challenge was already
 * stored; 'conflict' — a different challenge is already registered.
 */
export async function registerFrameChallenge(
  authSessionId: string,
  challenge: string,
  ttlSeconds: number,
): Promise<'stored' | 'same' | 'conflict'> {
  const ttl = Math.max(1, Math.min(FRAME_STATE_TTL_SECONDS, Math.floor(ttlSeconds)));
  if (await cacheSetIfAbsent(challengeKey(authSessionId), challenge, ttl)) return 'stored';
  const existing = await cacheGet<string>(challengeKey(authSessionId));
  return typeof existing === 'string' && constantTimeEqualString(existing, challenge) ? 'same' : 'conflict';
}

/**
 * Compare a presented challenge with the registered one. Never stores.
 * 'none' when the session has no registered challenge.
 */
export async function matchFrameChallenge(
  authSessionId: string,
  challenge: string,
): Promise<'same' | 'conflict' | 'none'> {
  const stored = await cacheGet<string>(challengeKey(authSessionId));
  if (typeof stored !== 'string') return 'none';
  return constantTimeEqualString(stored, challenge) ? 'same' : 'conflict';
}

/** Whether a challenge is registered for the session. */
export async function hasFrameChallenge(authSessionId: string): Promise<boolean> {
  return typeof (await cacheGet<string>(challengeKey(authSessionId))) === 'string';
}

/** Per-auth-session cap on secret-release attempts, per minute. */
export const SECRET_ATTEMPTS_PER_MINUTE = 10;

/** Count one secret-release attempt for the session; returns the count in the current minute. */
export async function countSecretAttempt(authSessionId: string): Promise<number> {
  return cacheIncr(`animated_qr:secret_attempts:${authSessionId}`, 60);
}

/**
 * Check a presented verifier against the registered challenge.
 * 'no_challenge' when the session has none (the public path cannot be used).
 */
export async function checkFrameVerifier(
  authSessionId: string,
  verifier: string,
): Promise<'ok' | 'mismatch' | 'no_challenge'> {
  const stored = await cacheGet<string>(challengeKey(authSessionId));
  if (typeof stored !== 'string') return 'no_challenge';
  return constantTimeEqualString(challengeForVerifier(verifier), stored) ? 'ok' : 'mismatch';
}

/** Start the next secret generation and return its number (1, 2, ...). */
export async function nextFrameGeneration(authSessionId: string): Promise<number> {
  return cacheIncr(generationKey(authSessionId), FRAME_STATE_TTL_SECONDS);
}

/**
 * Current generation, or 0 when no secret has been issued under generations
 * (sessions created before generations existed).
 */
export async function currentFrameGeneration(authSessionId: string): Promise<number> {
  const value = await cacheGet<number>(generationKey(authSessionId));
  return typeof value === 'number' && Number.isInteger(value) && value > 0 ? value : 0;
}

/** Key-derivation and signer session id for a generation. Generation 0 is the bare id. */
export function frameKeyId(authSessionId: string, generation: number): string {
  return generation > 0 ? `${authSessionId}_g${generation}` : authSessionId;
}
