/**
 * Constant-time equality helpers (AUDIT-FINDING-002, AUDIT-FINDING-012).
 *
 * `===` on signatures, MAC tags, hashes, verifiers, and challenges is a
 * timing-oracle contract violation in this codebase. Always route those
 * comparisons through `constantTimeEqualString`, which wraps
 * `crypto.timingSafeEqual` with a length guard and buffer coercion.
 *
 * The guard is required because `crypto.timingSafeEqual` throws when the
 * buffers differ in length. That throw is itself timing-dependent (string
 * length comparison is cheap and constant-time on V8 for normal strings),
 * but to avoid exposing the length check as a side channel we short-circuit
 * on mismatch without calling the underlying primitive.
 */
import { timingSafeEqual } from 'node:crypto';

/**
 * Constant-time equality for two strings of the same expected length.
 *
 * Returns `false` immediately on length mismatch — callers should treat
 * values of different lengths as different values, not as a timing leak.
 * Otherwise delegates to `crypto.timingSafeEqual` over UTF-8 buffers.
 */
export function constantTimeEqualString(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  const ba = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}
