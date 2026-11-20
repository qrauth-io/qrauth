/**
 * Byte helpers shared by tree construction and verification.
 */

/**
 * Compare two byte arrays without an early exit on the first differing
 * byte. Lengths are not secret here (every hash has the hasher's fixed
 * size), so a length mismatch returns false immediately.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * True for a tree size or leaf index this library accepts: a non-negative
 * integer that a JavaScript number represents exactly (below 2^53).
 */
export function isIndex(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

/** Floor division by two: a right shift that stays exact above 2^32. */
export function half(value: number): number {
  return Math.floor(value / 2);
}

export function isOdd(value: number): boolean {
  return value % 2 === 1;
}

/** Exact for every safe integer (no 32-bit bitwise operators). */
export function isPowerOfTwo(value: number): boolean {
  if (!isIndex(value) || value === 0) return false;
  let k = 1;
  while (k < value) k *= 2;
  return k === value;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
