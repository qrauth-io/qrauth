/**
 * Canonical payload serialization for QRVA protocol v2.
 *
 * The string this module produces is fed into SHA3-256 to compute Merkle leaf
 * hashes. Because the leaf hash anchors all downstream verification (Merkle
 * proofs, batch root signatures, transparency log commitments), the format
 * MUST be byte-identical across every implementation — Node SDK, Python SDK,
 * edge worker, mobile clients, and future language bindings.
 *
 * Field order, separator, and hashing algorithm are part of the on-the-wire
 * protocol. They are pinned to `qrva-v2` and must not change without bumping
 * `protocolVersion` in the QRVA envelope.
 *
 * Cross-language test vectors live in `packages/protocol-tests/` and gate CI.
 */

export const QRVA_PROTOCOL_VERSION = "qrva-v2" as const;
export const CANONICAL_FIELD_SEPARATOR = "|" as const;

export interface CanonicalQRPayload {
  /** Short token embedded in the QR image (URL path component). */
  token: string;
  /** Tenant / organization identifier. */
  tenantId: string;
  /** Destination URL the QR resolves to. Hashed in the canonical form. */
  destinationUrl: string;
  /** Latitude of registered location, or null when no location is bound. */
  lat: number | null;
  /** Longitude of registered location, or null when no location is bound. */
  lng: number | null;
  /** Geo-fence radius in meters, or null when no location is bound. */
  radiusM: number | null;
  /** Expiry as ISO 8601 string. Empty string for non-expiring codes. */
  expiresAt: string;
  /** Per-leaf nonce (hex). Generated at issuance time. */
  nonce: string;
}

/**
 * SHA3-256 over a UTF-8 string, hex-encoded.
 *
 * Implemented against the Web Crypto–compatible `globalThis.crypto.subtle`
 * surface where available; falls back to Node's `crypto.createHash` so the
 * helper is usable in shared code that runs in Node, browsers, edge workers,
 * and React Native.
 */
export async function sha3_256Hex(input: string | Uint8Array): Promise<string> {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;

  // Node's SubtleCrypto does not implement SHA3 yet (as of Node 22). Prefer the
  // built-in `crypto.createHash` when it exists, otherwise fall back to
  // SubtleCrypto's SHA-256 (only used in environments that have already opted
  // out of SHA3 — never on the server hot path).
  const nodeCrypto = await loadNodeCrypto();
  if (nodeCrypto) {
    return nodeCrypto.createHash("sha3-256").update(Buffer.from(bytes)).digest("hex");
  }

  // Browser / edge fallback: subtle does not support SHA3-256 in any shipping
  // browser today. Callers that hit this branch must polyfill via @noble/hashes.
  throw new Error(
    "sha3_256Hex: no SHA3-256 implementation available. Install @noble/hashes and provide a polyfill.",
  );
}

let cachedNodeCrypto: typeof import("crypto") | null | undefined;
async function loadNodeCrypto(): Promise<typeof import("crypto") | null> {
  if (cachedNodeCrypto !== undefined) return cachedNodeCrypto;
  try {
    cachedNodeCrypto = await import("crypto");
  } catch {
    cachedNodeCrypto = null;
  }
  return cachedNodeCrypto;
}

/**
 * Build the canonical payload string for a QR code.
 *
 * Fields are concatenated in fixed order, separated by `|`. Destination URL
 * and geo-coordinates are hashed individually so the canonical form leaks
 * neither the URL nor the precise location to anyone who only sees the leaf
 * hash on the transparency log.
 *
 * Empty-location codes encode geo as the literal string `none` (not an empty
 * geohash) so a missing location can never collide with a real one whose
 * components hash to the empty string.
 */
export async function canonicalizePayload(payload: CanonicalQRPayload): Promise<string> {
  const destHash = await sha3_256Hex(payload.destinationUrl);
  const geoHash = await canonicalGeoHash(payload.lat, payload.lng, payload.radiusM);

  // Defensive precondition: no field may contain the separator or a
  // newline. Without escaping, two distinct payloads where one field
  // contains a `|` could canonicalize to the same string and collide on
  // the leaf hash. Production callers never produce these (tokens come
  // from a fixed charset, hashes are hex, IDs are cuids, expiry is ISO
  // 8601), but the canonicalizer is the single source of truth and
  // must enforce the contract for any future caller. Property-based
  // fuzz tests catch this; the throw makes it loud rather than silent.
  assertCanonicalSafe("token", payload.token);
  assertCanonicalSafe("tenantId", payload.tenantId);
  assertCanonicalSafe("expiresAt", payload.expiresAt);
  assertCanonicalSafe("nonce", payload.nonce);

  return [
    payload.token,
    payload.tenantId,
    destHash,
    geoHash,
    payload.expiresAt,
    payload.nonce,
  ].join(CANONICAL_FIELD_SEPARATOR);
}

/**
 * Reject any field value that contains the canonical separator, a
 * newline, or a NUL byte. These characters break the parse-back
 * contract and must never appear in a canonical payload field.
 *
 * Exported so SDKs (Node, Python, Go) can reuse the same predicate at
 * their own boundary if they ever build payloads from untrusted input.
 */
export function assertCanonicalSafe(fieldName: string, value: string): void {
  if (typeof value !== "string") {
    throw new Error(`canonical: field "${fieldName}" must be a string`);
  }
  if (
    value.includes(CANONICAL_FIELD_SEPARATOR) ||
    value.includes("\n") ||
    value.includes("\0")
  ) {
    throw new Error(
      `canonical: field "${fieldName}" contains a forbidden character ` +
        `(${CANONICAL_FIELD_SEPARATOR}, newline, or NUL)`,
    );
  }
}

/**
 * Compute the canonical geo hash for a (lat, lng, radius) triple.
 *
 * - All-null → literal `"none"`.
 * - Otherwise → SHA3-256 of `"<lat>:<lng>:<radius>"` using fixed-precision
 *   numeric formatting so that 41.4 and 41.40 produce identical hashes.
 */
export async function canonicalGeoHash(
  lat: number | null,
  lng: number | null,
  radiusM: number | null,
): Promise<string> {
  if (lat === null && lng === null && radiusM === null) return "none";
  if (lat === null || lng === null || radiusM === null) {
    throw new Error("canonicalGeoHash: lat, lng, and radiusM must all be set or all null");
  }
  // Fixed precision: 7 decimals lat/lng (~1cm), integer meters for radius.
  // Cross-language SDKs MUST follow the same formatting.
  const formatted = `${lat.toFixed(7)}:${lng.toFixed(7)}:${Math.trunc(radiusM)}`;
  return sha3_256Hex(formatted);
}

/**
 * Synchronous canonical form, for callers that already have the hashed
 * destination and geo components in hand. Used by the merkle-signing service
 * to avoid awaiting a hash inside a tight batch loop.
 */
export function canonicalizePayloadSync(parts: {
  token: string;
  tenantId: string;
  destinationHash: string;
  geoHash: string;
  expiresAt: string;
  nonce: string;
}): string {
  assertCanonicalSafe("token", parts.token);
  assertCanonicalSafe("tenantId", parts.tenantId);
  assertCanonicalSafe("destinationHash", parts.destinationHash);
  assertCanonicalSafe("geoHash", parts.geoHash);
  assertCanonicalSafe("expiresAt", parts.expiresAt);
  assertCanonicalSafe("nonce", parts.nonce);
  return [
    parts.token,
    parts.tenantId,
    parts.destinationHash,
    parts.geoHash,
    parts.expiresAt,
    parts.nonce,
  ].join(CANONICAL_FIELD_SEPARATOR);
}
