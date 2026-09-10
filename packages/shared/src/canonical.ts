/**
 * Unified canonical payload serialization for QRVA protocol v2
 * (AUDIT-FINDING-011/019/020/021).
 *
 * The same canonical string is fed into:
 *   - HMAC-SHA3-256 for the MAC leg
 *   - ECDSA-P256 signing for the classical leg
 *   - SHA3-256 (with a 0x00 leaf-prefix) for the Merkle leaf hash
 *
 * Because these three legs now agree byte-for-byte on the input, a divergence
 * bug in any one implementation shows up immediately as a signature mismatch
 * across all three. That is the safety property the unification buys.
 *
 * Cross-language test vectors live in `packages/protocol-tests/` and gate CI.
 *
 * Core form (6 fields, pipe-separated, fixed order):
 *
 *     algVersion | token | tenantId | destHash | geoHash | expiresAt
 *
 * Merkle leaf form (core + nonce, 7 fields):
 *
 *     algVersion | token | tenantId | destHash | geoHash | expiresAt | nonce
 *
 * Sentinels:
 *   - `expiresAt` uses the empty string (`''`) for non-expiring codes.
 *   - `geoHash` uses the literal string `"none"` when no location is bound.
 *   - `destHash` is SHA3-256 hex of the content-type-aware destination
 *     commitment — see `computeDestHash`.
 */

export const QRVA_PROTOCOL_VERSION = "qrva-v2" as const;
export const CANONICAL_FIELD_SEPARATOR = "|" as const;

/**
 * Minimum fields every signed, MAC'd, or logged payload commits to. Extending
 * this interface requires a protocol version bump and regenerated cross-SDK
 * test vectors — the on-wire bytes are part of the public contract.
 */
export interface CanonicalCore {
  /** Algorithm version string (e.g. `hybrid-ecdsa-slhdsa-v1`). */
  algVersion: string;
  /** Short token embedded in the QR image (URL path component). */
  token: string;
  /** Tenant / organization identifier. */
  tenantId: string;
  /** SHA3-256 hex of the content-type-aware destination commitment. */
  destHash: string;
  /** `canonicalGeoHash(lat, lng, radiusM)` result; `"none"` when unbound. */
  geoHash: string;
  /** ISO 8601 string, or `''` for non-expiring codes. */
  expiresAt: string;
}

/** Merkle leaf form — core fields plus a per-leaf nonce. */
export interface CanonicalMerkleLeaf extends CanonicalCore {
  /** Hex-encoded per-leaf nonce generated at issuance time. */
  nonce: string;
}

/**
 * SHA3-256 over a UTF-8 string or byte buffer, hex-encoded.
 *
 * Implemented against Node's `crypto.createHash` where available. Subtle-only
 * environments (browsers, Cloudflare Workers) must polyfill via `@noble/hashes`
 * — Web Crypto does not ship SHA3 in any current engine.
 */
export async function sha3_256Hex(input: string | Uint8Array): Promise<string> {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  const nodeCrypto = await loadNodeCrypto();
  if (nodeCrypto) {
    return nodeCrypto.createHash("sha3-256").update(Buffer.from(bytes)).digest("hex");
  }
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
 * Reject any field value that contains the canonical separator, a newline,
 * or a NUL byte. These characters break the parse-back contract and must
 * never appear in a canonical payload field.
 *
 * Exported so SDKs can reuse the same predicate at their own boundary if
 * they ever build payloads from untrusted input.
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
 * Build the canonical core string — the payload every signing / MAC leg
 * binds to. Inputs must already be hashed (`destHash`, `geoHash`).
 *
 * Deterministic: pure string concatenation, no async dependencies. Both the
 * issuer and the verifier call this with identical inputs and compare byte
 * strings.
 */
export function canonicalizeCore(parts: CanonicalCore): string {
  assertCanonicalSafe("algVersion", parts.algVersion);
  assertCanonicalSafe("token", parts.token);
  assertCanonicalSafe("tenantId", parts.tenantId);
  assertCanonicalSafe("destHash", parts.destHash);
  assertCanonicalSafe("geoHash", parts.geoHash);
  assertCanonicalSafe("expiresAt", parts.expiresAt);
  return [
    parts.algVersion,
    parts.token,
    parts.tenantId,
    parts.destHash,
    parts.geoHash,
    parts.expiresAt,
  ].join(CANONICAL_FIELD_SEPARATOR);
}

/**
 * Build the canonical Merkle leaf string — the core form with a per-leaf
 * nonce appended. Used only by the Merkle/SLH-DSA leg. The per-leaf nonce
 * keeps leaves distinguishable even when two QRs share the same core
 * payload (e.g. batch re-issuance), which closes second-preimage attacks
 * on the Merkle tree.
 */
export function canonicalizeMerkleLeaf(parts: CanonicalMerkleLeaf): string {
  assertCanonicalSafe("nonce", parts.nonce);
  return canonicalizeCore(parts) + CANONICAL_FIELD_SEPARATOR + parts.nonce;
}

/**
 * Compute the canonical geo hash for a (lat, lng, radius) triple.
 *
 * - Null lat or lng → literal `"none"` (regardless of `radiusM`).
 * - Otherwise → SHA3-256 of `"<lat>:<lng>:<radius>"` using fixed-precision
 *   numeric formatting so that 41.4 and 41.40 produce identical hashes.
 */
export async function canonicalGeoHash(
  lat: number | null,
  lng: number | null,
  radiusM: number | null,
): Promise<string> {
  // Radius without a bound location has no meaning — treat any row with a
  // null lat or lng as "no location", regardless of what `radiusM` carries.
  // The schema has a historical radiusM default of 50, which would otherwise
  // trip the partial-set check on legitimately-unbound rows.
  if (lat === null || lng === null) return "none";
  if (radiusM === null) {
    throw new Error("canonicalGeoHash: radiusM must be set when lat/lng are set");
  }
  // Fixed precision: 7 decimals lat/lng (~1cm), integer meters for radius.
  // Cross-language SDKs MUST follow the same formatting.
  const formatted = `${lat.toFixed(7)}:${lng.toFixed(7)}:${Math.trunc(radiusM)}`;
  return sha3_256Hex(formatted);
}

/**
 * Content-type-aware destination commitment.
 *
 * AUDIT1.md §Finding-011/021 collapses the legacy `contentHash` field into
 * `destHash`. For URL QRs the commitment is the URL itself. For content QRs
 * (vCard, coupon, event, pdf, feedback, etc.) the commitment is the already-
 * hashed content body so the signature binds to the content the verifier
 * will render.
 *
 * Both caller shapes feed SHA3-256 over a domain-separated string so a URL
 * whose text happens to equal a serialised JSON blob cannot collide with a
 * content QR.
 *
 * Arguments:
 *   - `contentType`  — stored on the QR row (`"url"`, `"vcard"`, …).
 *   - `destinationUrl` — the URL set on the row; used when `contentType === "url"`.
 *   - `contentHashHex` — SHA-256/SHA3 hex of the content body (whatever the
 *     issuer already computes today via `stableStringify(content)`);
 *     used when `contentType !== "url"`.
 */
export async function computeDestHash(
  contentType: string,
  destinationUrl: string,
  contentHashHex: string,
): Promise<string> {
  // Domain separator `qrauth:dest:v1` prevents a cross-type collision:
  // two different contentType values always hash under different domains,
  // even if the trailing body accidentally matches.
  const body = contentType === "url" ? destinationUrl : contentHashHex;
  const domain = `qrauth:dest:v1:${contentType}:`;
  return sha3_256Hex(domain + body);
}
