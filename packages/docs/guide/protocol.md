# QRVA Protocol

> The most quantum-resistant cryptographic architecture is one where the security of the hot path reduces entirely to hash function preimage resistance, asymmetric operations are pushed offline and made infrequent, and the public record contains only opaque commitments — giving an adversary, quantum or classical, nothing actionable to harvest.
>
> — `ALGORITHM.md`, QRAuth architecture spec

QRVA (QR Verification & Attestation) is the open protocol underneath every QRAuth-signed QR code. It pins how tokens are serialized, signed, verified, and audited — cross-language, cross-implementation, cross-version. This page is the specification third-party implementors build against.

QRVA v2 is the current protocol version. It differs from v1 in three load-bearing ways: tokens are signed in Merkle batches rather than individually, the root of each batch is signed with SLH-DSA (FIPS 205) instead of ECDSA-P256, and the transparency log publishes opaque hash commitments instead of recoverable signatures. The v1 wire format is still accepted during the deprecation window — see [Protocol Versions](#protocol-versions) below.

---

## Protocol Versions

| Version | Signing Algorithm | Hash Function | Status | Notes |
|---|---|---|---|---|
| QRVA v1 | ECDSA-P256 | SHA-256 | Deprecated | Sunset date announced per-tenant. Legacy tokens still verify. |
| QRVA v2 | Hybrid ECDSA-P256 + SLH-DSA-SHA2-128s | SHA3-256 | Current | All new tokens. Both legs must verify. |
| QRVA v3 | SLH-DSA-SHA2-128s only | SHA3-256 | Roadmap | Post-ECDSA removal. Same wire format as v2 minus the ECDSA leg. |

Every QRVA-compliant implementation must accept v2 tokens. v1 support is optional and only relevant for issuers migrating legacy inventories. v3 support becomes mandatory once QRAuth announces the ECDSA sunset date for the integrator's region.

---

## Algorithm Versioning

Every QRVA-signed payload carries a mandatory `alg_version` field. Verifiers reject payloads with absent, unrecognized, or deprecated (past-sunset) `alg_version` values. This is not optional and not defaultable — absence of `alg_version` is a protocol error.

### Supported versions

| Version String | Signing | Hash | Status |
|---|---|---|---|
| `ecdsa-p256-sha256-v1` | ECDSA-P256 | SHA-256 | Deprecated |
| `hybrid-ecdsa-slhdsa-v1` | ECDSA-P256 + SLH-DSA-SHA2-128s | SHA3-256 | Accepted (current) |
| `slhdsa-sha2-128s-v1` | SLH-DSA-SHA2-128s | SHA3-256 | Accepted (PQC-only target) |
| `slhdsa-sha2-256s-v1` | SLH-DSA-SHA2-256s | SHA3-256 | Accepted (high-security variant) |
| `ecdsa-pending-slhdsa-v1` | ECDSA-P256 (merkle leg in flight) | SHA3-256 | Accepted (transient) |

### Rejection policy

A QRVA verifier implements the following three-state classifier:

- **Accepted** — proceed silently. Every version in the table above except the deprecated and unknown cases.
- **Deprecated** — proceed, but emit a warning in the verification response and a log entry for the operator dashboard. `ecdsa-p256-sha256-v1` currently falls here.
- **Rejected** — fail closed. Return `ALG_VERSION_REJECTED`. No version sits in this bucket until a QRAuth-announced sunset date for the tenant's region is reached.
- **Unknown** — fail closed. Any `alg_version` string not in the above table is a schema violation and the verifier refuses the token. Surface `ALG_VERSION_UNSUPPORTED` to the operator.

The reference classifier lives in `packages/shared/src/alg-versions.ts` (`checkAlgVersion()`) and is byte-identical in every first-party SDK. Third-party implementations must match this behavior exactly.

Deprecation warnings must be surfaced in the verifier response so downstream applications can show operator-facing compliance warnings. Do not surface warnings to end users.

---

## Batch Issuance Architecture

QRVA v2 does not sign QR tokens individually. Per-token asymmetric signing is the wrong trade-off for a platform where tokens are long-lived, the transparency log is public, and the adversary model includes future quantum computers. Instead:

1. The issuer collects QR payload hashes into a batch.
2. Each payload becomes a leaf hash in a binary Merkle tree.
3. The Merkle tree's root is signed **once**, with SLH-DSA-SHA2-128s, by the tenant's offline signing key.
4. The signed root plus the tree is persisted server-side; each token carries a leaf index and a Merkle inclusion path.
5. At verify time, the token's leaf hash is recomputed from its canonical payload, walked up through the Merkle path, and compared against the batch root. The batch root's SLH-DSA signature is verified once per batch and cached at the edge.

This architecture has two consequences. First, per-token verification requires zero asymmetric operations on the hot path — only hash computations and a cached root lookup. Second, the SLH-DSA signing cost is amortized across the whole batch, so the 1–50ms SLH-DSA sign latency becomes negligible per token.

### Leaf hash construction

```
leaf_i = SHA3-256( 0x00 || canonical_payload_i )
```

The `0x00` prefix is a mandatory domain-separation tag — see [Leaf and Node Prefix Separation](#leaf-and-node-prefix-separation) below.

### Internal node construction

```
node = SHA3-256( 0x01 || left_child_bytes || right_child_bytes )
```

Child bytes are the raw 32-byte SHA3-256 digests, not hex strings. Concatenation is byte-level.

### Padding

Batch sizes in production are rarely powers of two. The tree is padded to the next power of two using deterministic, index-keyed padding leaves:

```
pad_i = SHA3-256( 0x00 || "qrauth-pad:" || i )
```

The index in the padding string prevents two batches at different padding depths from producing colliding roots.

### Root signing

```
root_signature = SLH-DSA-SHA2-128s.sign( tenant_private_key, merkle_root_bytes )
```

The signing operation happens offline, on a signing host with no inbound internet access. The QRAuth platform ships a reference signer service under `packages/signer-service/` — see [Key Management Architecture](./security.md#key-management-architecture) in the Security guide.

### What the token carries vs what stays server-side

| Field | On the token (URL) | Server-side | In the transparency log |
|---|---|---|---|
| Token identifier | Yes (`t` param) | Yes | Hashed |
| Destination URL | No | Yes | Hashed |
| Geo-fence | No | Yes | Hashed |
| Batch ID | No | Yes | Hashed reference |
| Merkle leaf index | No | Yes | Via inclusion proof |
| Merkle inclusion path | No | Yes | Yes |
| Batch root | No | Yes | Yes |
| Batch root signature (SLH-DSA) | No | Yes | Yes |
| Tenant SLH-DSA public key | No | Yes (authenticated endpoint) | **No** — only a SHA3-256 hash |

The token URL is intentionally minimal: it carries only a short identifier that resolves to the full verification context server-side. This keeps QR payloads scannable and eliminates any wire-format pressure to embed key material.

---

## Canonical Payload Serialization

The canonical payload is the exact byte sequence that is hashed into the Merkle leaf. Cross-language byte-for-byte equality is the contract — every SDK, every edge worker, every future implementation must produce identical output from identical input.

### Format

Pipe-separated, six fields, no trailing delimiter, no escaping:

```
{token}|{tenant_id}|{SHA3-256(destination_url)}|{geo_hash}|{expires_at_iso8601}|{nonce_hex}
```

Where:

- `token` — the short token embedded in the QR URL. Drawn from `[a-zA-Z0-9]` in production; the canonicalizer rejects any field containing `|`, `\n`, or `\0` (see "Forbidden characters" below).
- `tenant_id` — the issuing tenant's identifier (cuid in the reference implementation).
- `SHA3-256(destination_url)` — hex string, 64 chars. The destination URL itself never appears in the canonical form.
- `geo_hash` — either the literal string `none` for location-unbound tokens, or `SHA3-256(f"{lat:.7f}:{lng:.7f}:{int(radius_m)}")`. Seven decimal places give ~1cm precision and the integer radius is truncated, not rounded. Cross-language SDKs must follow the exact same formatting.
- `expires_at_iso8601` — ISO 8601 UTC timestamp, or `1970-01-01T00:00:00.000Z` for non-expiring tokens (epoch sentinel). Empty string is a v1 legacy and is not valid in v2.
- `nonce_hex` — per-leaf random nonce, hex-encoded. At least 16 hex chars (64 bits). The nonce ensures two tokens with identical payloads produce different leaf hashes.

### Forbidden characters

No canonical field may contain `|` (separator), `\n` (newline), or `\0` (NUL). The reference canonicalizer calls `assertCanonicalSafe` on every caller-provided field and throws on any forbidden character. This defense prevents two distinct payloads from collapsing to identical canonical strings via separator injection. Production callers never generate these characters, but the defense is the single source of truth for the wire contract.

### Cross-language test vectors

Ten hand-picked fixtures pin the wire format in `packages/protocol-tests/fixtures/canonical-vectors.json`. Both the Node and Python reference implementations must produce byte-identical output for every fixture; CI fails on any drift. The fixtures cover:

- Minimal payload (no location)
- Real-world coordinates (northern and southern hemispheres)
- Antimeridian edge (longitudes near ±180)
- Polar extremes (latitudes near ±90)
- Epoch sentinel expiry (non-expiring tokens)
- URLs with query strings and fragments
- Long tokens
- Full 7-decimal coordinate precision

Third-party implementations must pass the full vector suite before claiming QRVA compliance.

---

## Verification Flow

A QRVA verifier performs the following steps for every token. Failures at any step are reported as the corresponding error code and the token is treated as invalid.

### Slow path (full audit)

```
1. Resolve token → load leaf data + merkle path + batch_id + batch_root + root_signature
2. Recompute leaf hash from canonical payload bytes
3. Walk the merkle path: for each path node, hash (0x01 || left || right) using the side tag
4. Compare walked root to the stored batch_root — timing-safe comparison
5. Verify SLH-DSA signature over batch_root using tenant's SLH-DSA public key
6. If all pass: token is authentic
```

The SLH-DSA verify in step 5 is cached per-batch at the edge — the result is reused for every subsequent verification of any token in that batch. First-scan latency dominates; repeat scans of any token in the same batch skip the SLH-DSA verify entirely.

### Fast path (hot path)

Alongside the asymmetric legs, QRAuth computes a symmetric MAC at issuance time using a per-tenant HMAC-SHA3-256 key. The MAC is stored server-side only — it is never embedded in the QR URL, never published to the transparency log, and never leaves the authenticated API surface. At verify time:

```
1. Resolve token → load stored MAC + canonical payload
2. Recompute HMAC-SHA3-256 over the canonical payload using the tenant's active MAC key
3. Timing-safe compare against stored MAC
4. On match → short-circuit, token is server-authentic; skip asymmetric verification
5. On miss → fall through to the slow path (the MAC key may have rotated)
```

The MAC is an **additive** fast path, not a replacement. The Merkle inclusion proof remains the authoritative verification for offline and third-party audits. A MAC mismatch is never treated as proof of forgery — it falls through to the asymmetric legs which stay authoritative.

### Hybrid-mode invariants

For tokens with `alg_version = hybrid-ecdsa-slhdsa-v1`, **both** legs must verify:

- ECDSA-P256 signature over the canonical payload, verified against the tenant's ECDSA public key
- SLH-DSA signature over the Merkle batch root, verified against the tenant's SLH-DSA public key, **and** the token's Merkle inclusion proof must walk from its leaf to the signed root

A failure in either leg causes the verifier to reject the token. This is the defense-in-depth property of the hybrid: a hypothetical algebraic break of either ECDSA or SLH-DSA leaves the other intact.

---

## Transparency Log Format

QRVA transparency log entries contain no cryptographic key material. This is deliberate: publishing recoverable signatures or public keys in an append-only public log creates a harvest surface for future quantum adversaries. The log format below is structured so an adversary who captures the entire log today gains nothing actionable — the entries are opaque hash commitments and the one asymmetric artifact (the SLH-DSA signature over the batch root) is, by the nature of SLH-DSA, not a vector for private key recovery.

### Per-token entry

```typescript
{
  commitment: string;         // SHA3-256( token || tenant_id || dest_hash || geo_hash || expiry || nonce ) — hex
  batchRootRef: string;       // SHA3-256 of the batch Merkle root — hex
  merkleInclusionProof: Array<{ hash: string; side: 'left' | 'right' }>;
  tenantId: string;
  issuedAt: string;           // ISO 8601
  expiresAt: string;          // ISO 8601
  algVersion: string;
}
```

The `commitment` field is the only per-token identifier in the log. Without the original nonce, the commitment reveals nothing about the underlying payload — not the destination URL, not the geo-fence, not even the token itself. Auditors who need to verify a specific token provide the token plus its nonce and the verifier reproduces the commitment from scratch.

### Batch root entry (separate table)

```typescript
{
  batchId: string;
  merkleRoot: string;            // hex — the value that was signed
  rootSignature: string;         // SLH-DSA signature of merkleRoot — base64
  tenantPublicKeyHash: string;   // SHA3-256 of tenant's SLH-DSA public key — NOT the key itself
  algVersion: string;
  issuedAt: string;
  tokenCount: number;
}
```

`tenantPublicKeyHash` is the critical field. It is a hash of the tenant's SLH-DSA public key — the key itself is never in the log. Auditors retrieve the real public key via an authenticated tenant signing-key endpoint and compare `SHA3-256(retrieved_key)` to this field. An adversary who scrapes the entire transparency log obtains neither the public key nor a quantum-usable signature (SLH-DSA signatures do not expose the private key under any known quantum algorithm).

The batch root endpoint for auditors:

```
GET /api/v1/transparency/batch/:batchId
```

This is public and unauthenticated. Response carries only the fields above — no private key material, no tenant metadata beyond the ID.

---

## Leaf and Node Prefix Separation

Every QRVA implementation **must** prefix hash inputs with a one-byte domain tag:

```
leaf:         0x00 || canonical_payload
internal:     0x01 || left_child_bytes || right_child_bytes
```

The prefix separation prevents a class of second-preimage attacks where an adversary crafts an internal node value that happens to equal a legitimate leaf hash — without the prefix, the tree's structure is ambiguous and an attacker can forge a proof by presenting the internal node as a leaf.

This is a mandatory protocol requirement. Every first-party SDK enforces it and the property-based fuzz tests in `packages/protocol-tests/src/merkle-fuzz.test.ts` verify it against hundreds of randomized inputs per CI run. Third-party implementations that omit the prefix will fail the cross-language test vector suite.

---

## Third-Party Compliance Test Suite

The canonical test suite lives in `packages/protocol-tests/`. Implementations claiming QRVA compliance must pass every test in the suite before shipping:

- **Canonical vectors** — byte-identical canonical strings for 10 pinned fixtures (`fixtures/canonical-vectors.json`)
- **Merkle fuzzing** — 7 property-based tests × 200 random runs each covering soundness, leaf tamper, path tamper, side swap, drop, duplicate, wrong root
- **Merkle tree fuzzing** — 7 property-based tests covering determinism, single-leaf invariant, order sensitivity, padding distinguishability, inclusion proof completeness
- **Canonical fuzzing** — 18 tests covering determinism, field independence, geo precision, and separator-injection defense
- **Algorithm versioning** — 9 tests pinning the accepted/deprecated/rejected/unknown classifier
- **SLH-DSA adapter** — 9 tests covering key sizes, sign, verify, tamper rejection
- **ML-DSA adapter** — 9 tests for the WebAuthn bridge path
- **Cross-language vectors** — the canonical test vector suite runs in both Node (`npm test -w packages/protocol-tests`) and Python (`python -m pytest packages/python-sdk/tests/`). First-party CI runs both against the same fixtures; any drift fails the build.

To claim QRVA v2 compliance, a third-party implementation must:

1. Produce byte-identical canonical strings for every vector in `fixtures/canonical-vectors.json`.
2. Produce byte-identical Merkle leaf hashes for every vector (using the `0x00` leaf prefix convention).
3. Verify a valid SLH-DSA-SHA2-128s signature over a correctly-constructed batch root.
4. Enforce the `assertCanonicalSafe` forbidden-character rules on every caller-provided field.
5. Reject any `alg_version` string outside the accepted/deprecated table.

QRAuth reviews implementation test reports on request — contact the team for a compliance review.

---

## Error Codes

| Code | HTTP | Meaning |
|---|---|---|
| `INVALID_SIGNATURE` | 200 (trust = 0) | ECDSA leg verification failed |
| `MERKLE_PROOF_INVALID` | 200 (trust = 0) | Merkle inclusion proof walk did not match the signed batch root |
| `BATCH_SIGNATURE_INVALID` | 200 (trust = 0) | SLH-DSA signature over the batch root did not verify |
| `BATCH_NOT_FOUND` | 404 | Referenced batch_id does not exist in the signed-batch store |
| `ALG_VERSION_UNSUPPORTED` | 400 | `alg_version` field absent or not in the accepted/deprecated table |
| `ALG_VERSION_REJECTED` | 400 | `alg_version` has passed its sunset date for the tenant's region |
| `QR_NOT_FOUND` | 404 | Token unknown |
| `QR_EXPIRED` | 410 | Past `expiresAt` |
| `QR_REVOKED` | 410 | Manually revoked |
| `TRANSPARENCY_LOG_MISMATCH` | 200 (trust − 20) | Log entry commitment did not match the recomputed commitment |
| `NO_ACTIVE_KEY` | 500 | Org has no active signing key — operator action required |

---

## See Also

- **`ALGORITHM.md`** — the full cryptographic architecture specification (read before implementing)
- **[Security](./security.md)** — threat model, cryptographic primitives, key management
- **[Threat Model](./threat-model.md)** — adversary capabilities and attack scenarios
- **[Compliance](./compliance.md)** — NIST FIPS alignment, certifications, audit pathways
