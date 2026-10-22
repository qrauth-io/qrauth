# QRVA Protocol

QRVA (QR Verification & Attestation) is the open protocol underneath every QRAuth-signed QR code. It pins how tokens are serialized, signed, verified, and audited — cross-language, cross-implementation, cross-version. This page summarizes the protocol for implementors. The normative specification lives in the [QRVA protocol repository](https://github.com/qrauth-io/protocol); the cryptographic detail of the QRAuth reference implementation is in [ALGORITHM.md](https://github.com/qrauth-io/qrauth/blob/main/ALGORITHM.md).

QRVA v2 is the current protocol version. Every token carries a hybrid signature: an ECDSA-P256 signature over its canonical core, and a Merkle inclusion proof against a batch root signed with SLH-DSA-SHA2-128s (FIPS 205). Both legs must verify. QRVA v1 (`ecdsa-p256-sha256-v1`) is rejected — see [Protocol Versions](#protocol-versions) below.

---

## Protocol Versions

| Version | Signing Algorithm | Hash Function | Status | Notes |
|---|---|---|---|---|
| QRVA v1 | ECDSA-P256 | SHA-256 | Rejected | Verifiers fail closed. Legacy tokens must be re-issued. |
| QRVA v2 | Hybrid ECDSA-P256 + SLH-DSA-SHA2-128s | SHA3-256 | Current | All new tokens. Both legs must verify. |

Every QRVA-compliant implementation must accept v2 tokens and must reject v1 tokens.

---

## Algorithm Versioning

Every QRVA-signed payload carries a mandatory `alg_version` field. Verifiers reject payloads with absent, unrecognized, or rejected `alg_version` values. This is not optional and not defaultable — absence of `alg_version` is a protocol error.

### Supported versions

| Version String | Signing | Hash | Status |
|---|---|---|---|
| `hybrid-ecdsa-slhdsa-v1` | ECDSA-P256 + SLH-DSA-SHA2-128s | SHA3-256 | Accepted (current; all new issuance) |
| `slhdsa-sha2-128s-v1` | SLH-DSA-SHA2-128s | SHA3-256 | Rejected (reserved; accepted once its verifier ships) |
| `slhdsa-sha2-256s-v1` | SLH-DSA-SHA2-256s | SHA3-256 | Rejected (reserved; accepted once its verifier ships) |
| `ecdsa-p256-sha256-v1` | ECDSA-P256 | SHA-256 | Rejected |
| `ecdsa-pending-slhdsa-v1` | ECDSA-P256 only (no Merkle leg) | SHA3-256 | Rejected (former transient state) |

Every new QR code is issued as `hybrid-ecdsa-slhdsa-v1`, with its ECDSA signature and Merkle data written together.

### Rejection policy

A QRVA verifier implements the following three-state classifier:

- **Accepted** — proceed silently. Every version marked Accepted in the table above.
- **Deprecated** — proceed, but emit a warning in the verification response (`warnings[]` with code `ALG_DEPRECATED`) and a log entry for the operator. No version is deprecated today.
- **Rejected** — fail closed. `ecdsa-p256-sha256-v1` is rejected.
- **Unknown** — fail closed. Any `alg_version` string not in the above table is a schema violation and the verifier refuses the token.

The reference classifier lives in `packages/shared/src/alg-versions.ts` (`checkAlgVersion()`) and is enforced server-side by the QRAuth verify endpoint. For rejected and unknown versions it returns `verified: false` with a human-readable `reason` and logs the alg version. Third-party implementations must match this classification exactly.

Deprecation warnings must be surfaced in the verifier response so downstream applications can show operator-facing compliance warnings. Do not surface warnings to end users.

---

## Batch Issuance Architecture

QRVA v2 combines a per-token ECDSA-P256 signature with a batched post-quantum leg:

1. The issuer signs each token's canonical core with ECDSA-P256 (see [Canonical Payload Serialization](#canonical-payload-serialization)).
2. Each token's canonical Merkle leaf (core plus a per-leaf nonce) becomes a leaf hash in a binary Merkle tree. Batches flush at 64 items or 200 ms, whichever comes first.
3. The Merkle tree's root is signed **once** per batch, with SLH-DSA-SHA2-128s, by the tenant's key on the isolated signer service.
4. The signed root is persisted server-side; each token row stores its leaf hash, its Merkle inclusion path, and its batch ID.
5. At verify time, the verifier checks the ECDSA-P256 signature, recomputes the token's leaf from its canonical core and stored nonce, requires it to equal the stored leaf, and walks the inclusion proof from the recomputed leaf to an SLH-DSA-SHA2-128s-signed batch root. The batch-root SLH-DSA verification is cached in-process per batch for 1 hour after a success.

Per-token verification therefore runs one ECDSA-P256 verify plus hashing; the SLH-DSA verify is amortized per batch. SLH-DSA signing cost is amortized across up to 64 tokens per batch.

### Leaf hash construction

```
leaf_i = SHA3-256( 0x00 || canonical_merkle_leaf_i )
```

`canonical_merkle_leaf_i` is the 7-field leaf form (core plus nonce). The `0x00` prefix is a mandatory domain-separation tag — see [Leaf and Node Prefix Separation](#leaf-and-node-prefix-separation) below.

### Internal node construction

```
node = SHA3-256( 0x01 || left_child_bytes || right_child_bytes )
```

Child bytes are the raw 32-byte SHA3-256 digests, not hex strings. Concatenation is byte-level.

### Padding

Batch sizes in production are rarely powers of two. The tree is padded to the next power of two using deterministic, index-keyed padding leaves, unique per position:

```
pad_i = SHA3-256( 0x00 || "qrauth-pad:" || i )
```

The index in the padding string prevents two batches at different padding depths from producing colliding roots.

### Root signing

```
root_signature = SLH-DSA-SHA2-128s.sign( tenant_slhdsa_private_key, "qrauth:merkle-root:v1:" || merkle_root_bytes )
```

In production the signing operation runs on the signer service, which the API reaches over a private network. The QRAuth platform ships a reference signer service under `packages/signer-service/` — see [Signing Architecture](./signing-architecture).

### What the token carries vs what stays server-side

| Field | On the token (URL) | Server-side |
|---|---|---|
| Token identifier | Yes (URL path `/v/:token`) | Yes |
| Destination URL | No | Yes |
| Geo-fence | No | Yes |
| ECDSA-P256 signature | No | Yes (DER, base64) |
| Batch ID | No | Yes |
| Merkle leaf hash and inclusion path | No | Yes |
| Batch root and SLH-DSA root signature | No | Yes |
| Tenant SLH-DSA public key | No | Yes (the public batch endpoint returns only its SHA3-256 hash) |

The token URL is intentionally minimal: it carries only a short identifier that resolves to the full verification context server-side. This keeps QR payloads scannable: signatures are held server-side and never embedded in the QR image.

---

## Canonical Payload Serialization

The canonical payload is the exact byte sequence the MAC, ECDSA-P256 and Merkle legs bind to. The reference implementation is `packages/shared/src/canonical.ts`. Cross-language byte-for-byte equality is the contract — every SDK, every edge worker, every future implementation must produce identical output from identical input.

### Format

Pipe-separated, no trailing delimiter, no escaping. The **canonical core** has six fields and is the input to the MAC and the ECDSA-P256 signature:

```
{algVersion}|{token}|{tenantId}|{destHash}|{geoHash}|{expiresAt}
```

The **canonical Merkle leaf** appends a seventh field:

```
{algVersion}|{token}|{tenantId}|{destHash}|{geoHash}|{expiresAt}|{nonce}
```

Where:

- `algVersion` — the row's `alg_version` string, e.g. `hybrid-ecdsa-slhdsa-v1`.
- `token` — the short token embedded in the QR URL. Drawn from `[a-zA-Z0-9]` in production; the canonicalizer rejects any field containing `|`, `\n`, or `\0` (see "Forbidden characters" below).
- `tenantId` — the issuing tenant's identifier (cuid in the reference implementation).
- `destHash` — SHA3-256 hex (64 chars) of a domain-separated destination commitment. For URL codes: `SHA3-256("qrauth:dest:v1:url:" + destinationUrl)`. For other content types: `SHA3-256("qrauth:dest:v1:" + contentType + ":" + contentHashHex)`, where `contentHashHex` is the hash of the canonical content. The destination URL itself never appears in the canonical form.
- `geoHash` — either the literal string `none` for location-unbound tokens, or `SHA3-256(f"{lat:.7f}:{lng:.7f}:{int(radius_m)}")`. Seven decimal places give ~1cm precision and the integer radius is truncated, not rounded. Cross-language SDKs must follow the exact same formatting.
- `expiresAt` — ISO 8601 UTC timestamp (`YYYY-MM-DDTHH:mm:ss.sssZ`), or the empty string for non-expiring tokens.
- `nonce` (leaf form only) — 32 random bytes, hex-encoded. The nonce ensures two tokens with identical core payloads produce different leaf hashes.

The ECDSA-P256 leg signs `"qrauth:ecdsa-canonical:v1:" + canonical_core`. The signature is DER-encoded and stored base64.

### Forbidden characters

No canonical field may contain `|` (separator), `\n` (newline), or `\0` (NUL). The reference canonicalizer calls `assertCanonicalSafe` on every caller-provided field and throws on any forbidden character. This defense prevents two distinct payloads from collapsing to identical canonical strings via separator injection. Production callers never generate these characters, but the defense is the single source of truth for the wire contract.

### Cross-language test vectors

Seven fixtures pin the wire format in `packages/protocol-tests/fixtures/canonical-vectors.json`. The Node test suite checks `destHash`, `geoHash`, the canonical core, the Merkle leaf form and the leaf hash for every fixture in CI, under UTC and a non-UTC time zone; any drift fails the build. A `leafBinding` section pins verifier behaviour: for a payload and nonce it gives the leaf a verifier must recompute and whether that matches the stored leaf. The fixtures cover:

- Minimal payload (URL content, no location)
- URL code with a location and radius
- Non-expiring code (empty-string `expiresAt`)
- Content code (vCard), where `destHash` commits to the content hash
- Southern-hemisphere coordinates
- Full 7-decimal coordinate precision
- Expiry one millisecond before midnight UTC, serialized as UTC ISO 8601 regardless of the host time zone

Third-party implementations must pass the full vector suite before claiming QRVA compliance.

---

## Verification Flow

The QRAuth verify endpoint performs the following steps for every token. Any failure makes the token invalid. Details: [ALGORITHM.md](https://github.com/qrauth-io/qrauth/blob/main/ALGORITHM.md).

```
1. Resolve token → load the row (unknown token → 404)
2. Status checks: revoked, expired, scan limits
3. alg_version gate: rejected or unknown → fail closed
4. MAC pre-filter (if the row has a MAC): mismatch → reject
5. ECDSA-P256 verify over "qrauth:ecdsa-canonical:v1:" || canonical_core
6. Hybrid rows: leaf = SHA3-256(0x00 || canonical_core || "|" || nonce); timing-safe compare with the stored leaf
   (a row missing batch id, leaf, nonce or path fails)
7. Hybrid rows: walk the inclusion path from the recomputed leaf to the batch root — timing-safe comparison
8. Hybrid rows: verify the SLH-DSA-SHA2-128s signature over "qrauth:merkle-root:v1:" || batch_root
9. Valid only if step 5 and steps 6–8 pass
```

The SLH-DSA verify in step 8 is cached in-process per batch for 1 hour after a success; failures are not cached.

### MAC pre-filter

At issuance QRAuth also computes a MAC using a per-tenant HMAC-SHA3-256 key over `"qrauth:mac:v1:" + canonical_core`. The MAC is stored server-side only — it is never embedded in the QR URL and never written to the issuance log. At verify time:

```
1. Load stored MAC + key version
2. Recompute HMAC-SHA3-256 over the canonical core with that key
3. Timing-safe compare against the stored MAC
4. On mismatch → verification fails immediately
5. On match → continue to the ECDSA-P256 and Merkle/SLH-DSA legs
```

The MAC is a fast-reject pre-filter, not a replacement. A match never skips the asymmetric legs.

### Hybrid-mode invariants

For tokens with `alg_version = hybrid-ecdsa-slhdsa-v1`, **both** legs must verify:

- ECDSA-P256 signature over the canonical core, verified against the tenant's ECDSA public key
- The Merkle leaf recomputed from the same canonical core and the stored nonce, equal to the stored leaf, with its inclusion proof verified against a batch root whose SLH-DSA-SHA2-128s signature verifies under the tenant's SLH-DSA public key

A failure in either leg causes the verifier to reject the token.

---

## Issuance Log

Every issuance appends an entry to a **hash-chained issuance log** in the QRAuth database. Each entry stores the previous entry's hash and its own entry hash (SHA-256). Entries for hybrid rows also carry the token's SHA3-256 Merkle leaf hash (`commitment`), a reference to the signed batch root (`batchRootRef`, the SHA3-256 of the root), and the token's Merkle inclusion proof. Entries contain no private key material.

The chain is tamper-evident against someone who can read but not write the database, when cross-checked against a previously saved snapshot of the log. It is not tamper-evident against an adversary with database write access; it is a forensic record, not a cryptographic proof. An RFC 6962-style Merkle log with signed tree heads and external witnesses is planned, specified in [ADR-0001](https://github.com/qrauth-io/qrauth/blob/main/docs/adr/0001-transparency-log.md).

### Signed batch record

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

`tenantPublicKeyHash` is the SHA3-256 hash of the tenant's SLH-DSA public key, not the key itself. An auditor holding the public key compares `SHA3-256(public_key)` with this field.

The batch root endpoint for auditors:

```
GET /api/v1/transparency/batch/:batchId
```

This is public and unauthenticated. The response carries only the fields above — no private key material.

---

## Leaf and Node Prefix Separation

Every QRVA implementation **must** prefix hash inputs with a one-byte domain tag:

```
leaf:         0x00 || canonical_payload
internal:     0x01 || left_child_bytes || right_child_bytes
```

The prefix separation prevents a class of second-preimage attacks where an adversary crafts an internal node value that happens to equal a legitimate leaf hash — without the prefix, the tree's structure is ambiguous and an attacker can forge a proof by presenting the internal node as a leaf.

This is a mandatory protocol requirement. The reference implementation enforces it, and property-based tests (200 runs per property) in `packages/protocol-tests/src/merkle-fuzz.test.ts` check it in CI. Third-party implementations that omit the prefix will fail the cross-language test vector suite.

---

## Third-Party Compliance Test Suite

The canonical test suite lives in `packages/protocol-tests/`. Implementations claiming QRVA compliance must pass every test in the suite before shipping:

- **Canonical vectors** — byte-identical canonical strings and leaf hashes for 7 pinned fixtures, plus leaf-binding verdicts (`fixtures/canonical-vectors.json`)
- **Merkle fuzzing** — 7 property-based tests × 200 random runs each covering soundness, leaf tamper, path tamper, side swap, drop, duplicate, wrong root
- **Merkle tree fuzzing** — 7 property-based tests (100–200 runs each) covering determinism, single-leaf invariant, order sensitivity, padding distinguishability, inclusion proof completeness
- **Canonical fuzzing** — 16 tests covering determinism, field independence, geo precision, and separator-injection defense
- **Algorithm versioning** — 9 tests pinning the accepted/deprecated/rejected/unknown classifier
- **SLH-DSA adapter** — 9 tests covering key sizes, sign, verify, tamper rejection
- **ML-DSA adapter** — 10 tests for the WebAuthn bridge path
- **Cross-language vectors** — the canonical test vector suite runs via `npm test -w packages/protocol-tests` against the pinned fixtures; any drift fails the build.

To claim QRVA v2 compliance, a third-party implementation must:

1. Produce byte-identical canonical strings for every vector in `fixtures/canonical-vectors.json`.
2. Produce byte-identical Merkle leaf hashes for every vector (using the `0x00` leaf prefix convention).
3. Verify a valid SLH-DSA-SHA2-128s signature over a correctly-constructed batch root.
4. Enforce the `assertCanonicalSafe` forbidden-character rules on every caller-provided field.
5. Reject `ecdsa-p256-sha256-v1` and any `alg_version` string outside the accepted/deprecated sets.

QRAuth reviews implementation test reports on request — contact the team for a compliance review.

---

## Verification Responses

The reference verify endpoint (`GET /v/:token`) does not return protocol error codes. It responds as follows:

| Case | HTTP | Response |
|---|---|---|
| Unknown token | 404 | Not-found error |
| Revoked, expired, or scan limit reached | 200 | `verified: false` with a human-readable `reason` |
| Rejected or unknown `alg_version` | 200 | `verified: false` with a human-readable `reason` |
| MAC pre-filter mismatch | 200 | `verified: false`, reason "This QR code failed signature verification." |
| ECDSA or Merkle/SLH-DSA leg fails | 200 | `verified: false`, `security.signatureValid: false` |
| Geo-fence enforced and no coordinates / outside the fence | 200 | `verified: false`, `reason` `GEO_PROXIMITY_REQUIRED` / `GEO_OUT_OF_FENCE` |
| Trust score 20 or below | 200 | `verified: false` with a low-trust `reason` |

See [Verification API](/api/verification) for the full response shape.

---

## See Also

- **[ALGORITHM.md](https://github.com/qrauth-io/qrauth/blob/main/ALGORITHM.md)** — the full cryptographic architecture specification (read before implementing)
- **[QRVA protocol repository](https://github.com/qrauth-io/protocol)** — the normative protocol specification
- **[Security](./security.md)** — threat model, cryptographic primitives, key management
- **[Threat Model](./threat-model.md)** — adversary capabilities and attack scenarios
- **[Compliance](./compliance.md)** — NIST FIPS alignment, certifications, audit pathways
