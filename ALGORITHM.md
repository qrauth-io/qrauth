# QRAuth — Cryptographic Architecture

**Version:** 2.3
**Status:** Authoritative. This file is the single source of truth for QRAuth's cryptographic mechanisms, wire formats, and parameter choices. Threat analysis and adversary catalogs live in `THREAT_MODEL.md`; operator-facing and integrator-facing summaries live in `SECURITY.md`. When this file disagrees with implementation, this file is wrong and must be amended before code changes — the spec drives.
**Last reviewed:** 2026-10-20.
**Review cadence:** on every new or deprecated primitive, on every wire-format change, on every completed audit, and at least once every 12 months.

---

## Table of Contents

1. Why This Document Exists
2. Threat Model
3. As-Shipped Cryptographic State
4. Core Principle: Hybrid Verification with Batched Asymmetric Cost
5. Entropy
6. Layer 1 — QR Signing: Merkle-Based Batch Architecture
7. Layer 2 — MAC Pre-Filter
8. Layer 3 — Issuance Log: Hash Chain
9. Layer 4 — WebAuthn Passkeys: Hybrid Bridge
10. Layer 5 — Key Lifecycle
11. Algorithm Agility in the QRVA Protocol
12. Rollout Invariants
13. Implementation Concerns and Pitfalls
14. Testing Requirements
15. Dependency Reference
16. Integrator Mechanism Reference
17. Version History

---

## 1. Why This Document Exists

QRAuth's signing and verification paths combine classical and post-quantum primitives into a single coherent construction. This document specifies the construction: what each primitive is, what it binds to, how it composes with the others, and where in the codebase it lives.

The threat model this construction defends against — adversary capabilities, attack scenarios, residual risk — is specified separately in `THREAT_MODEL.md`. When a design choice in this document is justified by a threat, it cites the attack scenario from that document rather than duplicating the analysis.

Verification of a hybrid QR row combines four checks: an HMAC-SHA3-256 MAC pre-filter, an ECDSA-P256 signature over the domain-separated canonical core, a SHA3-256 Merkle inclusion proof for the row, and an SLH-DSA-SHA2-128s signature over the batch root. The security of these checks rests on the EUF-CMA security of ECDSA-P256 against classical adversaries, the EUF-CMA security of SLH-DSA-SHA2-128s (a hash-based scheme), the collision and second-preimage resistance of SHA3-256, and the PRF security of HMAC-SHA3-256. Grover's algorithm reduces SHA3-256 preimage security from 256 to 128 bits.

## 2. Threat Model

The threat model is maintained in [`THREAT_MODEL.md`](THREAT_MODEL.md). That document describes adversary capabilities (classical, near-term quantum, long-term CRQC), the assets under protection, and attack scenarios A–F: harvest now / attack later, protocol downgrade, server or KMS compromise, issuance-log harvest, WebAuthn credential forgery, and real-time proxy.

This file specifies the mechanisms those mitigations compose into. When a design choice below references a threat, it cites the scenario letter from `THREAT_MODEL.md` rather than duplicating the analysis. A reader reviewing this document for protocol soundness should read the threat model first, then return here.

## 3. As-Shipped Cryptographic State

The following primitives are currently implemented and in use. Files are paths relative to repository root.

| Layer | Primitive | Algorithm | Files | Post-quantum |
|---|---|---|---|---|
| QR signing (PQC leg) | Merkle batch + SLH-DSA | SLH-DSA-SHA2-128s (FIPS 205) | `packages/api/src/services/merkle-signing.ts`, `packages/api/src/services/slhdsa-adapter.ts`, `packages/signer-service/src/server.ts` | Resistant |
| QR signing (classical leg) | ECDSA-P256 | ECDSA-P256 SHA-256 (FIPS 186-4) | `packages/api/src/services/signing.ts`, `packages/api/src/services/ecdsa-signer/`, `packages/signer-service/src/server.ts` | Classical only; present for defense in depth |
| Canonical form | SHA3-256 | FIPS 202 | `packages/shared/src/canonical.ts` | Resistant |
| Merkle tree hashing | SHA3-256 | FIPS 202 | `packages/api/src/services/merkle-signing.ts` | Resistant |
| MAC pre-filter | HMAC-SHA3-256 | FIPS 198 / FIPS 202 | `packages/api/src/services/mac.ts` | Resistant |
| Proximity attestation | ES256-style JWT (domain-separated signed bytes, DER-encoded signature — not portable to stock JWT libraries) with `kid`/`aud`/`device`/`alg_version` | FIPS 186-4 | `packages/api/src/services/proximity.ts` | Classical only |
| Auth-session approval | ECDSA-P256 over unified canonical form | FIPS 186-4 | `packages/api/src/services/auth-session.ts` | Classical only |
| Animated-QR frame signing | HMAC-SHA-256 (transitional), 8-byte truncated tag; per-session key derived with HKDF-SHA-256 | FIPS 198 / FIPS 180-4 / RFC 5869 | `packages/api/src/services/animated-qr.ts`, `packages/signer-service/src/server.ts` (`/v1/mac/*`) | Resistant (SHA3 migration deferred) |
| WebAuthn credentials | ECDSA-P256 | FIPS 186-4 | hardware authenticators | Classical only |
| WebAuthn PQC bridge | ML-DSA-44 | FIPS 204 | `packages/api/src/services/webauthn.ts`, client browser | Resistant |
| At-rest encryption | AES-256-GCM | FIPS 197 | `packages/api/src/lib/key-at-rest.ts`, `packages/signer-service/src/key-at-rest.ts` | Resistant |
| App webhook signatures | HMAC-SHA-256 | FIPS 198 / FIPS 180-4 | `packages/api/src/services/webhook.ts` | Resistant |
| Signing-key webhook signatures | HMAC-SHA3-256 | FIPS 198 / FIPS 202 | `packages/api/src/services/security-webhook.ts` | Resistant |
| Issuance log | SHA-256 hash chain; SHA3-256 Merkle leaf and batch-root references | FIPS 180-4 / FIPS 202 | `packages/api/src/services/transparency.ts` | Resistant |
| OIDC ID tokens | RS256 (default) / ES256 JWS | RFC 7518 | `packages/api/src/lib/oidc-id-token.ts`, `packages/signer-service/src/server.ts` (`/v1/sign-rsa-jws`, `/v1/sign-ecdsa-jws`) | Classical only |
| JWT session signing | HS256 (HMAC-SHA256) | RFC 7518 | `packages/api/src/middleware/auth.ts` | Resistant |
| Entropy | `crypto.randomBytes` | kernel CSPRNG | `packages/api/src/lib/entropy.ts` | — |

SHA3-256 is used for the canonical form, the Merkle tree, the MAC pre-filter, the signing-key webhook, the issuance-log Merkle references, and the proximity attestation `sub` and `device` claims. SHA-256 remains in use for:

- ECDSA-P256, RS256 and HS256 signing (required by those primitives).
- Living Codes frame HMAC and HKDF key derivation (deferred migration, tracked as Audit-1 Finding-013).
- App webhook HMAC and the app client-secret hash that keys it.
- The issuance-log hash chain (`entryHash`) and its token and destination hash fields.
- Hashed scanner IP addresses, the server-side fallback device fingerprint, and ephemeral-session device fingerprints.
- Lookup hashes for stored credentials: API keys, refresh tokens, OIDC authorization codes, access tokens, sessions and client secrets.
- PKCE `S256` code challenges (fixed by RFC 7636) and OAuth state binding.
- OIDC pairwise subject derivation (HMAC-SHA-256).
- The content hash (`stableStringify` of the content) passed to `computeDestHash`.

## 4. Core Principle: Hybrid Verification with Batched Asymmetric Cost

Earlier drafts of this document described QRAuth as having a "hash-native" verification path where asymmetric operations lived only at issuance and verification reduced to hash preimage resistance. That characterization was too strong, and Audit-1 identified a specific instance — the MAC fast path — where the implementation had taken the characterization literally and allowed the MAC to short-circuit asymmetric verification. The remediation removed the short-circuit. The accurate characterization is:

**The per-QR asymmetric cost is amortized across a batch, not per-request.** Every hybrid row's verification runs the ECDSA-P256 leg, the Merkle inclusion proof, and the SLH-DSA-SHA2-128s batch root signature check. The ECDSA verify is ~50 µs. The Merkle path walk is ~10 µs. The SLH-DSA verify is ~3 ms on a cold cache, O(1) lookup on a warm cache (1-hour TTL per `batchId`, 10k-entry LRU). In aggregate, hot-path P50 is ~0.15 ms and P95 is ~0.18 ms, measured in `packages/api/test/bench/verify.bench.ts`.

**The MAC is a pre-filter.** A `macTokenMac` column on a QR row, when present, is recomputed and compared constant-time before asymmetric verification runs. A MAC mismatch is a fast-reject; a MAC match does not short-circuit anything. The MAC's role is to cheaply reject tampered or malformed inputs before cryptographic cycles are spent on them, and to provide an independent integrity check over the same canonical core the ECDSA leg verifies. It does not replace the asymmetric legs. See §7.

**The post-quantum leg is hash-based.** SLH-DSA-SHA2-128s security reduces to properties of SHA-2; no known quantum algorithm recovers its private keys from signatures or public keys. A hybrid row verifies only if, in addition to the ECDSA-P256 signature, the row's Merkle inclusion proof verifies against a batch root carrying a valid SLH-DSA-SHA2-128s signature under the tenant's key. This is the construction that addresses harvest now / attack later (`THREAT_MODEL.md` Scenario A).

## 5. Entropy

QRAuth uses Node's `crypto.randomBytes` via a thin helper in `packages/api/src/lib/entropy.ts`:

```ts
export async function generateSecureEntropy(bytes: number): Promise<Buffer> {
  if (!Number.isInteger(bytes) || bytes <= 0) {
    throw new Error(`generateSecureEntropy: bytes must be a positive integer, got ${bytes}`);
  }
  return randomBytes(bytes);
}
```

On Linux production hosts this is backed by `getrandom(2)` against the kernel CSPRNG.

An earlier draft of this section specified a multi-source HMAC-DRBG combiner over `crypto.randomBytes` and a KMS-backed RNG. That design was implemented, audited in Audit-1 (Finding-017), and found to be a combiner with no distinct second source — the KMS leg was a stub that also returned `crypto.randomBytes`. The combiner's HMAC-DRBG added no entropy over its seed, so the claim of multi-source entropy did not hold. During remediation we made the explicit decision (Audit-1 Findings 017+023, option b) to collapse the combiner to a direct alias rather than implement the KMS leg under time pressure. Rationale: `crypto.randomBytes` alone is sound; a combiner with one real source is not better than the source; misleading naming is worse than a simple wrapper. The decision is recorded in `docs/security/remediation-log.md`.

A future KMS-backed entropy source is a clean swap-in at the `generateSecureEntropy` boundary. Callers do not change.

## 6. Layer 1 — QR Signing: Merkle-Based Batch Architecture

### 6.1 Concept

Per-QR asymmetric signing would make the signer service the bottleneck of issuance. Instead, each QR contributes a SHA3-256 leaf hash to a Merkle tree; the tree's root is signed once via SLH-DSA-SHA2-128s on the signer host; each QR row stores its inclusion proof. At verification, the verifier walks the inclusion proof to the batch root, then verifies the SLH-DSA signature over that root.

```
                    SLH-DSA Signature (on signer host)
                              │
                         MerkleRoot
                        ┌─────┴─────┐
                      Node01       Node23
                     ┌──┴──┐      ┌──┴──┐
                    L0    L1    L2    L3
                    │      │      │      │
                  QR-T0  QR-T1  QR-T2  QR-T3
```

Each leaf `Li = SHA3-256(0x00 || canonicalizeMerkleLeaf(payload_i))`. Internal nodes `N = SHA3-256(0x01 || left || right)` with bytes-level concatenation of decoded hashes. The `0x00` / `0x01` prefixes provide domain separation against second-preimage attacks where an adversary crafts an internal-node hash that collides with a leaf hash.

### 6.2 Batch Issuance Flow

The canonical payload that each leaf commits to is built by `canonicalizeCore` and `canonicalizeMerkleLeaf` in `packages/shared/src/canonical.ts`:

**Core form (6 fields, `|`-separated, fixed order):**

```
algVersion | token | tenantId | destHash | geoHash | expiresAt
```

**Merkle leaf form (core + per-leaf nonce, 7 fields):**

```
algVersion | token | tenantId | destHash | geoHash | expiresAt | nonce
```

Field specifications:

- `algVersion` — string constant for the signing algorithm (`hybrid-ecdsa-slhdsa-v1` as of this document).
- `token` — the short random token embedded in the QR image's URL path.
- `tenantId` — organization CUID; binds the signature to the issuing tenant.
- `destHash` — SHA3-256 hex of a content-type-aware destination commitment. For URL QRs: `SHA3-256("qrauth:dest:v1:url:" || destinationUrl)`. For content QRs (vCard, coupon, event, pdf, feedback): `SHA3-256("qrauth:dest:v1:" || contentType || ":" || contentHashHex)`. See `computeDestHash`.
- `geoHash` — `"none"` literal for unbound rows; otherwise `SHA3-256(lat.toFixed(7) || ":" || lng.toFixed(7) || ":" || Math.trunc(radiusM))`.
- `expiresAt` — ISO 8601 string, or the empty string `""` for non-expiring codes.
- `nonce` — per-leaf hex-encoded 32 bytes from `generateSecureEntropy(32)`. Ensures two QRs with otherwise-identical payloads produce distinct leaves.

`assertCanonicalSafe` rejects any field containing `|`, `\n`, or `\0` before serialization so a field-injection attack cannot collapse two distinct payloads into the same canonical bytes.

Batch construction runs in `packages/api/src/services/merkle-signing.ts::issueBatchInternal`:

1. Generate per-leaf nonces.
2. Compute leaf hashes via `computeLeafHash` (SHA3-256 with `0x00` leaf prefix).
3. Build the Merkle tree via `buildMerkleTree` with power-of-2 padding. Padding leaves are `SHA3-256(0x00 || "qrauth-pad:" || paddedIndex)` to keep padding leaves unique and prevent cross-batch root collisions.
4. Hash internal nodes via `hashInternalNode` (SHA3-256 with `0x01` node prefix, bytes-level concat).
5. Sign the root via the configured `SlhDsaSigner` (`LocalSlhDsaSigner` in dev, `HttpSlhDsaSigner` in production).
6. Return the `SignedBatch` record with root, root signature, and per-token inclusion proofs.

The signer service prepends `qrauth:merkle-root:v1:` (UTF-8) to the root bytes before signing. The verifier reconstructs the same prefix. See §13.1.

### 6.3 Verification Flow

Verification runs in `packages/api/src/routes/verify-signatures.ts::verifyRowSignatures` (wired into the main route in `packages/api/src/routes/verify.ts`):

1. If the row carries a `macTokenMac`, compute the MAC over the canonical core string and compare constant-time. On mismatch, return `macRejected: true`; the row's signature status short-circuits to "invalid" and the asymmetric legs are not consulted. On match, continue.
2. Verify the ECDSA leg over `qrauth:ecdsa-canonical:v1:` || `coreCanonical` via `SigningService.verifyCanonical`. The signature is base64 DER.
3. For hybrid rows (`algVersion === 'hybrid-ecdsa-slhdsa-v1'`), run the Merkle/SLH-DSA leg via `HybridSigningService.verifyHybridLeg`:
   1. The row MUST carry `merkleBatchId`, `merkleLeafHash`, `merkleLeafNonce` and an array `merklePath`. If any is missing, verification fails (`MERKLE_FIELDS_MISSING`).
   2. Recompute the leaf from the same canonical core the MAC and ECDSA legs used and the row's stored nonce: `leaf = SHA3-256(0x00 || coreCanonical || "|" || nonce)` (`computeLeafHashFromCore`). A nonce that is empty or contains `|`, `\n` or `\0` fails (`LEAF_NONCE_INVALID`).
   3. Compare the recomputed leaf with the stored `merkleLeafHash` in constant time. A mismatch fails (`LEAF_HASH_MISMATCH`).
   4. Load the batch; it must exist (`BATCH_NOT_FOUND`) and belong to the row's organization (`BATCH_TENANT_MISMATCH`).
   5. Walk the inclusion proof from the recomputed leaf to the batch root (`MERKLE_PROOF_INVALID` on failure).
   6. Verify the SLH-DSA-SHA2-128s signature on the batch root (`BATCH_SIGNATURE_INVALID` on failure).
4. The signature is valid only if the ECDSA leg and the Merkle/SLH-DSA leg both pass. Hybrid is the only accepted alg version and the only one with a verifier. Every other version is rejected before this step (§11.3); `verifyRowSignatures` also fails any non-hybrid version it receives (`ALG_VERSION_UNSUPPORTED`). A failure is logged with its reason.

Because the leaf is rebuilt from the payload being verified, a change to any field of the canonical core (destination, tenant, location, expiry, algorithm version) or to the nonce breaks the post-quantum leg on its own, independently of the ECDSA leg.

The SLH-DSA batch-root verification is cached in-process:

- Key: `batchId` (the random hex identifier assigned at batch creation).
- Value: absolute expiry time in milliseconds.
- Bound: 10,000 entries.
- TTL: 1 hour.
- Eviction: insertion-order (oldest entry removed when size hits bound); gets touch the entry to the tail for LRU semantics.
- Only successful verifications are cached. Failures are never cached so a signer-side key compromise cannot be accidentally blessed by a poisoned cache.

Implementation: `BatchRootVerifyCache` in `packages/api/src/services/hybrid-signing.ts`.

### 6.4 Hybrid Signing (shipping)

The shipping construction is hybrid ECDSA-P256 + SLH-DSA-SHA2-128s, and it is the only issuance path. At issuance, each QR receives its own ECDSA-P256 signature over the canonical core, and its Merkle leaf joins a batch whose root is signed once with SLH-DSA-SHA2-128s. At verification, a hybrid row is valid only if the ECDSA leg and the Merkle/SLH-DSA leg both pass. `alg_version = 'hybrid-ecdsa-slhdsa-v1'` identifies the construction in the QRVA envelope.

```ts
interface HybridSignature {
  algVersion: 'hybrid-ecdsa-slhdsa-v1';
  ecdsa: string;    // base64 DER over "qrauth:ecdsa-canonical:v1:" || canonicalizeCore(...)
  merkleBatchId: string;
  merkleLeafHash: string;  // stored for comparison only; verification recomputes it
  merkleLeafNonce: string; // per-leaf nonce, 32 random bytes hex
  merklePath: MerkleNode[];
  rootSignature: string;   // base64 SLH-DSA over qrauth:merkle-root:v1: || root
}
```

Verification (simplified):

```ts
const ecdsaValid = verifyEcdsa(publicKey, sig.ecdsa, 'qrauth:ecdsa-canonical:v1:' + coreCanonical);
const leaf = sha3_256(Buffer.concat([Buffer.from([0x00]), Buffer.from(coreCanonical + '|' + sig.merkleLeafNonce, 'utf8')]));
const leafValid = constantTimeEqual(leaf, sig.merkleLeafHash);
const merkleValid = leafValid && verifyMerkleProof(leaf, sig.merklePath, merkleRoot);
const slhdsaValid = await slhDsaVerify(
  slhdsaPublicKey,
  Buffer.concat([Buffer.from('qrauth:merkle-root:v1:', 'utf8'), Buffer.from(merkleRoot, 'hex')]),
  Buffer.from(sig.rootSignature, 'base64'),
);
if (!ecdsaValid || !merkleValid || !slhdsaValid) return false;
```

ECDSA deprecation is not planned for the current release horizon. When PQC-only operation becomes appropriate, the `alg_version` agility mechanism in §11 handles the transition without breaking in-flight tokens.

Issuance awaits both legs before the row is written, so every issued row carries its ECDSA signature and complete Merkle data from the start. There is no intermediate state. The former transient version `ecdsa-pending-slhdsa-v1` (ECDSA signed, Merkle leg in flight) is no longer produced and is REJECTED at verification (§11.3). `qr_codes.algVersion` is required with no default, so every insert states the version it signed.

## 7. Layer 2 — MAC Pre-Filter

### 7.1 Role

The MAC is a fast-reject pre-filter. A `macTokenMac` column on a QR row, when populated, is recomputed and compared constant-time before the asymmetric legs run. A MAC mismatch fails the verification immediately. A MAC match allows verification to continue to ECDSA and SLH-DSA.

The MAC is not a replacement for asymmetric verification. A party holding a MAC secret (for example through database read access) cannot produce a verifiable QR with it: verification still requires a valid ECDSA-P256 signature and, for hybrid rows, a valid inclusion proof against an SLH-DSA-signed batch root, neither of which the MAC secret grants. This is the property that was broken in Audit-1 Finding-001 and restored in remediation.

Why keep the MAC at all if it does not gate asymmetric verification:

- **Cheap tampering detection.** HMAC-SHA3-256 is ~2 µs per verify. ECDSA is ~50 µs. SLH-DSA cold-cache is ~3 ms. Rejecting tampered inputs at the MAC layer saves asymmetric cycles on obviously bad requests (scanner misreading, network corruption, deliberate malformed input).
- **Cross-leg consistency.** The MAC and ECDSA legs verify against the same `canonicalizeCore` string, and the Merkle leaf is built at issuance from the same core plus the per-leaf nonce. A canonicalization drift between the MAC and ECDSA paths surfaces as a MAC or signature mismatch.

### 7.2 Implementation

`packages/api/src/services/mac.ts`:

```ts
export function computeMac(canonicalPayload: string, secret: Buffer): string {
  return createHmac('sha3-256', secret)
    .update(`qrauth:mac:v1:${canonicalPayload}`)
    .digest('hex');
}

export function macsEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const ba = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}
```

The domain separator `qrauth:mac:v1:` prevents the same tenant MAC secret from producing colliding MACs if it is ever reused in a different protocol under the same canonical input.

### 7.3 Key Ring and Rotation

`OrgMacKey` rows carry `(organizationId, version, secret, status)` where status is one of `ACTIVE`, `ROTATED`, `RETIRED`. Exactly one key per organization is `ACTIVE` at any time. On rotation:

1. Current `ACTIVE` row transitions to `ROTATED`.
2. New row is created with `version = max+1` and `status = ACTIVE`.
3. Verification tries the version stored on the QR row first; if that version has status `ACTIVE` or `ROTATED`, accept. `RETIRED` is rejected.
4. Rotation re-MACs every live QR row under the new key.
5. The `qrauth-cleanup` worker (hourly) rotates `ACTIVE` keys older than 90 days, moves a `ROTATED` key to `RETIRED` 30 days after rotation once no active QR row references it, and deletes `RETIRED` keys 7 days after retirement.

MAC secrets are stored in the database on `OrgMacKey` rows and loaded into API process memory for verification. Because the MAC is a pre-filter, holding a MAC secret does not let a party produce a verifiable QR (§7.1).

## 8. Layer 3 — Issuance Log: Hash Chain

### 8.1 Format

Every QR issuance appends an entry to a hash-chained issuance log in the QRAuth database (Prisma model `TransparencyLogEntry`; the model keeps its historical name). Implementation: `packages/api/src/services/transparency.ts`.

```ts
interface TransparencyLogEntry {
  logIndex: number;          // monotonic
  qrCodeId: string;
  organizationId: string;
  tokenHash: string;         // hex, SHA-256 of the token
  destinationHash: string;   // hex, SHA-256 of the destination URL
  geoHash: string | null;
  commitment: string | null; // hex, SHA3-256 Merkle leaf hash (hybrid rows)
  batchRootRef: string | null; // hex, SHA3-256 of the signed batch root
  merkleInclusionProof: MerkleNode[] | null;
  previousHash: string | null; // entryHash of the previous entry
  entryHash: string;         // hex, SHA-256 chain hash
  algVersion: string;
  createdAt: Date;
}
```

The chain hash is SHA-256 over the string concatenation of the previous entry's hash and the entry's content, plus the append timestamp:

```
entryHash = SHA-256(previousHash || commitment || batchRootRef || timestamp)                 // entries with a Merkle leaf
entryHash = SHA-256(previousHash || tokenHash || destinationHash || geoHash || timestamp)     // entries without one
```

`previousHash` is the empty string for the first entry. Entries for hybrid rows carry the SHA3-256 Merkle leaf hash and a reference to the SLH-DSA-signed batch root, linking the log to the Merkle batch described in §6.

### 8.2 Guarantee and limits

The issuance log provides tamper-evidence against a party who can read but not write the database, when the log is cross-checked against a previously saved snapshot: modifying an entry changes its `entryHash`, which breaks the `previousHash` link of every later entry.

It is not tamper-evident against a party with database write access, who can rebuild a consistent chain. The issuance log is a forensic record, not a cryptographic proof of append-only behaviour.

### 8.3 Planned redesign

An RFC 6962-style Merkle log with signed tree heads and external witnesses is specified in [`docs/adr/0001-transparency-log.md`](docs/adr/0001-transparency-log.md). It is not shipped. Until it ships, the guarantees are those stated in §8.2.

## 9. Layer 4 — WebAuthn Passkeys: Hybrid Bridge

### 9.1 Current state

WebAuthn credentials use ECDSA-P256 (COSE alg `-7`) by default. The credential is generated and stored inside authenticator hardware (Secure Enclave on Apple devices, Titan on Google, TPM on Windows). The algorithm choice is enforced at the hardware level; QRAuth cannot change it from the server side.

The classical vulnerability: from the public key (transmitted during assertion), Shor's algorithm on a future CRQC derives the private key. An adversary recording WebAuthn assertion responses today can forge them later. This is Scenario E in `THREAT_MODEL.md`.

### 9.2 The ML-DSA bridge (shipping)

QRAuth registers an optional ML-DSA-44 keypair alongside the WebAuthn credential. The bridge private key is generated in the user's browser, never on the server. Registration flow:

1. Client (web or SDK) imports `@noble/post-quantum/ml-dsa`.
2. Client generates the keypair locally.
3. Client stores the private half in IndexedDB scoped to the rpId origin.
4. Client sends only the public half to `POST /webauthn/register/verify` as `bridgePublicKeyBase64`.
5. Server validates byte length against `MLDSA_LENGTHS.publicKey`, validates the algorithm tag matches `MLDSA_PARAM_SET`, persists the public key on the `Passkey` row. Server never sees the private half.

The server-side ML-DSA keygen path that shipped in an earlier draft was rejected during Audit-1 (Finding-003) as violating the principle that private keys never traverse the network. The remediation moved keygen to the browser; `mlDsaGenerateKeyPair` is deleted from the server codebase. See `packages/api/src/services/webauthn.ts`.

### 9.3 Authentication

Bridge assertion runs alongside the standard WebAuthn assertion:

```
message = "qrauth:webauthn:bridge:v1" || webauthnChallenge
clientBridgeSig = ML-DSA_Sign(bridgePrivateKey_in_IndexedDB, message)
```

The client sends `bridgeSignature` in the assertion request. Passkeys registered with a bridge key carry this additional ML-DSA-44 signature, verified alongside the WebAuthn assertion when present via `mlDsaVerify(passkey.bridgePublicKey, message, bridgeSignature)`. Domain separator `qrauth:webauthn:bridge:v1` ensures the ML-DSA key cannot be repurposed for any other signed payload in the codebase.

### 9.4 Per-organization policy

`DevicePolicy.bridgePolicy` is a per-organization setting with the values `required`, `optional` and `disabled`. A user's effective policy is resolved as the strictest value across all of the user's organization memberships (`DevicePolicyService.resolveBridgePolicyForUser`).

### 9.5 FIDO PQC WebAuthn timeline

The FIDO Alliance PQC WebAuthn working group is expected to publish a specification in 2026–2027. Browser support is expected 2027–2028. The bridge is a transition mechanism until post-quantum credential types are available at the authenticator layer.

## 10. Layer 5 — Key Lifecycle

### 10.1 Keys in scope

Private key material in QRAuth:

- **Per-tenant ECDSA-P256 signing keys.** Encrypted at rest as an AES-256-GCM envelope (§10.2), with the public key on a `SigningKey` row. Generated on the API host and provisioned to the signer host (`SIGNER_KEYGEN=local`, default), or generated on the signer host, which returns only the public key (`SIGNER_KEYGEN=signer`). All ECDSA signing runs on the signer host in production (`ECDSA_SIGNER=http`).
- **Per-tenant SLH-DSA-SHA2-128s signing keys.** Generated, encrypted and provisioned in the same way, paired with the same `SigningKey` row. All SLH-DSA signing runs on the signer host in production (`SLH_DSA_SIGNER=http`).
- **RSA-2048 signing keys** for OIDC RS256 ID tokens. Same envelope format and provisioning; signed on the signer host via `/v1/sign-rsa-jws`.
- **Per-tenant HMAC-SHA3-256 MAC secrets.** Stored in the database as base64 on `OrgMacKey` rows. Loaded into API process memory for verification.
- **Living Codes root secret** (`ANIMATED_QR_SECRET`), from which frame secrets are derived with HKDF-SHA-256 per auth session and secret generation (info `frame_secret:<authSessionId>_g<n>`).

One master key at the infrastructure layer: `SIGNER_MASTER_KEY`. Base64-encoded 32 random bytes, loaded from the environment on the signer host (which decrypts envelopes) and, with `SIGNER_KEYGEN=local` or a local signing backend, on the API host (which encrypts new envelopes). With `SIGNER_KEYGEN=signer` and both signing backends `http`, the API host does not need it and logs a warning in production if it is set. Not automatically rotated.

### 10.2 At-rest encryption envelope

`packages/api/src/lib/key-at-rest.ts` and `packages/signer-service/src/key-at-rest.ts` (functionally identical):

```
envelope = "qrauth-kek-v1" || "\0" || base64(iv) || "\0" || base64(ct) || "\0" || base64(tag)
```

- AES-256-GCM, 12-byte IV, 16-byte authentication tag, random IV per encryption.
- Format tag `qrauth-kek-v1` is the domain separator. Both decryptors reject any envelope that does not start with the format tag; there is no plaintext pass-through.
- Atomic write: temp file + `fs.rename` within the same directory so a crash during key generation never leaves partial material on disk.

### 10.3 Rotation cadence

Driven by the hourly `qrauth-cleanup` worker:

- **Tenant signing keys** (`packages/api/src/workers/signing-key-rotation.ts`). States `ACTIVE`, `ROTATED`, `REVOKED`. An `ACTIVE` key older than 90 days (`SIGNING_KEY_ROTATION_DAYS`) is rotated: it becomes `ROTATED` (verify-only) and a same-algorithm replacement is minted. A `ROTATED` key becomes `REVOKED` 30 days after rotation (`SIGNING_KEY_REVOKE_GRACE_DAYS`), at day 120 with the defaults. A rotated key stays published in JWKS for 24 hours after rotation (`SIGNING_KEY_JWKS_WINDOW_HOURS`). `REVOKED` keys are excluded from status-filtered verification and from JWKS; rows and envelopes are retained, and QR and batch verification resolve the key by reference, so issued QRs keep verifying.
- **MAC secrets.** States `ACTIVE`, `ROTATED`, `RETIRED`, on a 90/30/7 cadence: rotate after 90 days (re-MACing live rows), retire 30 days after rotation once no active row references the key, delete 7 days after retirement (§7.3).
- **SIGNER_MASTER_KEY.** No automatic rotation.

SLH-DSA is stateless (no XMSS-style leaf index to track). The rotation discipline is for audit traceability and to bound the blast radius of a key compromise, not for correctness.

## 11. Algorithm Agility in the QRVA Protocol

### 11.1 Mandate

QR signatures (inside the canonical form), issuance-log entries, and proximity attestations carry an explicit `alg_version` field. Verifiers pin to this field and dispatch accordingly. Unknown versions fail closed.

### 11.2 Payload envelope

The canonical form itself commits to `alg_version` as its first field. There is no outer envelope wrapping the canonical form; the algorithm commitment is inside the bytes being signed.

```ts
// canonicalizeCore
[algVersion, token, tenantId, destHash, geoHash, expiresAt].join('|')
```

This binds the signature to a specific algorithm: a signature produced under `hybrid-ecdsa-slhdsa-v1` cannot be repurposed as a signature under a different (weaker) version because the signed bytes include the version string.

### 11.3 Version sets

Maintained in `packages/shared/src/alg-versions.ts`:

```ts
ACCEPTED_ALG_VERSIONS = {
  'hybrid-ecdsa-slhdsa-v1',     // shipping; the only version with a verifier
};

DEPRECATED_ALG_VERSIONS = {};   // none post-cutover

REJECTED_ALG_VERSIONS = {
  'ecdsa-p256-sha256-v1',       // legacy; no QRs use this post-cutover
  'ecdsa-pending-slhdsa-v1',    // former transient state; no longer issued
  'slhdsa-sha2-128s-v1',        // PQC-only; reserved, no verifier yet
  'slhdsa-sha2-256s-v1',        // high-security PQC variant; reserved, no verifier yet
};
```

A version is ACCEPTED only when a verifier for it ships. The reserved PQC-only versions move to ACCEPTED in the change that adds their verifier, not before.

`checkAlgVersion` classifies an input string:

- `accepted` → verification proceeds silently.
- `deprecated` → verification proceeds with a warning log and a `warnings` field on the response (`ALG_DEPRECATED`).
- `rejected` → verification fails closed.
- `unknown` → verification fails closed.

Pre-cutover, `ecdsa-p256-sha256-v1` was classified as `deprecated`. Post-cutover it moves to `rejected` as part of the cutover checklist (Audit-2 N-6). `ecdsa-pending-slhdsa-v1` moved from `accepted` to `rejected` in v2.2, when the asynchronous issuance path was removed. Any future move from `accepted` to `deprecated` requires updating this section of the document and the policy file in the same commit.

## 12. Rollout Invariants

The following cannot change without a coordinated QRVA protocol version bump and a new ACCEPTED entry in §11.3. Changes to any of them break every issued QR under the current version and require re-issuance.

1. **Canonical payload field order.** `algVersion | token | tenantId | destHash | geoHash | expiresAt` for the core form, with `| nonce` appended for Merkle leaves. Field count, field names, and separator are fixed.
2. **Merkle tree construction rules.** `0x00` leaf prefix, `0x01` node prefix, power-of-2 padding with unique padding leaves, bytes-level internal-node concatenation.
3. **Signer domain-separation prefixes.** `qrauth:merkle-root:v1:` on the SLH-DSA signing path; `qrauth:ecdsa-canonical:v1:` on the ECDSA signing path (shipping as of Audit-2 N-2). Changing either requires a new protocol version because verifiers reconstruct the prefix.
4. **At-rest envelope format.** `qrauth-kek-v1\0base64(iv)\0base64(ct)\0base64(tag)` with AES-256-GCM. Format tag is the version identifier.
5. **Proximity attestation JWT header, claims structure, and signed-bytes envelope.** Header includes `alg`, `typ`, `kid`. Claims include `iss`, `sub`, `aud`, `device`, `loc`, `proximity`, `alg_version`, `iat`, `exp`. The signed bytes are `qrauth:ecdsa-canonical:v1:` || `header.payload` (domain-separated per invariant 3; see §16). Adding a claim is backwards-compatible; removing or repurposing one, or changing the signed-bytes envelope, is not.
6. **Auth-session approval signature domain and field order.** Domain `qrauth:auth-session:v1`. Fields `algVersion | kid | sessionId | userId | appId | resolvedAtIso`.
7. **WebAuthn bridge signing domain.** `qrauth:webauthn:bridge:v1` || challenge bytes.
8. **Animated-QR frame-signing input format.** `baseUrl || ":" || timestamp || ":" || frameIndex`. 8-byte HMAC tag truncation.

Any change to the above requires: (a) a new `qrva-v3` (or higher) protocol version, (b) a new ACCEPTED entry in §11.3, (c) coordinated updates to the Node SDK and any future language SDK, (d) cross-language protocol tests under `packages/protocol-tests/` regenerated and green in CI, (e) an update to this section documenting what changed.

## 13. Implementation Concerns and Pitfalls

### 13.1 Signer service isolation

In production, all signing runs on the signer host (`packages/signer-service/`): the API sends canonical bytes and receives signatures. Private keys are encrypted at rest under `SIGNER_MASTER_KEY` (§10.2); they are either generated on the API host and provisioned to the signer host (`SIGNER_KEYGEN=local`), or generated on the signer host (`SIGNER_KEYGEN=signer`). The API authenticates to the signer with a bearer token. The signer exposes:

- `POST /v1/sign` (SLH-DSA), `POST /v1/sign-ecdsa` (ECDSA-P256 canonical), `POST /v1/sign-ecdsa-jws` and `POST /v1/sign-rsa-jws` (OIDC ID-token JWS input, which must match `base64url.base64url`).
- `POST /v1/mac/session`, `POST /v1/mac/sign`, `POST /v1/mac/verify` (Living Codes frame MACs).
- `POST /v1/keys/generate` (key generation), `POST /v1/keys/:keyId` (key provisioning) and `GET /v1/keys/:keyId/public`.
- `GET /healthz` and `GET /internal/stats`.

The two canonical sign endpoints:

**`POST /v1/sign` — SLH-DSA.** Accepts `{ keyId, message }` with `message` base64-encoded. Prepends the domain-separation prefix `qrauth:merkle-root:v1:` before calling `slh_dsa_sha2_128s.sign`. Returns `{ signature }` base64. Signatures from this endpoint are bound to the Merkle-root domain.

**`POST /v1/sign-ecdsa` — ECDSA-P256.** Accepts `{ keyId, message }` with `message` as UTF-8 canonical form. Prepends the domain-separation prefix `qrauth:ecdsa-canonical:v1:` before calling `createSign('SHA256').update(...).sign(pem)`. The API-side verifier reconstructs the same prefix.

**Bearer token.** Minimum 32 characters; refuses to start below that. Constant-time comparison via `crypto.timingSafeEqual`.

**Audit log.** Every sign operation logs `{keyId, messageFingerprint, messageBytes, signatureBytes, alg}` at `info`. `messageFingerprint` is the full SHA3-256 hex digest of the signed bytes (pre-prefix). Retention is the operator's responsibility; we recommend at least 12 months.

**`POST /v1/keys/:keyId` — Key provisioning.** Accepts `{ ecdsa?, slhdsa?, rsa? }` with encrypted envelope strings. Validates the `qrauth-kek-v1` format tag before writing. Rejects overwrites (409 Conflict). Atomic writes (temp + rename). Clears the sign caches for the provisioned keyId. Used by `SigningService.pushKeysToSigner()` during `createKeyPair()` and `rotateKey()` — no manual key distribution required.

**`POST /v1/keys/generate` — Key generation.** Accepts exactly `{ kind }` with `kind` `es256-slhdsa` or `rs256`. Generates the pair on the signer (EC P-256 plus SLH-DSA-SHA2-128s from a 48-byte random seed, or RSA-2048), assigns a random UUID keyId, writes the envelope(s) atomically (temp file 0600, fsync, rename; never overwrites), and returns `{ keyId, kind, publicKey, slhdsaPublicKey? }`. Private bytes never leave the signer. Logs keyId and kind only. Used by `SigningService` when `SIGNER_KEYGEN=signer`; the API validates the returned key types and lengths before writing the `SigningKey` row.

**ECDSA signer backend.** The API server supports `ECDSA_SIGNER=local` (in-process, dev only) and `ECDSA_SIGNER=http` (remote signer, production). The `ecdsa-signer` Fastify plugin selects the backend at boot and decorates a shared `SigningService` instance. All route plugins use `fastify.signingService`. Any `SigningService` constructed without explicit signers uses the configured backends: with `ECDSA_SIGNER=http` that is the remote ECDSA and RSA signer, never a local one (the cleanup worker's rotation probe and signing canary included). This mirrors the existing `SLH_DSA_SIGNER` pattern. With both signers set to `http`, the API host performs no ECDSA or SLH-DSA signing.

**Dual-token rotation (Audit-3 H-5).** The signer accepts `SIGNER_TOKEN_NEXT` alongside `SIGNER_TOKEN` for zero-downtime token rotation. Both are checked constant-time. Rotation procedure: set `SIGNER_TOKEN_NEXT` on signer → restart signer → update API tokens → restart API → promote and remove `SIGNER_TOKEN_NEXT`.

**Key load.** Encrypted envelopes are read lazily on first use and cached per-keyId in process memory. Cache is cleared on process restart or key provisioning. Path traversal is defended via a `^[a-zA-Z0-9._-]+$` keyId regex check before filesystem access.

### 13.2 Signature size

SLH-DSA-SHA2-128s signatures are 7,856 bytes. Too large for inline encoding in the QR image; the QR encodes only the token, signatures are fetched server-side during verification. Public keys are 32 bytes, secret keys 64 bytes, seed 48 bytes.

The alternative parameter set `sha2-256s` is declared (reserved) in `ALG_VERSION_POLICY` as `slhdsa-sha2-256s-v1` but not used by current code, and is REJECTED at verification (§11.3).

### 13.3 Merkle tree second-preimage defenses

Three independent defenses compose:

1. **Leaf / node domain separation.** Leaf hashes use `0x00` prefix; internal node hashes use `0x01` prefix. An adversary cannot construct an internal node that hashes to a leaf value.
2. **Per-leaf nonce.** Every leaf commits to a random 32-byte nonce. Two distinct QRs with otherwise-identical canonical payloads produce distinct leaves.
3. **Unique padding leaves.** Padding to power-of-2 uses index-dependent hashes (`SHA3-256(0x00 || "qrauth-pad:" || paddedIndex)`) so two batches of different real-leaf count cannot collide on root after padding.

### 13.4 Timing attacks

Every MAC, hash, signature, or challenge comparison uses `constantTimeEqualString` from `packages/api/src/lib/constant-time.ts`, which wraps `crypto.timingSafeEqual` after a length check. The ESLint rule in `packages/api/eslint.config.mjs` (severity `error`) flags `===`/`!==` on identifiers and member properties matching `/(Signature|Mac|Hash|Challenge|Verifier)$/i`. CI runs `npm run lint` across workspaces, so a violation fails the build.

### 13.5 Canonical serialization across SDKs

The canonical form in §6.2 must produce byte-identical output in the Node implementation and any future language SDK. The authoritative implementation is `packages/shared/src/canonical.ts`. Canonical-form vectors are pinned in `packages/protocol-tests/fixtures/canonical-vectors.json`; the Node implementation is checked against them in CI, and any other-language implementation must reproduce them.

Subtle risks:

- **Float formatting.** `lat.toFixed(7)` in JavaScript and, for example, `format(lat, '.7f')` in a Python implementation may disagree on rounding for edge values (5-bit-rounded halves). Test vectors include edge floats; if a divergence appears, the fix is to pin a language-agnostic decimal formatting convention rather than trust language primitives.
- **Integer truncation.** `Math.trunc(radiusM)` and, for example, Python `int(radiusM)` agree for positive integers but diverge for negative values. `radiusM` is always positive by schema; vectors cover zero and large positives.
- **Unicode.** Field inputs are validated against `|`, `\n`, `\0` but not against non-ASCII. Tokens are base64url (ASCII-only by construction). `tenantId` is a CUID (ASCII). `destHash` and `geoHash` are hex (ASCII). `expiresAt` is ISO 8601 (ASCII). `algVersion` is a fixed-string set. Non-ASCII input would be a schema violation, not a canonical-form concern.

### 13.6 Batch size limits

SLH-DSA-SHA2-128s signing takes ~2.0–2.4 s per signature with `@noble/post-quantum` (pure TypeScript) on developer hardware. Batching amortizes that cost: a batch flushes at 64 items or after a 200 ms wait, and its root is signed once. Per-QR issuance latency is dominated by the SLH-DSA sign (~2 s), not by the 200 ms batch window.

Batch size is bounded by SLH-DSA signing throughput, not by the Merkle tree (SHA3-256 is ~1 µs per node). One signer process signs ~0.4–0.5 batch roots per second, which at 64 leaves per batch is ~25–30 QR issuances per second per signer process.

### 13.7 Do not roll your own crypto

Every primitive in this document comes from Node's standard library `crypto` module, `@noble/post-quantum`, or an established library for a specific protocol (`@simplewebauthn/server` for WebAuthn, `@fastify/jwt` and `jose` for JWT). No hand-rolled hash, MAC, KDF, signing, or verifying code is permitted anywhere in QRAuth. The only custom cryptographic code is orchestration: Merkle tree traversal, canonical payload construction, envelope parsing. These are covered by the protocol-test suite (§14).

## 14. Testing Requirements

### 14.1 Test vectors

Deterministic canonical-form vectors live in `packages/protocol-tests/fixtures/canonical-vectors.json`. They cover URL QRs, content QRs, far-future expiry, empty-string expiry, bound geo, unbound geo, edge-decimal lat/lng, and the corresponding Merkle leaf hashes. A `leafBinding` section pins verifier behaviour: for each case it gives the payload and nonce a verifier sees, the leaf it must recompute, and whether that leaf matches the stored one (`accept`) or not (`reject`). An unchanged payload is accepted; a change to any bound field or to the nonce is rejected.

Round-trip and known-answer tests in `packages/protocol-tests/src/` cover SLH-DSA signing and verification, ML-DSA-44, Merkle tree construction and inclusion proofs, hybrid verification, the MAC pre-filter, ECDSA domain separation, the batch signer, `alg_version` classification, bridge policy resolution, and the WebAuthn bridge. Proximity attestation signing and verification are covered by unit tests in `packages/api`.

### 14.2 Cross-language consistency

The protocol-test suite (`packages/protocol-tests/`, 21 test files, 259 tests; CI runs them under UTC and Europe/Athens) passes, and the CI job `protocol-tests` gates deploy. The Node reference implementation is checked against the canonical vectors in that job; any future language SDK must consume the same vector file and produce byte-identical output.

### 14.3 Fuzzing

`fast-check` property tests cover canonical-form round-trips and Merkle proof verification (`canonical-fuzz.test.ts`, `merkle-fuzz.test.ts`, `merkle-tree-fuzz.test.ts` in `packages/protocol-tests/src/`).

### 14.4 Performance benchmarks

Measured on developer hardware. Verify-path figures from `packages/api/test/bench/verify.bench.ts`; SLH-DSA sign and verify with `@noble/post-quantum`:

- Leaf hash computation: under 1 ms per leaf.
- Merkle path walk (depth 10): ~10 µs.
- Merkle proof verification: under 1 ms for any realistic tree depth.
- SLH-DSA-SHA2-128s sign: ~2.0–2.4 s per signature (one per batch root).
- SLH-DSA-SHA2-128s verify (cold cache): ~3 ms.
- SLH-DSA verify (warm cache via `BatchRootVerifyCache`): O(1) Map lookup, sub-microsecond.
- Full hybrid verify (ECDSA + Merkle + cached SLH-DSA): P50 ~0.15 ms, P95 ~0.18 ms.

## 15. Dependency Reference

| Purpose | Library | Version | Notes |
|---|---|---|---|
| SLH-DSA, ML-DSA | `@noble/post-quantum` | pinned in `package-lock.json` | Audited, pure TypeScript, no WASM. |
| SHA3-256, HMAC, AES-GCM, ECDSA | Node standard library `crypto` | Node 22+ | SHA3 native via OpenSSL 3.x. |
| Constant-time comparison | Node `crypto.timingSafeEqual` | Node 22+ | Used via `constantTimeEqualString`. |
| Random bytes | Node `crypto.randomBytes` | Node 22+ | `getrandom(2)` on Linux. |
| Merkle trees | Custom | — | `packages/api/src/services/merkle-signing.ts`. Not from a third-party library. |
| WebAuthn server | `@simplewebauthn/server` | pinned | FIDO2 compliant. |
| JWT signing (session tokens) | `@fastify/jwt` | pinned | HS256 only. |
| JOSE | `jose` | pinned | JWKS export and verification of third-party OAuth/OIDC tokens. |
| Fastify plugins | `fastify` and ecosystem | pinned | See `package-lock.json`. |
| ORM | `prisma` | pinned | Parameterized queries. |

Supply-chain trust for these dependencies is assumed per `THREAT_MODEL.md` Out of Scope ("Supply-chain compromise of cryptographic libraries"). We pin versions via `package-lock.json` and run a production dependency audit in CI (`scripts/audit-prod.mjs`); we cannot defend cryptographically against a library maintainer shipping a backdoor.

## 16. Integrator Mechanism Reference

This section is a mechanism index for integrators writing code against QRAuth. Each mechanism is specified in more detail elsewhere in this file; this section is a one-stop pointer.

QRAuth sends two kinds of webhook, each signed over the raw request body.

**App webhooks.** Integration events (for example `qrcode.revoked`) delivered to an app's registered `webhookUrl`. HMAC-SHA-256, keyed with the app's webhook signing key: the lowercase hex SHA-256 of the app's client secret, used as the HMAC key string.

```
POST <app webhookUrl>
Headers:
  Content-Type: application/json
  X-QRAuth-Event: <event>
  X-QRAuth-Signature: sha256=<hex>
  User-Agent: QRAuth-Webhooks/1.0
Body:
  { "event": "<event>", "timestamp": "<ISO 8601>", "data": { ... } }
```

Integrator validates `HMAC-SHA-256(hex(SHA-256(clientSecret)), rawBody)`, constant-time compared to the hex after `sha256=`. See `packages/api/src/services/webhook.ts`.

**M-13 signing-key-registration webhook.** Fires on every `SigningKey` row creation. HMAC-SHA3-256 signed with the organization's webhook secret (32 random bytes, base64; the HMAC key is the decoded bytes). See `packages/api/src/services/security-webhook.ts`.

```
POST <integrator-registered-endpoint>
Headers:
  Content-Type: application/json
  X-QRAuth-Event: signing-key.created
  X-QRAuth-Signature: sha3-256=<hex>
  User-Agent: QRAuth-Security-Webhook/1
Body:
  {
    "eventId": "<uuid>",
    "eventType": "signing-key.created",
    "occurredAt": "<ISO 8601>",
    "organizationId": "<cuid>",
    "signingKey": {
      "kid": "<key id>",
      "algorithm": "ES256",
      "slhdsaAlgorithm": "slh-dsa-sha2-128s",
      "status": "ACTIVE",
      "createdAt": "<ISO 8601>"
    },
    "operatorIdentity": null
  }
```

`algorithm` is `"RS256"` with `slhdsaAlgorithm: null` for OIDC RSA keys. Integrator validates the signature via `HMAC-SHA3-256(webhookSecret, rawBody)` constant-time compared to `X-QRAuth-Signature`. An event that does not correspond to a legitimate key creation or rotation is the signal to start incident response (see `SECURITY.md`, Incident Response).

**PKCE auth-session envelope.** Public-client flow requires `code_challenge` at session creation and `code_verifier` at retrieval. Challenge method is always `S256`. See `packages/api/src/routes/auth-sessions.ts`.

**Animated-QR frame envelope.** URL form: `<baseUrl>?f=<frameIndex>&t=<timestampMs>&h=<hmacHex16>`. HMAC is the first 16 hex characters of `HMAC-SHA-256(frameSecret, baseUrl + ":" + timestamp + ":" + frameIndex)`. `frameSecret` is derived server-side per auth session and secret generation and supplied to the rendering client. A confidential client receives it from `POST /api/v1/animated-qr/session` with its client secret. A public client registers `frameChallenge = base64url(SHA-256(frameVerifier))` at `POST /session` (set once per auth session) and receives the secret from `POST /session/secret` only on presenting `frameVerifier` in the request body. Every issuance starts a new generation; only the current generation verifies, and the frame-index replay check is kept per generation. The frame-verify endpoint (`POST /api/v1/animated-qr/validate`) accepts a frame whose timestamp is at most 5 s old and at most 2 s in the future, and requires a strictly increasing frame index per session.

**Proximity attestation JWT.** A proximity attestation states that the device reported a location within `radiusM` metres of the QR code's registered location at time `iat`, signed by the issuing organization. The location is reported by the client; the attestation is not proof of physical presence. Request: `POST /api/v1/proximity/:token` with `clientLat`, `clientLng`, `rpId` and `deviceFingerprint`. ES256, compact. Header: `{alg, typ, kid}`. Claims: `iss` (organization ID), `sub` = hex `SHA3-256("qrauth:proximity-sub:v1:" || token)`, `aud` (the supplied `rpId`), `device` = hex `SHA3-256("qrauth:proximity-device:v1:" || deviceFingerprint)`, `loc` (the QR code's registered geohash, not the device's coordinates), `proximity: {matched, distanceM, radiusM}`, `alg_version`, `iat`, `exp`. `exp` is `iat + 300`. Verifier resolves public key by `(iss, kid)` against signing keys in state `ACTIVE` or `ROTATED`.

*Signed-bytes envelope (non-standard, important for integrators):* the ECDSA signature covers `qrauth:ecdsa-canonical:v1:` || `header.payload`, not the bare `header.payload` string that stock JWT libraries feed to ECDSA verification. This is the ECDSA domain separation introduced in Audit-2 N-2 (§12, invariant 3). The signature segment is the base64url encoding of a DER-encoded ECDSA signature, not the JWS `R || S` form. Stock JWT libraries (`jsonwebtoken`, `PyJWT`, `jose`, `jwt-go`) will reject QRAuth proximity attestations on signature verification. Integrators verify attestations with `verifyProximityAttestation` from `@qrauth/node`, which calls the QRAuth verify endpoint (`POST /api/v1/proximity/verify`). See `packages/api/src/services/proximity.ts`.

**Ephemeral session claim.** `POST /api/v1/ephemeral/:token/claim` with optional `deviceFingerprint`. Returns the claim payload only if the CAS-guarded update succeeds. Retry up to 5 times on contention.

**Auth-session approval signature envelope.** `<kid>:<base64sig>`. Canonical bytes signed: `qrauth:auth-session:v1 | qrauth-auth-session-v1 | kid | sessionId | userId | appId | resolvedAtIso`. Verifier resolves public key by `(organizationId, kid)`.

**Revocation.** `DELETE /api/v1/qrcodes/:token` sets status to `REVOKED`. Subsequent verification fails with a revoked result immediately. Integrator caches must invalidate on revocation signal.

## 17. Version History

**v2.3** — 2026-10-21. Signer-side key generation.

- §10.1, §13.1: `SIGNER_KEYGEN=signer` generates tenant key pairs on the signer host (`POST /v1/keys/generate`); the API receives public keys only and needs no `SIGNER_MASTER_KEY`. `SIGNER_KEYGEN=local` (default) keeps API-side generation and provisioning.
- §13.1: `SigningService` defaults follow the configured backends; with `ECDSA_SIGNER=http` RSA signing in the worker goes through the signer.

**v2.2** — 2026-10-20. Merkle leaf bound to the verified payload.

- §6.3, §6.4: verification recomputes the Merkle leaf as `SHA3-256(0x00 || coreCanonical || "|" || nonce)` from the row's canonical core and stored nonce, compares it with the stored leaf in constant time, and walks the inclusion proof from the recomputed value. A hybrid row without batch id, leaf hash, nonce or inclusion path fails closed.
- §6.3: the batch must belong to the row's organization; non-hybrid versions fail signature verification.
- §6.4: issuance has a single synchronous path; the transient pending state and its reconciler are removed. `qr_codes.algVersion` is required with no default.
- §11.3: `ecdsa-pending-slhdsa-v1`, `slhdsa-sha2-128s-v1` and `slhdsa-sha2-256s-v1` moved from ACCEPTED to REJECTED; a version is accepted only once its verifier ships.
- §14.1: an expiry one millisecond before midnight UTC added to the vectors; protocol tests run under UTC and Europe/Athens in CI.
- §14.1: leaf-binding vectors added to `packages/protocol-tests/fixtures/canonical-vectors.json`.

**v2.1** — 2026-10-20. Documentation aligned with the code.

- §1, §4, §6.1, §6.3, §6.4: verification described as implemented: MAC pre-filter, ECDSA-P256 over the domain-separated canonical core, Merkle inclusion-proof verification, SLH-DSA-SHA2-128s batch-root verification (cached).
- §2: threat references re-pointed to the scenarios A–F in `THREAT_MODEL.md`.
- §3: added issuance-log, app-webhook, signing-key-webhook and OIDC ID-token rows; listed every SHA-256 use.
- §7.3: MAC key rotation, re-MACing, retirement and purge are automated by the `qrauth-cleanup` worker; MAC secrets are stored in the database.
- §8: retitled "Issuance Log: Hash Chain"; SHA-256 chain hash documented; planned redesign linked to `docs/adr/0001-transparency-log.md`.
- §9.4: bridge policy reduced to the setting and its resolution across memberships.
- §10.1, §10.3, §13.1: key custody and the tenant signing-key lifecycle (`ACTIVE` 90 days, `ROTATED`, `REVOKED` 30 days after rotation) documented as implemented; RSA OIDC keys and the full signer endpoint list added.
- §13.6, §14.4: SLH-DSA-SHA2-128s signing time (~2.0–2.4 s) and per-signer throughput (~25–30 QR issuances per second) corrected from measurement.
- §16: both webhook systems documented; proximity attestation claims, request fields and verification path documented as implemented.
- Audit-2 items closed: N-1 (pending reconciler, §6.4), N-3 (plaintext envelope fallback removed, §10.2), N-4 (constant-time ESLint rule enforced in CI, §13.4), N-7 (protocol-test suite green and gating deploy, §14.2).
- §14.3: `fast-check` property tests for canonical form and Merkle proofs documented.
- References to SDKs other than `@qrauth/node` removed.

**v2.0** — Post Audit-2 remediation. Complete rewrite under the spec-driven-workflow model. Now the single source of truth for cryptographic architecture; threat analysis moved to `THREAT_MODEL.md`; operator/integrator summaries moved to `SECURITY.md`. Major changes from v1.x:

- §2 collapsed to a pointer to `THREAT_MODEL.md`.
- §3 replaced: the "current state audit" (pre-remediation vulnerable-primitives listing) is now historical; §3 lists as-shipped primitives.
- §4 reframed: the core principle is now "hybrid verification with batched asymmetric cost," not "hash-native with symmetric-only hot path." The MAC is a pre-filter, not a replacement.
- §5 collapsed to direct `crypto.randomBytes` wrapper per Audit-1 Finding-017+023 decision (b).
- §6 updated: canonical form unified across MAC / ECDSA / Merkle per Audit-1 Findings 011/019/020/021. `computeDestHash` with content-type domain tag. File paths updated. `BatchRootVerifyCache` documented. Domain-separation prefix on signer endpoints documented.
- §7 renamed and rewritten: "MAC Pre-Filter." MAC does not short-circuit asymmetric verification per Audit-1 Finding-001.
- §8 separated the current log from the planned RFC 6962-style redesign in `docs/adr/0001-transparency-log.md`.
- §9 rewritten: ML-DSA bridge keygen moved to the browser per Audit-1 Finding-003. Per-org `bridgePolicy` documented.
- §10 simplified: SLH-DSA is stateless; XMSS-style leaf-index discipline removed. Rotation cadence matches `qrauth-cleanup` worker (90/30/7). At-rest envelope format documented.
- §11 updated: `alg_version` is inside the canonical form, not in a wrapper envelope. `ecdsa-p256-sha256-v1` moves to REJECTED post-cutover per Audit-2 N-6.
- §12 deleted: "Migration Strategy" was a pre-production rollout plan that is now superseded. Replaced with "Rollout Invariants" — what cannot change without a protocol version bump.
- §13 updated: signer service documents both `/v1/sign` and `/v1/sign-ecdsa` with their respective domain-separation prefixes. `constantTimeEqualString` helper referenced.
- §14 updated: benchmark numbers replaced with Audit-2 measurements. Protocol-test regression (N-7) noted as a pre-ship item.
- §15 updated: removed aspirational KMS integration snippet; reflects the collapsed entropy decision.
- §16 new: integrator mechanism reference for M-13 webhook and related envelopes.

**v1.x** — Previous iterations. Superseded.
