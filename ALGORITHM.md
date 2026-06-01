# QRAuth — Cryptographic Architecture

**Version:** 2.0 (post Audit-2 remediation)
**Status:** Authoritative. This file is the single source of truth for QRAuth's cryptographic mechanisms, wire formats, and parameter choices. Threat analysis and adversary catalogs live in `THREAT_MODEL.md`; operator-facing and integrator-facing summaries live in `SECURITY.md`. When this file disagrees with implementation, this file is wrong and must be amended before code changes — the spec drives.
**Last reviewed:** Audit-2 remediation cycle.
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
8. Layer 3 — Transparency Log: Commitment-Only
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

The threat model this construction defends against — adversary capabilities, attack scenarios, residual risk — is specified separately in `THREAT_MODEL.md`. When a design choice in this document is justified by a threat, it cites the adversary or threat identifier from that document rather than duplicating the analysis.

The security of the hot verification path reduces to: the unforgeability of SLH-DSA-SHA2-128s under harvest-now-attack-later quantum adversaries, the unforgeability of ECDSA-P256 under classical adversaries (defense in depth), the preimage resistance of SHA3-256, and the MAC security of HMAC-SHA3-256. Grover's algorithm degrades SHA3-256 from 256-bit to 128-bit effective security — computationally intractable for any conceivable hardware.

## 2. Threat Model

The threat model is maintained in `THREAT_MODEL.md`. That document enumerates adversaries (A-NET, A-HOLDER, A-SCANSPOOF, A-RP, A-DB-READ, A-DB-WRITE, A-FS-KEYS, A-BEARER, A-CDN, A-CRQC-FUTURE), assets (nine, in priority order), threats (T-1 through T-22), and mitigations (M-1 through M-13).

This file specifies the mechanisms those mitigations compose into. When a design choice below references an adversary or threat, it cites the identifier from `THREAT_MODEL.md` rather than duplicating the analysis. A reader reviewing this document for protocol soundness should read the threat model first, then return here.

## 3. As-Shipped Cryptographic State

The following primitives are currently implemented and in use. Files are paths relative to repository root.

| Layer | Primitive | Algorithm | Files | Post-quantum |
|---|---|---|---|---|
| QR signing (PQC leg) | Merkle batch + SLH-DSA | SLH-DSA-SHA2-128s (FIPS 205) | `packages/api/src/services/merkle-signing.ts`, `packages/api/src/services/slhdsa-adapter.ts`, `packages/signer-service/src/server.ts` | Resistant |
| QR signing (classical leg) | ECDSA-P256 | ECDSA-P256 SHA-256 (FIPS 186-4) | `packages/api/src/services/signing.ts`, `packages/api/src/services/ecdsa-signer/`, `packages/signer-service/src/server.ts` | Classical only; present for defense in depth |
| Canonical form | SHA3-256 | FIPS 202 | `packages/shared/src/canonical.ts` | Resistant |
| Merkle tree hashing | SHA3-256 | FIPS 202 | `packages/api/src/services/merkle-signing.ts` | Resistant |
| MAC pre-filter | HMAC-SHA3-256 | FIPS 198 / FIPS 202 | `packages/api/src/services/mac.ts` | Resistant |
| Proximity attestation | ES256-style JWT (domain-separated signed bytes — not portable to stock JWT libraries) with `kid`/`aud`/`device`/`alg_version` | FIPS 186-4 | `packages/api/src/services/proximity.ts` | Classical only; PQC planned |
| Auth-session approval | ECDSA-P256 over unified canonical form | FIPS 186-4 | `packages/api/src/services/auth-session.ts` | Classical only |
| Animated-QR frame signing | HMAC-SHA-256 (transitional) | FIPS 198 / FIPS 180-4 | `packages/api/src/services/animated-qr.ts` | Resistant (SHA3 migration deferred) |
| WebAuthn credentials | ECDSA-P256 | FIPS 186-4 | hardware authenticators | Classical only |
| WebAuthn PQC bridge | ML-DSA-44 | FIPS 204 | `packages/api/src/services/webauthn.ts`, client browser | Resistant |
| At-rest encryption | AES-256-GCM | FIPS 197 | `packages/api/src/lib/key-at-rest.ts`, `packages/signer-service/src/key-at-rest.ts` | Resistant |
| Webhook signatures | HMAC-SHA3-256 | FIPS 198 / FIPS 202 | `packages/api/src/services/webhook.ts` | Resistant |
| JWT session signing | HS256 (HMAC-SHA256) | RFC 7518 | `packages/api/src/middleware/auth.ts` | Resistant |
| Entropy | `crypto.randomBytes` | kernel CSPRNG | `packages/api/src/lib/entropy.ts` | — |

SHA-256 (classical) remains in use only for ECDSA-P256 signing (required by the primitive), for JWT HS256 signing, for animated-QR HMAC (deferred migration, tracked as Audit-1 Finding-013), and for legacy content-hash inputs passed to `computeDestHash`. Every other hash site uses SHA3-256.

## 4. Core Principle: Hybrid Verification with Batched Asymmetric Cost

Earlier drafts of this document described QRAuth as having a "hash-native" verification path where asymmetric operations lived only at issuance and verification reduced to hash preimage resistance. That characterization was too strong, and Audit-1 identified a specific instance — the MAC fast path — where the implementation had taken the characterization literally and allowed the MAC to short-circuit asymmetric verification. The remediation removed the short-circuit. The accurate characterization is:

**The per-QR asymmetric cost is amortized across a batch, not per-request.** Every hybrid row's verification runs the ECDSA-P256 leg, the Merkle inclusion proof, and the SLH-DSA-SHA2-128s batch root signature check. The ECDSA verify is ~50 µs. The Merkle path walk is ~10 µs. The SLH-DSA verify is ~3 ms on a cold cache, O(1) lookup on a warm cache (1-hour TTL per `batchId`, 10k-entry LRU). In aggregate, hot-path P50 is ~0.15 ms and P95 is ~0.18 ms, measured in `packages/api/test/bench/verify.bench.ts`.

**The MAC is a pre-filter.** A `macTokenMac` column on a QR row, when present, is recomputed and compared constant-time before asymmetric verification runs. A MAC mismatch is a fast-reject; a MAC match does not short-circuit anything. The MAC's role is to cheaply reject tampered or malformed inputs before cryptographic cycles are spent on them, and to provide an independent integrity check over the same canonical bytes the asymmetric legs bind to. It does not replace the asymmetric legs. See §7 and M-3 in `THREAT_MODEL.md`.

**No algebraic structure for a quantum adversary to attack.** The SLH-DSA leg is hash-based. Its private keys are not recoverable from signatures under any known quantum algorithm. The hybrid construction means an adversary who breaks ECDSA-P256 via Shor's algorithm still faces an unbroken SLH-DSA leg over the same payload. This is the defense that addresses T-10 (harvest-now-attack-later).

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

Per-QR asymmetric signing would make the signer service the bottleneck of issuance. Instead, each QR contributes a SHA3-256 leaf hash to a Merkle tree; the tree's root is signed once via SLH-DSA-SHA2-128s on the signer host; each QR carries its inclusion proof. At verification, a client walks the inclusion proof to reconstruct the root, then verifies the SLH-DSA signature over that root.

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
2. Verify the ECDSA leg: `verifySignature(signingKey.publicKey, row.signature, coreCanonical)`.
3. If the row is a hybrid row (has `merkleBatchId`, `merkleLeafHash`, `merklePath` populated and `algVersion === 'hybrid-ecdsa-slhdsa-v1'`), verify the Merkle inclusion proof and SLH-DSA batch-root signature via `HybridSigningService.verifyHybridLeg`.
4. Signature is valid iff both legs pass. Either leg's failure is logged with the failure reason.

The SLH-DSA batch-root verification is cached in-process:

- Key: `batchId` (the random hex identifier assigned at batch creation).
- Value: absolute expiry time in milliseconds.
- Bound: 10,000 entries.
- TTL: 1 hour.
- Eviction: insertion-order (oldest entry removed when size hits bound); gets touch the entry to the tail for LRU semantics.
- Only successful verifications are cached. Failures are never cached so a signer-side key compromise cannot be accidentally blessed by a poisoned cache.

Implementation: `BatchRootVerifyCache` in `packages/api/src/services/hybrid-signing.ts`.

### 6.4 Hybrid Signing (shipping)

The shipping construction is hybrid ECDSA-P256 + SLH-DSA-SHA2-128s. Both signatures are produced at issuance; both must verify at verification time. `alg_version = 'hybrid-ecdsa-slhdsa-v1'` identifies the construction in the QRVA envelope.

```ts
interface HybridSignature {
  algVersion: 'hybrid-ecdsa-slhdsa-v1';
  ecdsa: string;    // base64 DER over canonicalizeCore(...)
  merkleBatchId: string;
  merkleLeafHash: string;
  merklePath: MerkleNode[];
  rootSignature: string;   // base64 SLH-DSA over qrauth:merkle-root:v1: || root
}
```

Verification requires both:

```ts
const ecdsaValid = verifyEcdsa(publicKey, sig.ecdsa, coreCanonical);
const merkleValid = verifyMerkleProof(sig.merkleLeafHash, sig.merklePath, merkleRoot);
const slhdsaValid = await slhDsaVerify(
  slhdsaPublicKey,
  Buffer.concat([Buffer.from('qrauth:merkle-root:v1:', 'utf8'), Buffer.from(merkleRoot, 'hex')]),
  Buffer.from(sig.rootSignature, 'base64'),
);
if (!ecdsaValid || !merkleValid || !slhdsaValid) return false;
```

ECDSA deprecation is not planned for the current release horizon. When PQC-only operation becomes appropriate, the `alg_version` agility mechanism in §11 handles the transition without breaking in-flight tokens.

During batch-signer wait windows, a QR may transiently carry `alg_version = 'ecdsa-pending-slhdsa-v1'` while the Merkle leg completes asynchronously. A reconciler is required to promote pending rows to `hybrid-ecdsa-slhdsa-v1` once the batch flushes; pending rows verify under ECDSA alone until promotion. Pending-state rows are cryptographically weaker than hybrid rows and must not persist indefinitely. See Audit-2 N-1.

## 7. Layer 2 — MAC Pre-Filter

### 7.1 Role

The MAC is a fast-reject pre-filter. A `macTokenMac` column on a QR row, when populated, is recomputed and compared constant-time before the asymmetric legs run. A MAC mismatch fails the verification immediately. A MAC match allows verification to continue to ECDSA and SLH-DSA.

The MAC is not a replacement for asymmetric verification. An attacker with a MAC secret (obtained via A-DB-READ) cannot forge a verifiable QR by itself — they would also need to produce valid ECDSA and SLH-DSA signatures, which the MAC secret does not grant. This is the property that was broken in Audit-1 Finding-001 and restored in remediation.

Why keep the MAC at all if it does not gate asymmetric verification:

- **Cheap tampering detection.** HMAC-SHA3-256 is ~2 µs per verify. ECDSA is ~50 µs. SLH-DSA cold-cache is ~3 ms. Rejecting tampered inputs at the MAC layer saves asymmetric cycles on obviously bad requests (scanner misreading, network corruption, deliberate malformed input).
- **Binding check against DB row tampering.** An adversary with A-DB-READ but not the MAC secret cannot alter a row's signed fields without invalidating the MAC; they must either produce a valid MAC (requires the secret) or leave the MAC stale (which fails fast-reject).
- **Cross-leg consistency.** The MAC, ECDSA, and Merkle legs all bind to the same `canonicalizeCore` string. A drift bug in any single leg surfaces immediately as a MAC or signature mismatch.

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
4. After a 30-day grace window, `ROTATED` keys are manually transitioned to `RETIRED` (worker automation is planned).

An acknowledged gap: MAC secrets currently live in the database and load into API process memory rather than being fetched per-request from KMS. This is tracked as a post-launch hardening item (Audit-2 carries the TODO at `services/mac.ts:63`). The DB-compromise threat (T-6) is bounded by the MAC-as-pre-filter design: an attacker with the secret cannot forge valid ECDSA or SLH-DSA signatures.

## 8. Layer 3 — Transparency Log: Commitment-Only

### 8.1 Current format

Every QR issuance appends a `TransparencyLogEntry` row that commits to the canonical leaf without revealing it:

```ts
interface TransparencyLogEntry {
  logIndex: number;          // monotonic
  qrCodeId: string;
  organizationId: string;
  commitment: string;        // hex, SHA3-256 of the Merkle leaf
  batchRootRef: string;      // hex, SHA3-256 of the batch root
  merkleInclusionProof: MerkleNode[];
  previousHash: string | null;
  entryHash: string;         // hash-chain pointer
  algVersion: string;
  createdAt: Date;
}
```

An auditor holding the tenant's SLH-DSA public key and a `SignedBatch` record can verify (a) the signed root, (b) the leaf's inclusion in that root, (c) the entry's chain position. An adversary scraping the log without the leaf gains only issuance volume, not issuance content.

### 8.2 Current guarantee and limits

The current log provides tamper-evidence against adversaries who do not have DB write access (A-DB-READ). Entries are chained by `previousHash`. Any adversary who modifies an entry must also modify every subsequent entry's `previousHash` to keep the chain consistent — detectable by any auditor cross-referencing with a known-good snapshot.

The current log does not provide tamper-evidence against adversaries with DB write access (A-DB-WRITE). Such an adversary can reconstruct a consistent chain from scratch. The current log is forensic-layer, not proof-layer. This is stated honestly in `THREAT_MODEL.md` T-17 and SECURITY.md §8.

### 8.3 Planned redesign

The full RFC 6962-compatible transparency log with signed tree heads, external witnesses, and append-only Merkle-tree audit proofs is specified in `docs/adr/0001-transparency-log.md`. It is scheduled post-launch. The redesign will:

- Persist the entry's `createdAt` as a dedicated column so `entryHash` is recomputable from stored fields.
- Publish a signed tree head at a well-known URL on a fixed cadence.
- Solicit external witnesses to co-sign tree heads, making single-operator log rewriting detectable.
- Transition from linear hash chain to RFC 6962 Merkle log structure.

Until the redesign ships, the current log's guarantees are as stated above, no more.

## 9. Layer 4 — WebAuthn Passkeys: Hybrid Bridge

### 9.1 Current state

WebAuthn credentials use ECDSA-P256 (COSE alg `-7`) by default. The credential is generated and stored inside authenticator hardware (Secure Enclave on Apple devices, Titan on Google, TPM on Windows). The algorithm choice is enforced at the hardware level; QRAuth cannot change it from the server side.

The classical vulnerability: from the public key (transmitted during assertion), Shor's algorithm on a future CRQC derives the private key. An adversary recording WebAuthn assertion responses today can forge them later. This matches T-20 in `THREAT_MODEL.md`.

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

The client sends `bridgeSignature` in the assertion request. Server verifies via `mlDsaVerify(passkey.bridgePublicKey, message, bridgeSignature)`. Domain separator `qrauth:webauthn:bridge:v1` ensures the ML-DSA key cannot be repurposed for any other signed payload in the codebase.

### 9.4 Per-organization policy

`DevicePolicy.bridgePolicy` is one of:

- `required` — both WebAuthn and ML-DSA signatures must verify on every authentication. A missing or invalid bridge signature fails the authentication. Appropriate for government, regulated, or high-value-records tenants.
- `optional` — bridge signatures are verified when present; missing bridge signatures are accepted with a soft log for operator tracking. Appropriate for standard enterprise.
- `disabled` — bridge is skipped entirely; no new bridge keys are minted. Appropriate for integrations where CRQC-era forgery is not a concern.

The policy is resolved per user as the strictest across all the user's org memberships.

### 9.5 FIDO PQC WebAuthn timeline

The FIDO Alliance PQC WebAuthn working group is expected to publish a specification in 2026–2027. Browser support is expected 2027–2028. QRAuth will implement PQC credential types as they become available at the authenticator layer; the bridge is a transition mechanism, not a permanent architecture.

## 10. Layer 5 — Key Lifecycle

### 10.1 Keys in scope

Three classes of private key material exist in QRAuth:

- **Per-tenant ECDSA-P256 signing keys.** PEM on disk (encrypted envelope), paired with a `SigningKey` row in the DB. Lives on the signer host in production; on the API host in dev.
- **Per-tenant SLH-DSA-SHA2-128s signing keys.** Raw-bytes-in-encrypted-envelope on disk, paired with the same `SigningKey` row. Same host as the ECDSA PEM.
- **Per-tenant HMAC-SHA3-256 MAC secrets.** Stored in the DB as base64 on `OrgMacKey` rows. Not on disk. Loaded into API process memory; KMS-backed per-request loading is a post-launch hardening item.

One master key at the infrastructure layer: `SIGNER_MASTER_KEY`. Base64-encoded 32 random bytes. Loaded at signer-host startup from environment. Decrypts every at-rest key envelope. Not automatically rotated.

### 10.2 At-rest encryption envelope

`packages/api/src/lib/key-at-rest.ts` and `packages/signer-service/src/key-at-rest.ts` (byte-identical):

```
envelope = "qrauth-kek-v1" || "\0" || base64(iv) || "\0" || base64(ct) || "\0" || base64(tag)
```

- AES-256-GCM, 12-byte IV, 16-byte authentication tag, random IV per encryption.
- Format tag `qrauth-kek-v1` is the domain separator; envelopes without it are rejected post-cutover.
- Atomic write: temp file + `fs.rename` within the same directory so a crash during key generation never leaves partial material on disk.

One transitional branch exists in the decryptor: envelopes that do not start with the format tag are currently returned as plaintext. This branch exists only to let legacy plaintext `.slhdsa.key` and `.pem` files load during the pre-cutover window. It is removed as part of the end-of-program cutover (Audit-2 N-3). Until it is removed, an adversary with filesystem write access can replace an encrypted envelope with a plaintext key of their choice. The threat (T-7) is addressed by removing the branch.

### 10.3 Rotation cadence

Driven by the `qrauth-cleanup` worker:

- **Tenant signing keys.** `ACTIVE` for 90 days. `ROTATED` for the next 30 days (verify-only grace window). `RETIRED` for 7 more days (not used for verification but bytes remain for forensic audit). Purge on day 127.
- **MAC secrets.** Same 90/30/7 cadence, same lifecycle states.
- **SIGNER_MASTER_KEY.** No automatic rotation. Annual manual rotation is recommended. Rotation procedure re-encrypts every envelope under the new master key and is documented in `SECURITY.md §10`.

SLH-DSA is stateless (no XMSS-style leaf index to track). The rotation discipline is for audit traceability and to bound the blast radius of a key compromise, not for correctness.

## 11. Algorithm Agility in the QRVA Protocol

### 11.1 Mandate

Every signed payload, every transparency-log entry, every API response that carries cryptographic material includes an explicit `alg_version` field. Verifiers pin to this field and dispatch accordingly. Unknown versions fail closed.

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
  'hybrid-ecdsa-slhdsa-v1',     // shipping
  'slhdsa-sha2-128s-v1',        // PQC-only; reserved for future
  'slhdsa-sha2-256s-v1',        // high-security PQC variant; reserved
  'ecdsa-pending-slhdsa-v1',    // transient: ECDSA signed, Merkle in flight
};

DEPRECATED_ALG_VERSIONS = {};   // none post-cutover

REJECTED_ALG_VERSIONS = {
  'ecdsa-p256-sha256-v1',       // legacy; no QRs use this post-cutover
};
```

`checkAlgVersion` classifies an input string:

- `accepted` → verification proceeds silently.
- `deprecated` → verification proceeds with a warning log and a `warnings` field on the response (`ALG_DEPRECATED`).
- `rejected` → verification fails closed.
- `unknown` → verification fails closed.

Pre-cutover, `ecdsa-p256-sha256-v1` was classified as `deprecated`. Post-cutover it moves to `rejected` as part of the cutover checklist (Audit-2 N-6). Any future move from `accepted` to `deprecated` requires updating this section of the document and the policy file in the same commit.

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

Any change to the above requires: (a) a new `qrva-v3` (or higher) protocol version, (b) a new ACCEPTED entry in §11.3, (c) coordinated SDK updates across Node, Python, and mobile, (d) cross-language protocol tests under `packages/protocol-tests/` regenerated and green in CI, (e) an update to this section documenting what changed.

## 13. Implementation Concerns and Pitfalls

### 13.1 Signer service isolation

Private key bytes live only on the signer host (`packages/signer-service/`). The API server holds public keys and the signer's bearer token. Two sign endpoints:

**`POST /v1/sign` — SLH-DSA.** Accepts `{ keyId, message }` with `message` base64-encoded. Prepends the domain-separation prefix `qrauth:merkle-root:v1:` before calling `slh_dsa_sha2_128s.sign`. Returns `{ signature }` base64. A bearer-token compromise yields a signing oracle bound to "Merkle root of a QR batch" and nothing else.

**`POST /v1/sign-ecdsa` — ECDSA-P256.** Accepts `{ keyId, message }` with `message` as UTF-8 canonical form. Must prepend the domain-separation prefix `qrauth:ecdsa-canonical:v1:` before calling `createSign('SHA256').update(...).sign(pem)`. The API-side verifier reconstructs the same prefix.

**Bearer token.** Minimum 32 characters; refuses to start below that. Constant-time comparison via `crypto.timingSafeEqual`. No rate limit currently; per-keyId rate limit is post-launch hardening.

**Audit log.** Every sign operation logs `{keyId, messageFingerprint, messageBytes, signatureBytes, alg}` at `info`. `messageFingerprint` is the full SHA3-256 hex digest of the signed bytes (pre-prefix). Retention is the operator's responsibility; 12 months minimum recommended in `SECURITY.md §6`.

**`POST /v1/keys/:keyId` — Key provisioning.** Accepts `{ ecdsa?, slhdsa? }` with encrypted envelope strings. Validates the `qrauth-kek-v1` format tag before writing. Rejects overwrites (409 Conflict). Atomic writes (temp + rename). Clears the sign caches for the provisioned keyId. Used by `SigningService.pushKeysToSigner()` during `createKeyPair()` and `rotateKey()` — no manual key distribution required.

**ECDSA signer backend.** The API server supports `ECDSA_SIGNER=local` (in-process, dev only) and `ECDSA_SIGNER=http` (remote signer, production). The `ecdsa-signer` Fastify plugin selects the backend at boot and decorates a shared `SigningService` instance. All route plugins use `fastify.signingService`. The worker constructs its own instance with inline backend selection. This mirrors the existing `SLH_DSA_SIGNER` pattern. With both signers set to `http`, the API host holds zero private key material.

**Dual-token rotation (Audit-3 H-5).** The signer accepts `SIGNER_TOKEN_NEXT` alongside `SIGNER_TOKEN` for zero-downtime token rotation. Both are checked constant-time. Rotation procedure: set `SIGNER_TOKEN_NEXT` on signer → restart signer → update API tokens → restart API → promote and remove `SIGNER_TOKEN_NEXT`.

**Key load.** Encrypted envelopes are read lazily on first use and cached per-keyId in process memory. Cache is cleared on process restart or key provisioning. Path traversal is defended via a `^[a-zA-Z0-9._-]+$` keyId regex check before filesystem access.

### 13.2 Signature size

SLH-DSA-SHA2-128s signatures are 7,856 bytes. Too large for inline encoding in the QR image; the QR encodes only the token, signatures are fetched server-side during verification. Public keys are 32 bytes, secret keys 64 bytes, seed 48 bytes.

Alternative parameter sets (`sha2-128f` and `sha2-256s`) are declared in `ALG_VERSION_POLICY` but not used by current code. Their trade-offs are documented in §13.6.

### 13.3 Merkle tree second-preimage defenses

Three independent defenses compose:

1. **Leaf / node domain separation.** Leaf hashes use `0x00` prefix; internal node hashes use `0x01` prefix. An adversary cannot construct an internal node that hashes to a leaf value.
2. **Per-leaf nonce.** Every leaf commits to a random 32-byte nonce. Two distinct QRs with otherwise-identical canonical payloads produce distinct leaves.
3. **Unique padding leaves.** Padding to power-of-2 uses index-dependent hashes (`SHA3-256(0x00 || "qrauth-pad:" || paddedIndex)`) so two batches of different real-leaf count cannot collide on root after padding.

### 13.4 Timing attacks

Every MAC, hash, signature, or challenge comparison uses `constantTimeEqualString` from `packages/api/src/lib/constant-time.ts`, which wraps `crypto.timingSafeEqual` after a length check. The ESLint rule under `packages/api/.eslintrc.cjs` flags `===`/`!==` on variables matching `/(Signature|Mac|Hash|Challenge|Verifier)$/i`. The rule currently warns locally; wiring it into CI is a pre-ship item (Audit-2 N-4).

### 13.5 Canonical serialization across SDKs

The canonical form in §6.2 must produce byte-identical output across Node, Python, and any future language SDK. The authoritative implementation is `packages/shared/src/canonical.ts`. Cross-language parity is enforced by protocol-test vectors in `packages/protocol-tests/`.

Subtle risks:

- **Float formatting.** `lat.toFixed(7)` in JavaScript and `format(lat, '.7f')` in Python may disagree on rounding for edge values (5-bit-rounded halves). Test vectors include edge floats; if a divergence appears, the fix is to pin a language-agnostic decimal formatting convention rather than trust language primitives.
- **Integer truncation.** `Math.trunc(radiusM)` and Python `int(radiusM)` agree for positive integers but diverge for negative values. `radiusM` is always positive by schema; vectors cover zero and large positives.
- **Unicode.** Field inputs are validated against `|`, `\n`, `\0` but not against non-ASCII. Tokens are base64url (ASCII-only by construction). `tenantId` is a CUID (ASCII). `destHash` and `geoHash` are hex (ASCII). `expiresAt` is ISO 8601 (ASCII). `algVersion` is a fixed-string set. Non-ASCII input would be a schema violation, not a canonical-form concern.

### 13.6 Batch size limits

SLH-DSA-SHA2-128s signing is ~3–5 ms on commodity hardware. Batch flush cadence (default 200 ms wait, 64-item batch) amortizes that cost across the batch. Per-QR issuance latency is dominated by the batcher's wait window, not the signing operation.

Batch size is bounded by the available SLH-DSA signing throughput, not by the Merkle tree (SHA3-256 is ~1 µs per node). A single signer process can flush ~200 batches per second at the `sha2-128s` parameter set, which covers any realistic issuance rate.

### 13.7 Do not roll your own crypto

Every primitive in this document is either Node's standard library `crypto` module or `@noble/post-quantum`. No hand-rolled hash, MAC, KDF, signing, or verifying code is permitted anywhere in QRAuth. The only custom cryptographic code is orchestration: Merkle tree traversal, canonical payload construction, envelope parsing. These are heavily tested and audited.

## 14. Testing Requirements

### 14.1 Test vectors

Deterministic test vectors for every cryptographic operation live in `packages/protocol-tests/fixtures/`. Vectors cover:

- SLH-DSA signing and verification with fixed seed + fixed message.
- Merkle tree construction and inclusion proof verification for 1, 2, 3, 4, 7, 8, 16-leaf trees.
- Canonical form for URL QRs, content QRs, far-future expiry, empty-string expiry, bound geo, unbound geo, edge-decimal lat/lng.
- At-rest envelope round-trip with a fixed master key.
- ProximityAttestation JWT construction and verification.
- Auth-session approval signature round-trip.
- WebAuthn bridge signature round-trip.

### 14.2 Cross-language consistency

Every SDK (Node, Python, future mobile) imports the same test vectors and asserts byte-identical output. Divergence fails the CI build. The test runner lives in `packages/protocol-tests/`.

A known regression, tracked as Audit-2 N-7: 3 failing cases and 6 failed-to-load test files in the current suite. Re-baselining is a pre-ship item. Until it passes, the cross-language consistency gate is not enforcing.

### 14.3 Fuzzing

Property-based fuzzing against Merkle proof verification, canonical-form round-trips, and at-rest envelope parsing is planned, not shipped. `fast-check` is the intended framework.

### 14.4 Performance benchmarks

Measured on commodity developer hardware, `packages/api/test/bench/verify.bench.ts`:

- Leaf hash computation: under 1 ms per leaf.
- Merkle path walk (depth 10): ~10 µs.
- Merkle proof verification: under 1 ms for any realistic tree depth.
- SLH-DSA sign: 3–5 ms.
- SLH-DSA verify (cold cache): ~3 ms.
- SLH-DSA verify (warm cache via `BatchRootVerifyCache`): O(1) Map lookup, sub-microsecond.
- Full hybrid verify (ECDSA + Merkle + cached SLH-DSA): P50 0.15 ms, P95 0.18 ms.

## 15. Dependency Reference

| Purpose | Library | Version | Notes |
|---|---|---|---|
| SLH-DSA, ML-DSA | `@noble/post-quantum` | pinned in `package-lock.json` | Audited, pure TypeScript, no WASM. |
| SHA3-256, HMAC, AES-GCM, ECDSA | Node standard library `crypto` | Node 22+ | SHA3 native via OpenSSL 3.x. |
| Constant-time comparison | Node `crypto.timingSafeEqual` | Node 22+ | Used via `constantTimeEqualString`. |
| Random bytes | Node `crypto.randomBytes` | Node 22+ | `getrandom(2)` on Linux. |
| Merkle trees | Custom | — | `packages/api/src/services/merkle-signing.ts`. Not from a third-party library. |
| WebAuthn server | `@simplewebauthn/server` | pinned | FIDO2 compliant. |
| JWT signing (session tokens) | `jsonwebtoken` | pinned | HS256 only. |
| Fastify plugins | `fastify` and ecosystem | pinned | See `package-lock.json`. |
| ORM | `prisma` | pinned | Parameterized queries. |

Supply-chain trust for these dependencies is assumed per `THREAT_MODEL.md §3` ("Supply-chain compromise of cryptographic libraries" is out of scope). We pin versions, track CVEs, publish SBOMs; we cannot defend cryptographically against a library maintainer shipping a backdoor.

## 16. Integrator Mechanism Reference

This section is a mechanism index for integrators writing code against QRAuth. Each mechanism is specified in more detail elsewhere in this file; this section is a one-stop pointer.

**M-13 signing-key-registration webhook.** Fires on every `SigningKey` row creation. HMAC-SHA3-256 signed with the organization's webhook secret.

```
POST <integrator-registered-endpoint>
Headers:
  X-QRAuth-Event: signing-key.created
  X-QRAuth-Signature: sha3-256=<hex>
Body:
  {
    "eventId": "<uuid>",
    "eventType": "signing-key.created",
    "occurredAt": "<ISO 8601>",
    "organizationId": "<cuid>",
    "signingKey": {
      "kid": "<uuid>",
      "algorithm": "ES256",
      "slhdsaAlgorithm": "slh-dsa-sha2-128s",
      "status": "ACTIVE",
      "createdAt": "<ISO 8601>"
    },
    "operatorIdentity": "<string | null>"
  }
```

Integrator validates the signature via `HMAC-SHA3-256(webhookSecret, rawBody)` constant-time compared to `X-QRAuth-Signature`. Unauthorized events that do not correspond to a legitimate key-rotation event are the signal for T-9 incident response.

**PKCE auth-session envelope.** Public-client flow requires `code_challenge` at session creation and `code_verifier` at retrieval. Challenge method is always `S256`. See `routes/auth-sessions.ts` and SECURITY.md §5.

**Animated-QR frame envelope.** URL form: `<baseUrl>?f=<frameIndex>&t=<timestampMs>&h=<hmacHex16>`. HMAC is the first 16 hex characters of `HMAC-SHA-256(frameSecret, baseUrl + ":" + timestamp + ":" + frameIndex)`. `frameSecret` is derived server-side per session.

**Proximity attestation JWT.** ES256, compact. Header: `{alg, typ, kid}`. Claims: `{iss, sub, aud, device, loc, proximity: {matched, distanceM, radiusM}, alg_version, iat, exp}`. `exp` is `iat + 300`. Verifier resolves public key by `(iss, kid)` against signing keys in state `ACTIVE` or `ROTATED`.

*Signed-bytes envelope (non-standard, important for integrators):* the ECDSA signature covers `qrauth:ecdsa-canonical:v1:` || `header.payload`, not the bare `header.payload` string that stock JWT libraries feed to ECDSA verification. This is the domain-separation defense that bounds a compromised signer to the ECDSA-canonical domain (Audit-2 N-2). Stock JWT libraries (`jsonwebtoken`, `PyJWT`, `jose`, `jwt-go`) will reject QRAuth proximity attestations on signature verification because they omit the prefix. Third-party integrators must use `verifyProximityAttestation` from `@qrauth/node` or the Python SDK equivalent from `qrauth`, both of which reconstruct the prefix before calling ECDSA verification. The JWT is still offline-verifiable — it does not require an API call to QRAuth — but it does require a QRAuth-aware verifier. See `services/proximity.ts`.

**Ephemeral session claim.** `POST /api/v1/ephemeral/:token/claim` with optional `deviceFingerprint`. Returns the claim payload only if the CAS-guarded update succeeds. Retry up to 5 times on contention.

**Auth-session approval signature envelope.** `<kid>:<base64sig>`. Canonical bytes signed: `qrauth:auth-session:v1 | qrauth-auth-session-v1 | kid | sessionId | userId | appId | resolvedAtIso`. Verifier resolves public key by `(organizationId, kid)`.

**Revocation.** `DELETE /api/v1/qrcodes/:token` sets status to `REVOKED`. Subsequent verification returns `QR_REVOKED` immediately. Integrator caches must invalidate on revocation signal.

## 17. Version History

**v2.0** — Post Audit-2 remediation. Complete rewrite under the spec-driven-workflow model. Now the single source of truth for cryptographic architecture; threat analysis moved to `THREAT_MODEL.md`; operator/integrator summaries moved to `SECURITY.md`. Major changes from v1.x:

- §2 collapsed to a pointer to `THREAT_MODEL.md`.
- §3 replaced: the "current state audit" (pre-remediation vulnerable-primitives listing) is now historical; §3 lists as-shipped primitives.
- §4 reframed: the core principle is now "hybrid verification with batched asymmetric cost," not "hash-native with symmetric-only hot path." The MAC is a pre-filter, not a replacement.
- §5 collapsed to direct `crypto.randomBytes` wrapper per Audit-1 Finding-017+023 decision (b).
- §6 updated: canonical form unified across MAC / ECDSA / Merkle per Audit-1 Findings 011/019/020/021. `computeDestHash` with content-type domain tag. File paths updated. `BatchRootVerifyCache` documented. Domain-separation prefix on signer endpoints documented.
- §7 renamed and rewritten: "MAC Pre-Filter." MAC does not short-circuit asymmetric verification per Audit-1 Finding-001.
- §8 honest about current vs. future log: commitment-only entries are accurate for the current implementation; the RFC 6962 log with signed tree heads is deferred to `docs/adr/0001-transparency-log.md`.
- §9 rewritten: ML-DSA bridge keygen moved to the browser per Audit-1 Finding-003. Per-org `bridgePolicy` documented.
- §10 simplified: SLH-DSA is stateless; XMSS-style leaf-index discipline removed. Rotation cadence matches `qrauth-cleanup` worker (90/30/7). At-rest envelope format documented.
- §11 updated: `alg_version` is inside the canonical form, not in a wrapper envelope. `ecdsa-p256-sha256-v1` moves to REJECTED post-cutover per Audit-2 N-6.
- §12 deleted: "Migration Strategy" was a pre-production rollout plan that is now superseded. Replaced with "Rollout Invariants" — what cannot change without a protocol version bump.
- §13 updated: signer service documents both `/v1/sign` and `/v1/sign-ecdsa` with their respective domain-separation prefixes. `constantTimeEqualString` helper referenced.
- §14 updated: benchmark numbers replaced with Audit-2 measurements. Protocol-test regression (N-7) noted as a pre-ship item.
- §15 updated: removed aspirational KMS integration snippet; reflects the collapsed entropy decision.
- §16 new: integrator mechanism reference for M-13 webhook and related envelopes.

**v1.x** — Previous iterations. Superseded.
