---
title: Signing Architecture
description: How QRAuth signs and verifies every QR code with hybrid post-quantum cryptography.
---

# Signing Architecture

Every QR code issued by QRAuth carries a hybrid signature: an ECDSA-P256 signature (classical, FIPS 186-5) over its canonical core, and a Merkle inclusion proof against a batch root signed with SLH-DSA-SHA2-128s (post-quantum, FIPS 205). In production both signatures are produced on an isolated signer service, and both legs are verified at scan time by `GET /v/:token`. This is the production signing path running today, and the only issuance path.

The cryptographic detail is specified in [ALGORITHM.md](https://github.com/qrauth-io/qrauth/blob/main/ALGORITHM.md).

## Why Dual Signing

The threat model is harvest-now-decrypt-later. An adversary records signed QR codes today and waits for a cryptographically relevant quantum computer to break ECDSA. NIST finalized the first post-quantum signature standards in August 2024. QRAuth does not wait for the break — we ship the defense now.

Both legs must verify for `signatureValid: true`: the ECDSA-P256 signature over the canonical core, and the Merkle leaf recomputed from that same core and the stored nonce, walked through its inclusion proof to an SLH-DSA-SHA2-128s-signed batch root. SLH-DSA relies only on hash-function security, not lattice or elliptic-curve assumptions.

## The Signing Flow

When a developer calls `POST /api/v1/qrcodes`:

1. The API builds the canonical core: `algVersion|token|tenantId|destHash|geoHash|expiresAt`. `destHash` is the SHA3-256 of the destination URL or, for other content types, of the content hash, under a domain-separation prefix. Field ordering is fixed and every field is checked for forbidden characters before assembly. The Merkle leaf form appends a 32-byte random nonce. See [QRVA Protocol](./protocol#canonical-payload-serialization).

2. The canonical payload is ECDSA-P256 signed via the remote signer service. The signer prepends a domain-separation tag (`qrauth:ecdsa-canonical:v1:`) before signing, preventing cross-protocol signature reuse. The signature is DER-encoded (about 70–72 bytes) and stored base64.

3. The QR code enters a Merkle batch. When the batch closes (64 items or 200ms, whichever comes first), the batch root is signed with SLH-DSA-SHA2-128s over `qrauth:merkle-root:v1:` + root bytes, via the same signer service. Each QR code receives its individual Merkle proof — the path from its leaf to the signed root.

4. The ECDSA signature, the Merkle leaf hash and inclusion proof, and the batch reference are stored on the QR code row; the signed batch root is stored in its own table, and public keys on the tenant's signing-key record. The verification endpoint checks all legs.

## Isolated Signer Architecture

The API server handles HTTP requests, business logic, and database operations. In production it does not sign: all ECDSA-P256 and SLH-DSA-SHA2-128s signing operations run on the signer host (`ECDSA_SIGNER=http`, `SLH_DSA_SIGNER=http`). The API sends canonical bytes and receives signatures.

The signer service runs on a separate host reachable over a private network. It exposes a narrow HTTP surface: SLH-DSA batch-root signing, ECDSA canonical signing, ECDSA and RSA JWS signing for the OIDC provider, Living Codes MAC sessions, public-key read, and key provisioning. Requests are authenticated with a bearer token (at least 32 characters, compared in constant time, with dual-token rotation via `SIGNER_TOKEN_NEXT`).

Tenant private keys are encrypted at rest with AES-256-GCM under a master key (`SIGNER_MASTER_KEY`, 32 random bytes supplied through the environment). The envelope uses a versioned format tag (`qrauth-kek-v1`), and envelopes without the tag are rejected.

Tenant signing keys are ACTIVE for 90 days, then ROTATED (verify-only) for 30 days, and revoked at day 120.

```
┌─────────────────────┐         private network         ┌──────────────────────┐
│    API Server        │ ──── POST /v1/sign ──────────▶ │   Signer Service     │
│                      │ ──── POST /v1/sign-ecdsa ───▶  │                      │
│  - Routes            │ ──── POST /v1/keys/:id ─────▶  │  - ECDSA-P256 keys   │
│  - Business logic    │                                 │  - SLH-DSA keys      │
│  - Database          │ ◀─── { signature: "..." } ──── │  - AES-256-GCM       │
│  - Key generation    │                                 │  - No public access  │
└─────────────────────┘                                  └──────────────────────┘
```

## Auto Key Provisioning

Key generation happens on the API host. When `createKeyPair()` runs (during organization onboarding or key rotation), it generates both an ECDSA-P256 and an SLH-DSA keypair, encrypts them at rest immediately, writes the envelopes to the API host's local disk, and pushes them to the signer service via `POST /v1/keys/:keyId`.

The signer validates that each envelope carries the correct encryption format tag before writing. Existing keys cannot be overwritten — the endpoint returns 409 Conflict if a key file already exists. This means new organizations get signing capability automatically with no manual key distribution step.

## Verification Flow

When someone scans a QR code and hits `GET /v/:token`:

1. **MAC pre-filter** — an HMAC-SHA3-256 check over the canonical core. A mismatch rejects immediately; a match never skips the asymmetric legs.
2. **ECDSA-P256 signature verification** against the reconstructed canonical payload using the stored public key.
3. **Merkle proof validation** — the leaf is recomputed from the canonical core and the stored nonce and must equal the stored leaf; the inclusion proof is walked from the recomputed leaf up to the batch root.
4. **SLH-DSA signature verification** of the batch root against the tenant's SLH-DSA-SHA2-128s public key. A successful result is cached in-process per batch for 1 hour; failures are not cached.
5. All checks must pass. `signatureValid: true` means the ECDSA leg and the Merkle/SLH-DSA leg both verified.

## Algorithms

| Layer | Algorithm | Standard | Purpose |
|-------|-----------|----------|---------|
| QR signing (classical) | ECDSA-P256 | FIPS 186-5 | Per-code signature, DER-encoded |
| QR signing (post-quantum) | SLH-DSA-SHA2-128s | FIPS 205 | Batch root signature, hash-based (no lattice assumptions) |
| At-rest key encryption | AES-256-GCM | FIPS 197 | Master-key envelope for private key storage |
| Frame signing (Living Codes) | HMAC-SHA-256 | FIPS 198-1 | Per-frame authentication for animated QR codes |
| Proximity attestation | ECDSA-P256, JWT-shaped (`alg: ES256`) | — | Signed statement of a client-reported location; verify with the QRAuth SDK |
| Canonical domain separation | Prefixed signing | — | `qrauth:ecdsa-canonical:v1:` prevents cross-protocol reuse |

## Performance

Measured with `@noble/post-quantum` on developer hardware (`packages/api/test/bench/verify.bench.ts`):

- SLH-DSA-SHA2-128s sign: about 2.0–2.4 s per signature.
- SLH-DSA-SHA2-128s verify: about 3 ms cold.
- Full hybrid verify with a warm batch cache: P50 about 0.15 ms, P95 about 0.18 ms.

One signer process signs about 0.4–0.5 batch roots per second. At 64 leaves per batch that is about 25–30 QR issuances per second per signer process. Per-QR issuance latency is dominated by the SLH-DSA sign (about 2 s), not the 200 ms batch window.

SLH-DSA-SHA2-128s signatures are 7,856 bytes and public keys 32 bytes. QR images encode only the token URL; signatures are held server-side.

## Scope: which codes are verified at scan time

The signing pipeline runs on every `POST /api/v1/qrcodes` call, regardless of content type. All content types, `vcard` and `event` included, encode the signed `/v/:token` URL in the printed QR. The verification page then delivers the content (for example the native contact or calendar import) together with the Trust Reveal.

## What This Means for Developers

You do not configure any of this. Call `POST /api/v1/qrcodes` with your content, get a hybrid-signed QR code back. Verification is one endpoint: `GET /v/:token`. Both signature legs are checked automatically when that endpoint is hit, which happens on every scan because the printed QR encodes the `/v/:token` URL.

The SDKs and Web Components handle everything — no cryptographic code required on your side. The Node.js SDK's `qrauth.create()` and the REST API produce the same hybrid-signed output.

If NIST's post-quantum standards evolve or new algorithms are standardized, QRAuth upgrades the signing layer. Your integration stays the same. The `algVersion` field in the canonical payload tracks the active algorithm version, and the verifier gates on it — so algorithm transitions do not change your integration.
