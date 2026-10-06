---
title: Signing Architecture
description: How QRAuth signs and verifies every QR code with hybrid post-quantum cryptography.
---

# Signing Architecture

Every QR code issued by QRAuth is stored with two cryptographic signatures: ECDSA-P256 (classical, FIPS 186-5) and SLH-DSA-SHA2-128s (post-quantum, FIPS 205). Both are computed by an isolated signer service and verified independently at scan time for any code that routes through `GET /v/:token`. This is not a roadmap feature — it is the production signing path running today.

The one deliberate exception is covered in [Scope: which codes are verified at scan time](#scope-which-codes-are-verified-at-scan-time) below.

## Why Dual Signing

The threat model is harvest-now-decrypt-later. An adversary records signed QR codes today and waits for a cryptographically relevant quantum computer to break ECDSA. NIST finalized the first post-quantum signature standards in August 2024. QRAuth does not wait for the break — we ship the defense now.

A break of ECDSA leaves the SLH-DSA signature intact. A break of SLH-DSA (unlikely — it relies only on hash function security, not lattice assumptions) leaves ECDSA intact. Both legs must verify for `signatureValid: true`. The scheme degrades gracefully under either individual compromise.

## The Signing Flow

When a developer calls `POST /api/v1/qrcodes`:

1. The API builds a canonical payload: token, tenant ID, destination URL hash, geo-hash, expiry, content hash, nonce, and algorithm version. Field ordering is deterministic — the canonical form is a pipe-delimited string with injectiond fields validated before assembly.

2. The canonical payload is ECDSA-P256 signed via the remote signer service. The signer prepends a domain-separation tag (`qrauth:ecdsa-canonical:v1:`) before signing, preventing cross-protocol signature reuse. The signature is compact (64 bytes DER-encoded).

3. The QR code enters a Merkle batch. When the batch closes (64 items or 200ms, whichever comes first), the batch root is SLH-DSA signed via the same signer service. Each QR code receives its individual Merkle proof — the path from its leaf to the signed root.

4. Both signatures, the Merkle proof, and the public keys are stored in the database. The verification endpoint checks all legs.

## Isolated Signer Architecture

The API server handles HTTP requests, business logic, and database operations. It holds zero private key material in production.

The signer service runs on a separate host on a private network with no inbound internet access. It holds encrypted private keys and exposes a narrow HTTP surface: sign, sign-ecdsa, and key provisioning. Communication is bearer-token authenticated over the private network.

Keys are encrypted at rest with AES-256-GCM under a shared master key (`SIGNER_MASTER_KEY`). The encryption envelope uses a versioned format (`qrauth-kek-v1`) so future KMS or HSM-backed upgrades are a clean cutover without touching the signing API.

A compromise of the API server yields no private key bytes. An attacker would need to breach both hosts to forge signatures.

```
┌─────────────────────┐         private network         ┌──────────────────────┐
│    API Server        │ ──── POST /v1/sign ──────────▶ │   Signer Service     │
│                      │ ──── POST /v1/sign-ecdsa ───▶  │                      │
│  - Routes            │ ──── POST /v1/keys/:id ─────▶  │  - ECDSA-P256 keys   │
│  - Business logic    │                                 │  - SLH-DSA keys      │
│  - Database          │ ◀─── { signature: "..." } ──── │  - AES-256-GCM       │
│  - No private keys   │                                 │  - No public access  │
└─────────────────────┘                                  └──────────────────────┘
```

## Auto Key Provisioning

Key generation happens on the API server. When `createKeyPair()` runs (during organization onboarding or key rotation), it generates both an ECDSA-P256 and an SLH-DSA keypair, encrypts them at rest immediately, writes the envelopes to the API host's local disk, and pushes them to the signer service via `POST /v1/keys/:keyId`.

The signer validates that each envelope carries the correct encryption format tag before writing. Existing keys cannot be overwritten — the endpoint returns 409 Conflict if a key file already exists. This means new organizations get signing capability automatically with no manual key distribution step.

## Verification Flow

When someone scans a QR code and hits `GET /v/:token`:

1. **MAC pre-filter** — a fast-path check that detects cloning attempts in microseconds. A failed MAC rejects immediately without touching the asymmetric verification legs.
2. **ECDSA-P256 signature verification** against the reconstructed canonical payload using the stored public key.
3. **Merkle proof validation** — the QR code's leaf hashes up to the stored batch root.
4. **SLH-DSA signature verification** of the batch root against the stored post-quantum public key.
5. All four checks must pass. `signatureValid: true` means the full chain verified.

## Algorithms

| Layer | Algorithm | Standard | Purpose |
|-------|-----------|----------|---------|
| QR signing (classical) | ECDSA-P256 | FIPS 186-5 | Per-code signature, compact (64 bytes) |
| QR signing (post-quantum) | SLH-DSA-SHA2-128s | FIPS 205 | Batch root signature, hash-based (no lattice assumptions) |
| At-rest key encryption | AES-256-GCM | FIPS 197 | Master-key envelope for private key storage |
| Frame signing (Living Codes) | HMAC-SHA256 | FIPS 198-1 | Per-frame authentication for animated QR codes |
| Proximity attestation | ES256 JWT | RFC 7518 | Location proof tokens |
| Canonical domain separation | Prefixed signing | — | `qrauth:ecdsa-canonical:v1:` prevents cross-protocol reuse |

## Scope: which codes are verified at scan time

The signing pipeline runs on every `POST /api/v1/qrcodes` call, regardless of content type. Every row in the database has a valid ECDSA-P256 signature, a Merkle proof, and an SLH-DSA batch-root signature. `GET /v/:token` verifies all legs for any token, and the REST, SDK, and dashboard surfaces rely on that.

Scan-time verification, however, only fires for QR codes that actually encode a `/v/:token` URL in the printed matrix. `url`, `coupon`, `pdf`, and `feedback` content types do. `vcard` and `event` do **not** — those two types encode the raw vCard 3.0 / iCal VEVENT string directly so mobile devices trigger the native Add Contact / Add to Calendar prompt offline, and printed business cards and event posters keep working if the issuer's infrastructure is unreachable.

The practical consequences for `vcard` and `event`:

- No signature check runs on the scanning device — the phone's OS imports the content and never contacts QRAuth.
- No transparency-log hit is recorded, because no HTTP request is made.
- Fraud signals (proxy, velocity, geo-impossibility, clustering) never evaluate — they are scan-triggered.
- Trust Reveal, domain-phishing warnings, and the verification page render are not shown at scan time.
- The dashboard still shows the row, REST verification still works, and the audit record still exists — they just aren't exercised by a scan.

Pick `url` with a custom landing page if you need per-scan trust signals for contact or event content. Pick `vcard` or `event` if offline printability and native phone handling matter more than scan-time verification.

## What This Means for Developers

You do not configure any of this. Call `POST /api/v1/qrcodes` with your content, get a dual-signed QR code back. Verification is one endpoint: `GET /v/:token`. Both signature legs are checked automatically when that endpoint is hit — which for `url`, `coupon`, `pdf`, and `feedback` codes happens on every scan (the printed QR encodes the `/v/:token` URL). For `vcard` and `event` codes the QR encodes raw vCard/iCal content for offline native handling; the `/v/:token` endpoint still exists and still verifies, but scanners do not call it. See [Scope](#scope-which-codes-are-verified-at-scan-time) above.

The SDKs and Web Components handle everything — no cryptographic code required on your side. The `<qrauth-login>` component, the Node.js SDK's `client.qrcodes.create()`, and the REST API all produce the same dual-signed output.

If NIST's post-quantum standards evolve or new algorithms are standardized, QRAuth upgrades the signing layer. Your integration stays the same. The `algVersion` field in the canonical payload tracks the active algorithm version, and the verifier gates on it — so algorithm transitions are transparent to consumers.
