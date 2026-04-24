# Security

This page is written for enterprise security teams evaluating QRAuth during procurement. It describes the threat model the platform is designed against, the cryptographic primitives in use, and the known limitations we document plainly rather than paper over. The full technical specification lives in `ALGORITHM.md`; this page summarises what matters for a security review.

---

## Security Model Overview

QRAuth implements a five-tier progressive security model. Tiers 1–4 address classical adversaries (fraudulent QR codes, proxies, phishing); tier 5 addresses quantum adversaries who may exist in 5–10 years and are already recording traffic today. All five tiers are active simultaneously — there is no manual configuration required.

Tiers 1–4 are described in the [README](https://github.com/qrauth-io/qrauth#security-model). In brief:

- **Tier 1 — Cryptographic signing.** Every QR code carries a signature over its canonical payload, verifiable by third parties via the tenant's public key.
- **Tier 2 — Ephemeral visual proof.** Server-generated, time-bound images on the verification page that cloned pages cannot reproduce.
- **Tier 3 — Anti-proxy detection.** Composite trust signals (TLS fingerprint, latency, canvas, JS environment) that identify real-time MitM proxying.
- **Tier 4 — WebAuthn passkeys.** Origin-bound hardware-backed credentials that no phishing domain can trigger.
- **Tier 5 — Post-quantum cryptographic layer.** The subject of the rest of this page.

The post-quantum layer is not a replacement for Tiers 1–4. It is a parallel architectural property that holds even if every other tier's asymmetric cryptography is broken by a future quantum computer.

---

## Quantum Threat Model

QRAuth's signing infrastructure is designed against the "harvest now, attack later" (HNDL) threat: an adversary who records public signatures and verification traffic today, then uses a future Cryptographically Relevant Quantum Computer (CRQC) to derive private keys and forge signatures. This is not a theoretical concern for a platform with QRAuth's characteristics — QR codes are long-lived (expiry measured in months or years), the transparency log is public and permanent, and the target market includes government and physical infrastructure.

Three architectural properties defeat the HNDL attack surface:

**No key material in public records.** The transparency log publishes only opaque SHA3-256 hash commitments and SLH-DSA signatures over Merkle roots. SLH-DSA is hash-based (FIPS 205) and its private keys are not recoverable from signatures under any known quantum algorithm. Public keys are never in the log — the log carries `SHA3-256(public_key)` instead, so auditors verify via an authenticated endpoint and compare hashes. There is nothing in any public QRAuth record that a quantum computer can use to derive a signing key.

**Asymmetric operations are offline and infrequent.** SLH-DSA root signing runs on a dedicated signer service with no inbound internet routes, configured via `SLH_DSA_SIGNER=http` and a bearer-authenticated HTTP endpoint. The private key never leaves the signer host's filesystem. The API server holds only public keys and never sees private bytes. Compromise of the API box yields zero key material.

**The real-time verification path is entirely symmetric.** Edge verification uses HMAC-SHA3-256 (FIPS 198) for the fast path and SHA3-256 Merkle inclusion proofs for the audit path. Neither involves elliptic curve operations. The security of this path reduces to SHA3-256 preimage resistance alone — a property Grover's algorithm degrades from 256-bit to 128-bit effective security, which remains computationally intractable for any conceivable hardware.

Cryptographic agility is baked into the protocol. Every signed payload carries an explicit `alg_version` field and every verifier implements a four-state classifier (accepted / deprecated / rejected / unknown). Migration between algorithms requires no protocol break and no tenant coordination beyond announcing a sunset date.

---

## Cryptographic Primitives

| Primitive | Algorithm | Standard | Quantum Status | Used For |
|---|---|---|---|---|
| QR batch signing | SLH-DSA-SHA2-128s | FIPS 205 | Resistant | Root signing (offline) |
| Hot-path verification | HMAC-SHA3-256 | FIPS 198 / FIPS 202 | Resistant | Per-token MAC fast path |
| Merkle tree hashing | SHA3-256 | FIPS 202 | Resistant | Inclusion proofs |
| Payload hashing | SHA3-256 | FIPS 202 | Resistant | Canonical payload, commitments |
| Webhook signatures | HMAC-SHA3-256 | FIPS 198 / FIPS 202 | Resistant | Event authentication |
| WebAuthn PQC bridge | ML-DSA-44 | FIPS 204 | Resistant | Bridged passkey assertions |
| At-rest encryption | AES-256-GCM | FIPS 197 | Resistant * | Database, file storage |
| Transport | TLS 1.3 | RFC 8446 | Partial ** | All connections |
| WebAuthn credentials | ECDSA-P256 (transitional) | FIPS 186-4 | Vulnerable | Passkey authentication |
| JWT session signing | HS256 | RFC 7518 | Resistant | API session tokens |

\* 128-bit effective security under Grover's algorithm, which remains intractable.
\*\* Key exchange is evolving at the infrastructure layer. Cloudflare is deploying hybrid X25519+ML-KEM in production; QRAuth inherits this transparently once available on the deployment substrate.

JWT session tokens use HS256 (HMAC-SHA256) — a symmetric algorithm, not ECDSA. This is already quantum-safe; no migration is required for the session-token layer.

WebAuthn credentials remain on ECDSA-P256 because the credential is generated inside the user's authenticator hardware (Secure Enclave, TPM, Titan chip), which QRAuth cannot unilaterally change. The FIDO Alliance is working on a post-quantum WebAuthn specification; QRAuth will support it when browsers and operating systems ship it. In the meantime, the WebAuthn PQC bridge (ML-DSA-44) gives high-security tenants a second factor that holds against quantum adversaries today. See [Known Limitations](#known-limitations) below.

---

## Known Limitations

We state limitations plainly. Each one is followed by what we do about it.

### WebAuthn passkeys

FIDO2 credentials use ECDSA-P256 by default. The credential is generated and stored in authenticator hardware (Secure Enclave on Apple devices, Titan on Google, TPM on Windows, platform-specific equivalents elsewhere). QRAuth cannot change this from the server side — the algorithm choice is enforced at the hardware level by the authenticator, not by our application code.

The FIDO Alliance post-quantum WebAuthn working group is expected to publish a specification in 2026–2027. QRAuth will implement PQC credential types as browser and OS support lands. Until then, government-tier tenants can configure the `bridgePolicy: 'required'` setting on their organization, which enables a server-side ML-DSA-44 bridge signature alongside the WebAuthn assertion. Both legs verify: even if Shor's algorithm were used to forge the ECDSA-P256 WebAuthn assertion, the lattice-based ML-DSA leg would still reject the request. The bridge private key lives in the user's browser IndexedDB scoped to the passkey's credential ID.

### TLS key exchange

TLS 1.3 handshakes currently use X25519 ECDHE for key exchange, which is vulnerable to Shor's algorithm. Cloudflare is deploying hybrid X25519+ML-KEM768 in production as of 2025; this eliminates the TLS key-exchange harvest surface without any application-level change. QRAuth inherits the upgrade through its Cloudflare-fronted deployment.

On deployments that do not front through Cloudflare, operators should configure the TLS terminator to negotiate the hybrid key-exchange scheme as soon as their provider supports it. The application layer is unaffected.

### Legacy ECDSA-signed tokens

Tokens issued before the hybrid cutover carry `alg_version = 'ecdsa-p256-sha256-v1'` and verify via the ECDSA leg only. The verifier accepts them with a deprecation warning in the response `warnings` array, and operator dashboards surface a "tokens using deprecated cryptography" metric. These tokens are a migration target, not a security failure — they are no weaker than they were at issuance, and the signer has every incentive to re-issue them under the new algorithm.

Tenants can query the PQC health endpoint (`GET /api/v1/analytics/pqc-health`) to see their deprecated-token inventory and plan a re-issuance campaign.

---

## Signing Infrastructure

QRAuth separates signing from serving. In production, private key material lives exclusively on a dedicated signer host — the API server never holds private bytes.

### Architecture

The API server and signer service communicate over a private network. The signer exposes three endpoints authenticated by a shared bearer token:

- `POST /v1/sign` — SLH-DSA-SHA2-128s signature over a Merkle batch root
- `POST /v1/sign-ecdsa` — ECDSA-P256 signature over a canonical payload
- `POST /v1/keys/:keyId` — Receive encrypted key material during key generation

### Key Lifecycle

1. **Generation:** `createKeyPair()` generates both ECDSA and SLH-DSA keys on the API host, encrypts them at rest (AES-256-GCM), and auto-provisions them to the signer service via `POST /v1/keys/:keyId`. The signer writes the encrypted envelopes to its own disk.

2. **Signing:** All signing requests route through the signer service. The API server sends the canonical payload or Merkle root; the signer decrypts the key, signs, and returns the signature. Private key bytes never cross the network — only encrypted envelopes during initial provisioning.

3. **Rotation:** The `qrauth-cleanup` worker triggers automatic rotation after 90 days. The old key enters ROTATED status (30-day grace period where existing signatures still verify), then RETIRED, then purged 7 days later.

### Configuration

| Variable | Values | Description |
|----------|--------|-------------|
| `ECDSA_SIGNER` | `local` \| `http` | Signing backend. `local` for development, `http` for production. |
| `ECDSA_SIGNER_URL` | URL | Signer service URL (e.g., `http://10.0.0.2:7788`) |
| `ECDSA_SIGNER_TOKEN` | string | Bearer token for signer authentication |
| `SLH_DSA_SIGNER` | `local` \| `http` | Same as above for SLH-DSA |
| `SLH_DSA_SIGNER_URL` | URL | Signer service URL |
| `SLH_DSA_SIGNER_TOKEN` | string | Bearer token |
| `SIGNER_MASTER_KEY` | base64 | AES-256-GCM master key for at-rest encryption (shared between API and signer) |

**Warning:** Running `*_SIGNER=local` in production means private keys live on the API server. This is acceptable for development but not recommended for production deployments.

### Key rotation

Tenant signing keys rotate every 90 days by default, driven by the `qrauth-cleanup` worker. The rotation cycle:

1. Worker detects that the active key is older than 90 days.
2. New keypair is minted via `SigningService.rotateKey()`, which writes the new private key to the signer host's keys directory and inserts the new public key into the database.
3. The old key transitions to `ROTATED` state. Tokens signed under the old key continue to verify during a 30-day grace window.
4. After the grace window, the old key transitions to `RETIRED`. Verifiers no longer offer it as a candidate but the bytes remain for forensic audit.
5. After 7 more days, the retired key is purged from the keys directory.

Rotation is logged at every transition and surfaced on the PQC health dashboard. Operators can also trigger a rotation manually via `POST /api/v1/devices/policy` (for MAC keys) or the signing-key rotation endpoint (for ECDSA/SLH-DSA pairs).

---

## Incident Response

If a tenant signing key is suspected of compromise, the response procedure is:

1. **Immediate rotation.** Call `SigningService.rotateKey(organizationId)` to mint a fresh ECDSA + SLH-DSA pair. The old key transitions to `ROTATED` immediately and new issuances use the new key within the next BatchSigner flush window (default 200 ms).
2. **Revoke the affected tokens.** Any QR tokens issued under the compromised key that are still in the field should be revoked via `DELETE /api/v1/qrcodes/:token`. Revocation is immediate at the verifier — revoked tokens return `QR_REVOKED` on the next scan.
3. **Audit the transparency log.** The PQC health endpoint surfaces all tokens by alg_version and batch_id; the transparency log batch endpoint (`GET /api/v1/transparency/batch/:batchId`) returns the full batch metadata for forensic review.
4. **Notify affected third parties.** Integrators holding the tenant's public key should be notified that the key has rotated. The new public key is available via the authenticated signing-key endpoint.

For MAC key compromise, the rotation cascade is handled automatically by the `qrauth-cleanup` worker without operator intervention — the compromised key transitions through ROTATED → RETIRED → purged in the 90/30/7-day lifecycle described above.

---

## Living Codes HMAC Tag Truncation Analysis

> Audit-3 M-3: formal security analysis for the 8-byte HMAC truncation used in
> animated QR frame signing.

### Context

Each Living Codes frame carries an HMAC-SHA256 tag truncated to the first 8 bytes
(16 hex characters). The full tag is 32 bytes (256 bits). This section documents why
the truncation is safe for this specific use case.

### Parameters

| Parameter | Value | Source |
|---|---|---|
| Full HMAC output | 256 bits (32 bytes) | HMAC-SHA256 |
| Truncated tag | 64 bits (8 bytes, 16 hex chars) | `frame-signer.ts:58`, `animated-qr.ts:96` |
| Frame validity window | 5 seconds | `animated-qr.ts:86` |
| Frame rotation interval | 500 ms | Client-side `FrameSigner` |
| Max frames per window | ~10 | 5000 ms / 500 ms |
| Server secret entropy | >= 256 bits | `ANIMATED_QR_SECRET` (>= 32 hex chars, Audit-3 H-4) |
| Per-session secret | 256 bits | HMAC-SHA256 derivation from server secret |

### Brute-force analysis

The tag space is 2^64 (~1.8 x 10^19). An attacker attempting to forge a valid frame
HMAC must:

1. **Guess the 64-bit tag** for a specific `(baseUrl, timestamp, frameIndex)` triple.
2. **Submit the forged frame within the 5-second validity window.**

At the theoretical maximum rate of 10^9 guesses/second (network-bound; each guess
requires an HTTP round-trip), the expected time to find a collision is:

```
2^64 / 10^9 / 3600 / 24 / 365 ≈ 585 years
```

Even at 10^12 guesses/second (unrealistic for an online oracle), the expected time is
~213 days — well beyond the 5-second window.

### Birthday attack inapplicability

Birthday attacks reduce collision resistance to O(2^(n/2)) = O(2^32) for 64-bit tags.
However, birthday attacks require the attacker to find **any** collision among a set of
messages they control. In this protocol:

- The attacker does **not** control the server secret or the per-session derived key.
- The attacker cannot generate valid HMACs — only the server and the authorized client
  can.
- The attacker's goal is **second-preimage** (forge a tag for a specific message), not
  **collision** (find any two messages with the same tag).

Birthday attacks are therefore not applicable. The relevant security bound is the
second-preimage resistance of the truncated tag: 2^64.

### Replay protection

Even if an attacker captures a valid frame, replay is prevented by:

1. **Monotonic frame index:** The server tracks the highest seen frame index per session
   and rejects any frame with an index <= the last accepted index.
2. **Timestamp freshness:** Frames older than 5 seconds are rejected.
3. **Session binding:** The HMAC key is derived per-session, so a captured frame from
   one session cannot be replayed against another.

### Parallel session isolation

Each animated QR session derives its own HMAC key via
`HMAC-SHA256(serverSecret, "frame_secret:" + sessionIdentifier)`. Two concurrent
sessions for the same QR code use independent keys. A valid frame HMAC from session A
will not verify under session B's key.

### Conclusion

The 64-bit HMAC truncation provides 2^64 second-preimage resistance against an online
attacker constrained to a 5-second window. Combined with monotonic frame indices,
timestamp freshness checks, and per-session key derivation, the truncation is
cryptographically appropriate for this use case. No upgrade to the full 32-byte tag is
required.

A future protocol version may migrate to HMAC-SHA3-256 (per AUDIT-FINDING-013) — the
truncation analysis remains identical since it depends only on the output distribution,
which is uniform for both SHA-256 and SHA3-256.

---

## See Also

- **`ALGORITHM.md`** — full cryptographic architecture specification
- **[QRVA Protocol](./protocol.md)** — wire format, canonical payload, Merkle construction
- **[Threat Model](./threat-model.md)** — adversary capabilities, attack scenarios, mitigations
- **[Compliance](./compliance.md)** — NIST FIPS alignment, certifications, audit pathways
