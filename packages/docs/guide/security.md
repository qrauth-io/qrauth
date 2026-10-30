# Security

This page is written for enterprise security teams evaluating QRAuth during procurement. It describes the threat model the platform is designed against, the cryptographic primitives in use, and the known limitations we document plainly rather than paper over. The full technical specification lives in [ALGORITHM.md](https://github.com/qrauth-io/qrauth/blob/main/ALGORITHM.md) and the adversary analysis in [THREAT_MODEL.md](https://github.com/qrauth-io/qrauth/blob/main/THREAT_MODEL.md); this page summarises what matters for a security review.

---

## Reporting a Vulnerability

Report suspected vulnerabilities by email to **security@qrauth.io**. We welcome reports from security researchers and will work with you on coordinated disclosure.

Please include:

- The affected endpoint, host, or package (and version where relevant).
- Steps to reproduce, including any proof-of-concept request or payload.
- The impact you believe the issue has.

We aim to acknowledge every report within **72 hours**. Please do not test against production user data — use your own accounts and test data, and avoid actions that could degrade service for other users or expose third-party information.

A machine-readable contact is published at [`https://qrauth.io/.well-known/security.txt`](https://qrauth.io/.well-known/security.txt) (RFC 9116).

---

## Security Model Overview

QRAuth combines several independent controls. They run without per-tenant configuration:

- **Cryptographic signing.** Every QR code is issued with a hybrid signature: an ECDSA-P256 signature over its canonical payload, plus a Merkle inclusion proof against a batch root signed with SLH-DSA-SHA2-128s. Verification is performed by the QRAuth verify endpoint.
- **Ephemeral visual proof.** The verification page shows values the server observed for that request (approximate location, browser and OS, timestamp, and a keyed fingerprint). A static copy of the page does not reproduce them.
- **Fraud signals and trust score.** A background worker evaluates each scan for duplicate locations, geo-impossible scan sequences, scan velocity, bot user agents and device clustering, plus dynamic rules stored in the database. Open fraud incidents and recent scan velocity lower the trust score returned on verification.
- **WebAuthn passkeys.** Origin-bound credentials: the browser releases an assertion only for the relying party the passkey was registered with.
- **Post-quantum layer.** Hash-based and symmetric primitives protect a defined subset of artifacts, described in [Post-quantum coverage](#post-quantum-coverage) below.

---

## Quantum Threat Model

QRAuth's signing infrastructure is designed against the "harvest now, attack later" (HNDL) threat: an adversary who records public signatures and verification traffic today, then uses a future Cryptographically Relevant Quantum Computer (CRQC) to derive private keys and forge signatures. This matters for a platform with QRAuth's characteristics — QR codes are long-lived (expiry measured in months or years), issuance records are kept indefinitely, and the target market includes government and physical infrastructure.

### Post-quantum coverage

The post-quantum layer does not replace the other controls, and it does not cover every artifact. The split is:

**Post-quantum (hash-based or symmetric primitives):**

- The SLH-DSA-SHA2-128s leg of hybrid QR signatures (Merkle batch-root signatures).
- SHA3-256 canonical-payload and Merkle hashing.
- The HMAC-SHA3-256 MAC pre-filter and signing-key security webhooks.
- HMAC-SHA-256 app webhooks and Living Codes frame tags.
- AES-256-GCM encryption of signing-key envelopes at rest.
- HS256 session JWTs.
- The ML-DSA-44 bridge signature, on passkeys registered with a bridge key.

**Classical only (vulnerable to Shor's algorithm):**

- The ECDSA-P256 leg of QR signatures.
- Proximity attestations (ES256-style JWT, ECDSA-P256).
- Auth-session approval signatures (ECDSA-P256).
- OIDC ID tokens (RS256 by default, ES256 optional).
- WebAuthn passkey credentials (ECDSA-P256).
- TLS key exchange.

For a QR code in the `hybrid-ecdsa-slhdsa-v1` state, verification passes only if the ECDSA-P256 signature verifies **and** the post-quantum leg verifies: the verifier recomputes the Merkle leaf from the QR's canonical data and stored nonce, requires it to equal the stored leaf, and walks the inclusion proof from that recomputed leaf to an SLH-DSA-SHA2-128s-signed batch root. Both legs are therefore bound to the same payload. A hybrid row without complete Merkle data fails verification.

### Verification path

Each QR verification runs, in order: the HMAC-SHA3-256 MAC pre-filter (when the row has a MAC, a mismatch rejects; a match never skips the later checks), ECDSA-P256 verification over the canonical payload, recomputation of the SHA3-256 Merkle leaf from the same payload and the stored nonce (it must equal the stored leaf), the inclusion-proof walk from that recomputed leaf, and the SLH-DSA-SHA2-128s batch-root signature check (cached per batch for one hour after a successful verification; failures are not cached). See [ALGORITHM.md](https://github.com/qrauth-io/qrauth/blob/main/ALGORITHM.md) for the canonical form and Merkle construction.

### Cryptographic agility

QR signatures and proximity attestations carry an explicit `alg_version`. The QRAuth verifier classifies it as accepted, deprecated, rejected or unknown, and fails closed on rejected and unknown versions. Today `ecdsa-p256-sha256-v1` is rejected and no version is in the deprecated state. Moving between algorithms does not require a protocol break.

---

## Cryptographic Primitives

| Primitive | Algorithm | Standard | Quantum Status | Used For |
|---|---|---|---|---|
| QR signing, classical leg | ECDSA-P256 | FIPS 186-4 | Vulnerable | Per-QR signature over the canonical payload |
| QR signing, post-quantum leg | SLH-DSA-SHA2-128s | FIPS 205 | Resistant | Merkle batch-root signing on the signer service |
| Merkle tree hashing | SHA3-256 | FIPS 202 | Resistant | Merkle batch leaves, nodes and inclusion proofs |
| Payload hashing | SHA3-256 | FIPS 202 | Resistant | Canonical payload (destination and location hashes) |
| MAC pre-filter | HMAC-SHA3-256 | FIPS 198 / FIPS 202 | Resistant | Rejects rows whose MAC does not match; never skips signature checks |
| App event webhooks | HMAC-SHA-256 | FIPS 198 / FIPS 180-4 | Resistant | Event authentication (`X-QRAuth-Signature: sha256=<hex>`) |
| Signing-key security webhook | HMAC-SHA3-256 | FIPS 198 / FIPS 202 | Resistant | Signing-key event authentication (`X-QRAuth-Signature: sha3-256=<hex>`) |
| Living Codes frames | HMAC-SHA-256 (64-bit tag), HKDF-SHA-256 | FIPS 198 / RFC 5869 | Resistant | Animated QR frame tags |
| Proximity attestation | ECDSA-P256 | FIPS 186-4 | Vulnerable | Signed proximity attestation JWTs |
| Auth-session approval | ECDSA-P256 | FIPS 186-4 | Vulnerable | Approval signatures on QR auth sessions |
| OIDC ID tokens | RS256 (default) / ES256 | RFC 7518 | Vulnerable | Sign in with QRAuth |
| WebAuthn PQC bridge | ML-DSA-44 | FIPS 204 | Resistant | Additional signature on passkeys registered with a bridge key |
| WebAuthn credentials | ECDSA-P256 | FIPS 186-4 | Vulnerable | Passkey authentication |
| Key envelopes at rest | AES-256-GCM | FIPS 197 | Resistant * | Tenant signing-key envelopes (`qrauth-kek-v1`) |
| Issuance log chain | SHA-256 | FIPS 180-4 | Resistant | Hash-chained issuance log |
| Transport | TLS 1.2 / 1.3 | RFC 5246 / RFC 8446 | Classical key exchange ** | All connections |
| JWT session signing | HS256 | RFC 7518 | Resistant | API session tokens |

\* 128-bit effective security under Grover's algorithm, which remains intractable.
\*\* TLS key exchange is negotiated by the TLS terminator, outside the application layer. See [TLS key exchange](#tls-key-exchange).

Webhook formats and verification are documented in [Webhooks](/api/webhooks).

JWT session tokens use HS256 (HMAC-SHA-256) — a symmetric algorithm, not ECDSA. No post-quantum migration is required for the session-token layer.

WebAuthn credentials remain on ECDSA-P256 because the credential is generated inside the user's authenticator hardware (Secure Enclave, TPM, Titan chip), which QRAuth cannot unilaterally change. See [Known Limitations](#known-limitations) below.

---

## Known Limitations

We state limitations plainly.

### WebAuthn passkeys

FIDO2 credentials use ECDSA-P256 by default. The credential is generated and stored in authenticator hardware (Secure Enclave on Apple devices, Titan on Google, TPM on Windows, platform-specific equivalents elsewhere). QRAuth cannot change this from the server side — the algorithm choice is enforced at the hardware level by the authenticator, not by our application code. Post-quantum WebAuthn credential types depend on authenticator and browser support.

Passkeys registered with a bridge key carry an additional ML-DSA-44 signature, verified alongside the WebAuthn assertion when present. The bridge private key is generated and stored in the browser; the server stores only the public key.

### TLS key exchange

TLS key exchange is handled by the TLS terminator in front of the application. Classical ECDHE key exchange (for example X25519) is vulnerable to Shor's algorithm. Whether a connection uses a hybrid post-quantum key exchange depends on the client and the terminator; the application layer makes no post-quantum claim for TLS. Operators running their own deployment should enable hybrid post-quantum key exchange at their terminator where it is supported.

### Legacy ECDSA-signed tokens

Tokens with `alg_version = 'ecdsa-p256-sha256-v1'` are rejected: they fail verification and must be re-issued. No algorithm version is currently in the deprecated state.

Tenants can query the PQC health endpoint (`GET /api/v1/analytics/pqc-health`) to see their QR codes by algorithm version, rows stuck in the pending state, passkey bridge coverage and MAC key age.

---

## Key Management Architecture

### Key custody

Tenant ECDSA-P256 and SLH-DSA-SHA2-128s private keys are generated on the API host, encrypted at rest as AES-256-GCM envelopes (format `qrauth-kek-v1`, key `SIGNER_MASTER_KEY`), and provisioned to the signer host. Both the API and the signer reject key envelopes that lack the format tag. `SIGNER_MASTER_KEY` is 32 random bytes supplied through the environment; it is not rotated automatically.

In production all signing operations run on the signer host (`ECDSA_SIGNER=http`, `SLH_DSA_SIGNER=http`): the API sends the canonical bytes to sign and receives signatures.

### Signing infrastructure

In our production deployment the signer service (`packages/signer-service/`) runs on a separate host reachable only over a private network. It exposes bearer-authenticated endpoints for SLH-DSA-SHA2-128s batch-root signing (`POST /v1/sign`), ECDSA-P256 canonical signing (`POST /v1/sign-ecdsa`), ECDSA and RSA JWS signing for OIDC (`POST /v1/sign-ecdsa-jws`, `POST /v1/sign-rsa-jws`), Living Codes MAC sessions (`/v1/mac/*`), public-key retrieval (`GET /v1/keys/:keyId/public`) and key provisioning (`POST /v1/keys/:keyId`).

The signer refuses to start unless `SIGNER_TOKEN` is at least 32 characters, compares bearer tokens in constant time, and accepts a second token (`SIGNER_TOKEN_NEXT`) during token rotation. It logs every signature with the key ID, the SHA3-256 fingerprint of the signed message, the message length and the signature length.

| Variable | Values | Description |
|----------|--------|-------------|
| `ECDSA_SIGNER` | `local` \| `http` | Signing backend. `local` for development, `http` for production. |
| `ECDSA_SIGNER_URL` | URL | Signer service URL (e.g., `http://10.0.0.2:7788`) |
| `ECDSA_SIGNER_TOKEN` | string | Bearer token for signer authentication |
| `SLH_DSA_SIGNER` | `local` \| `http` | Same as above for SLH-DSA |
| `SLH_DSA_SIGNER_URL` | URL | Signer service URL |
| `SLH_DSA_SIGNER_TOKEN` | string | Bearer token |
| `SIGNER_MASTER_KEY` | base64 | AES-256-GCM master key for key envelopes at rest (shared between API and signer) |

With the local backend (`*_SIGNER=local`), the API host decrypts the envelopes (for example `{keyId}.slhdsa.enc`) and signs in-process, so private keys are usable on the API host. This is the development and single-host mode. The API logs a warning at startup:

```
SLH-DSA signing using LOCAL backend — private keys live on this host.
Set SLH_DSA_SIGNER=http for production hardening (ALGORITHM.md §13.1).
```

### Key rotation

**Tenant signing keys** (ECDSA-P256 + SLH-DSA-SHA2-128s pairs):

1. The hourly `qrauth-cleanup` worker rotates an ACTIVE key once it is 90 days old (`SIGNING_KEY_ROTATION_DAYS`).
2. `SigningService.rotateKey()` generates the new pair on the API host, writes its encrypted envelopes, provisions them to the signer and inserts the new public keys into the database. New issuances use the new key.
3. The old key becomes `ROTATED` (verify-only).
4. 30 days after rotation (`SIGNING_KEY_REVOKE_GRACE_DAYS`), the `ROTATED` key becomes `REVOKED`: it is no longer published or accepted by status-filtered verifiers. Key records are retained as the audit record and are not purged. QR codes issued under a rotated or revoked key continue to verify; to invalidate them, revoke the QR codes (see [Incident Response](#incident-response)).

Owners and admins can rotate a tenant's signing key manually with `POST /api/v1/organizations/:id/keys/rotate`.

**MAC keys** (`OrgMacKey`, stored in the database): ACTIVE for 90 days, then `ROTATED` when a new key is minted (live rows are re-MACed under the new key at rotation), `RETIRED` 30 days after rotation, and deleted 7 days after retirement.

---

## Incident Response

If a tenant signing key is suspected of compromise, the response procedure is:

1. **Immediate rotation.** Rotate the key with `POST /api/v1/organizations/:id/keys/rotate` (OWNER or ADMIN). New issuances use the fresh ECDSA + SLH-DSA pair; the old key becomes `ROTATED`.
2. **Revoke the affected QR codes.** QR codes issued under the compromised key that are still in the field should be revoked via `DELETE /api/v1/qrcodes/:token`. Revocation takes effect at the verifier immediately: the next scan returns `verified: false` with the reason "This QR code has been revoked by its issuer."
3. **Review issuance records.** Use the PQC health endpoint and the hash-chained issuance log to identify QR codes and signed batches issued under the affected key.
4. **Notify affected third parties.** Integrators holding the tenant's public key should be notified that the key has rotated. The new public key is available to owners and admins via `GET /api/v1/organizations/:id/keys`.

---

## Living Codes HMAC Tag Truncation Analysis

> Audit-3 M-3: formal security analysis for the 8-byte HMAC truncation used in
> animated QR frame signing.

### Context

Each Living Codes frame carries an HMAC-SHA-256 tag truncated to the first 8 bytes
(16 hex characters). The full tag is 32 bytes (256 bits). This section documents why
the truncation is appropriate for this specific use case.

### Parameters

| Parameter | Value | Source |
|---|---|---|
| Full HMAC output | 256 bits (32 bytes) | HMAC-SHA-256 |
| Truncated tag | 64 bits (8 bytes, 16 hex chars) | `frame-signer.ts`, `animated-qr.ts` |
| Frame acceptance window | At most 5 s old, at most 2 s in the future | `animated-qr.ts` |
| Frame rotation interval | 1000 ms by default, configurable (`frameInterval`) | `@qrauth/animated-qr` renderer |
| Frames generated per 5 s window | ~5 at the default interval | 5000 ms / 1000 ms |
| Server secret | At least 32 characters enforced; generate with `openssl rand -hex 32` (256 bits) | `ANIMATED_QR_SECRET` (Audit-3 H-4) |
| Per-session secret | 256 bits | HKDF-SHA-256 (RFC 5869) from the server secret, salt `qrauth:animated-qr:v1` |

### Brute-force analysis

The tag space is 2^64 (~1.8 x 10^19). An attacker attempting to forge a valid frame
HMAC must:

1. **Guess the 64-bit tag** for a specific `(baseUrl, timestamp, frameIndex)` triple.
2. **Submit the forged frame within the acceptance window.**

At the theoretical maximum rate of 10^9 guesses/second (network-bound; each guess
requires an HTTP round-trip), the expected time to find a matching tag is:

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
- The attacker cannot generate valid HMACs without the per-session frame secret, which
  is derived server-side per session and secret generation, and released only to a
  confidential client or to the browser that holds the session's frame verifier.
- The attacker's goal is **second-preimage** (forge a tag for a specific message), not
  **collision** (find any two messages with the same tag).

Birthday attacks are therefore not applicable. The relevant security bound is the
second-preimage resistance of the truncated tag: 2^64.

### Replay protection

The frame-verify endpoint (`POST /api/v1/animated-qr/validate`) applies these checks:

1. **Monotonic frame index:** The server keeps the highest accepted frame index per
   session (in Redis, 10-minute TTL) and rejects any frame whose index is not strictly
   greater. If Redis is unavailable, the frame is rejected.
2. **Timestamp freshness:** Frames more than 5 seconds old or more than 2 seconds in
   the future are rejected.
3. **Session binding:** The HMAC key is derived per session, so a captured frame from
   one session does not verify against another.

### Parallel session isolation

Each animated QR session derives its own HMAC key via
`HKDF-SHA-256(serverSecret, salt = "qrauth:animated-qr:v1", info = "frame_secret:" + sessionIdentifier)`.
Two concurrent sessions for the same QR code use independent keys. A valid frame HMAC
from session A will not verify under session B's key.

### Conclusion

The 64-bit HMAC truncation provides 2^64 second-preimage resistance against an online
attacker constrained to the acceptance window. Combined with monotonic frame indices,
timestamp freshness checks, and per-session key derivation, the truncation is
appropriate for this use case. No upgrade to the full 32-byte tag is required.

HMAC-SHA-256 is transitional for Living Codes; migration to HMAC-SHA3-256 is deferred
(Audit-1 Finding-013). The truncation analysis is identical for both, since it depends
only on the output distribution, which is uniform for both SHA-256 and SHA3-256.

---

## See Also

- **[ALGORITHM.md](https://github.com/qrauth-io/qrauth/blob/main/ALGORITHM.md)** — full cryptographic architecture specification
- **[THREAT_MODEL.md](https://github.com/qrauth-io/qrauth/blob/main/THREAT_MODEL.md)** — adversary capabilities, attack scenarios, mitigations
- **[QRVA Protocol](./protocol.md)** — wire format, canonical payload, Merkle construction
- **[Compliance](./compliance.md)** — standards alignment, data handling, compliance review
