<!-- Canonical source: packages/docs/guide/security.md. Keep in sync. -->

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

## Key Management Architecture

QRAuth ships with two signing backends, selected via the `SLH_DSA_SIGNER` environment variable.

### Local backend (`SLH_DSA_SIGNER=local`)

The API server reads the tenant's SLH-DSA private key from its local filesystem (`config.kms.ecdsaPrivateKeyPath/{keyId}.slhdsa.key`) and signs in-process. This is the development and single-host deployment mode. It is explicitly **not** air-gapped — a compromise of the API host yields the private key.

The local backend is logged with a warning at startup:

```
SLH-DSA signing using LOCAL backend — private keys live on this host.
Set SLH_DSA_SIGNER=http for production hardening (ALGORITHM.md §13.1).
```

### HTTP backend (`SLH_DSA_SIGNER=http`)

The API server delegates signing to a standalone `packages/signer-service/` process running on a separate host with no inbound internet routes. The API server holds only the tenant's public key and the signer service's bearer token. The wire protocol is minimal:

```
POST {baseUrl}/v1/sign
  Authorization: Bearer {token}
  Body: { keyId: "<uuid>", message: "<base64>" }
  200:  { signature: "<base64>" }

GET {baseUrl}/v1/keys/{keyId}/public
  Authorization: Bearer {token}
  200:  { publicKey: "<base64>", algorithm: "slh-dsa-sha2-128s" }
```

The signer service logs every sign request to stderr with the keyId, the first 16 bytes of the message (hex), and the signature size. These lines feed operator audit pipelines.

Production deployments should use the HTTP backend. The signer host has inbound network access only from the API server's private IP range and no outbound internet. A compromise of the API box yields zero key material because the API box never holds the private key. mTLS between the API and the signer is a future hardening step; the current bearer-token scheme is acceptable MVP when the network path is actually firewalled.

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

## See Also

- **`ALGORITHM.md`** — full cryptographic architecture specification
- **[QRVA Protocol](./protocol.md)** — wire format, canonical payload, Merkle construction
- **[Threat Model](./threat-model.md)** — adversary capabilities, attack scenarios, mitigations
- **[Compliance](./compliance.md)** — NIST FIPS alignment, certifications, audit pathways
