<!-- Canonical source: this file. packages/docs/guide/compliance.md mirrors it. Keep in sync. -->

# Compliance

QRAuth is a security product. Enterprise and regulated-industry buyers evaluate it against formal compliance frameworks before deployment. This page lists the cryptographic standards our algorithms are specified in, our data-handling practices, how platform features may support your own compliance obligations, and the pathway for requesting a formal compliance review.

---

## Standards Alignment

QRAuth uses algorithms specified in FIPS 202, FIPS 204, FIPS 205 and FIPS 186-4:

| Standard | Algorithm | Where QRAuth uses it |
|---|---|---|
| NIST FIPS 205 (SLH-DSA) | SLH-DSA-SHA2-128s | Merkle batch-root signatures (post-quantum leg of hybrid QR signatures). See [ALGORITHM.md](ALGORITHM.md) |
| NIST FIPS 204 (ML-DSA) | ML-DSA-44 | Additional signature on passkeys registered with a WebAuthn bridge key |
| NIST FIPS 202 (SHA-3) | SHA3-256 | Canonical payload hashing, Merkle trees, the MAC pre-filter, proximity attestation subject and device hashes, the signing-key security webhook |
| NIST FIPS 198 (HMAC) | HMAC-SHA3-256, HMAC-SHA-256 | MAC pre-filter and signing-key security webhook (HMAC-SHA3-256); app webhooks and Living Codes frames (HMAC-SHA-256) |
| NIST FIPS 186-4 (DSS) | ECDSA-P256 | Classical leg of hybrid QR signatures, proximity attestations, auth-session approvals, WebAuthn credentials |

The algorithms are implemented and tested end-to-end; canonical-form test vectors are pinned in `packages/protocol-tests`, and property-based tests cover the canonical form and Merkle proofs. These rows describe algorithm choice. They are not FIPS 140 module validations: the implementations (`@noble/post-quantum`, Node.js `crypto`) have not been through the Cryptographic Module Validation Program as part of QRAuth.

---

## Post-Quantum Cryptographic Compliance

QRAuth uses the NIST post-quantum cryptography standards finalized in August 2024 for a defined set of artifacts. Which artifacts are post-quantum and which remain classical is listed in [Security § Post-quantum coverage](SECURITY.md#post-quantum-coverage).

### FIPS 205 (SLH-DSA / SPHINCS+)

SLH-DSA is the hash-based signature scheme standardised as FIPS 205. QRAuth uses SLH-DSA-SHA2-128s for tenant signing-key operations — it signs the Merkle batch roots that every hybrid QR signature's inclusion proof is verified against. The choice of SLH-DSA over ML-DSA (FIPS 204) for the batch root is deliberate: SLH-DSA's security reduces solely to hash function preimage resistance, without any dependence on structured algebraic hardness assumptions. Lattice-based signatures (ML-DSA) are likely secure under current cryptanalysis but carry a structured-assumption risk that hash-based schemes do not. For the long-lived QR signing path, we prefer the most conservative assumption available.

Implementation reference: `packages/api/src/services/slhdsa-adapter.ts`, which wraps `@noble/post-quantum` and is pinned to the SLH-DSA-SHA2-128s parameter set (32-byte public key, 64-byte private key, 7,856-byte signature, NIST security category 1).

### FIPS 204 (ML-DSA / CRYSTALS-Dilithium)

ML-DSA is the lattice-based signature scheme standardised as FIPS 204. QRAuth uses ML-DSA-44 for the WebAuthn PQC bridge. Passkeys registered with a bridge key carry an additional ML-DSA-44 signature, verified alongside the WebAuthn assertion when present. The bridge private key is generated and stored in the browser; the server stores only the public key. ML-DSA suits this interactive path better than SLH-DSA, whose signing cost is much higher. The ML-DSA-44 signature is 2,420 bytes.

Implementation reference: `packages/api/src/services/ml-dsa-adapter.ts`.

### FIPS 202 (SHA-3)

QR canonical payload hashing, Merkle trees, the MAC pre-filter (HMAC-SHA3-256), proximity attestation subject and device hashes, and the signing-key security webhook use SHA3-256. SHA3-256 has the same classical security as SHA-256 and uses a different internal construction (sponge vs Merkle-Damgård), which provides defence-in-depth against future attacks on either family.

SHA-256 remains in use for ECDSA, RSA and HS256 signatures, Living Codes frame tags and key derivation (HMAC-SHA-256, HKDF-SHA-256), app webhooks (HMAC-SHA-256), the issuance log hash chain, scanner IP hashing and the fallback device fingerprint. Tokens with the legacy `ecdsa-p256-sha256-v1` algorithm version are rejected and must be re-issued.

### FIPS 203 (ML-KEM / CRYSTALS-Kyber)

ML-KEM is the lattice-based key encapsulation mechanism standardised as FIPS 203. QRAuth does not use ML-KEM in the application layer — key exchange is handled at the TLS terminator. See [Security § TLS key exchange](SECURITY.md#tls-key-exchange).

### NIST SP 800-208 (Stateful Hash-Based Signatures)

SP 800-208 provides guidance on stateful hash-based signature schemes (XMSS, LMS). QRAuth's SLH-DSA parameter set is stateless, so the state-management requirements of SP 800-208 do not apply. Key lifecycle: tenant signing keys rotate every 90 days and are revoked 30 days after rotation, with key records retained as the audit record; MAC keys rotate every 90 days, retire 30 days after rotation and are deleted 7 days after retirement. See [Security § Key rotation](SECURITY.md#key-rotation).

### Harvest Now, Decrypt Later (NIST IR 8309, CISA PQC Guidance)

NIST IR 8309 and the CISA Post-Quantum Cryptography Initiative both identify "harvest now, decrypt later" as a critical concern for long-lived cryptographic assets. For QRAuth the long-lived assets are QR codes. The post-quantum leg of each hybrid QR signature verifies the row's Merkle inclusion proof against an SLH-DSA-SHA2-128s-signed batch root; SLH-DSA is hash-based. Every issuance is also appended to a hash-chained issuance log (SHA-256 chain); entries for hybrid rows carry the SHA3-256 Merkle leaf hash and a reference to the signed batch root.

The adversary analysis is in [THREAT_MODEL.md](THREAT_MODEL.md).

---

## Data Handling

### Encryption

Transport uses TLS 1.2 and 1.3. Tenant signing keys are stored as AES-256-GCM envelopes (format `qrauth-kek-v1`, key `SIGNER_MASTER_KEY`) in files with `mode 0600` on the API and signer hosts.

MAC secrets are stored in the `OrgMacKey` table in PostgreSQL. MAC keys rotate every 90 days, retire 30 days after rotation and are deleted 7 days after retirement (see [Security § Key rotation](SECURITY.md#key-rotation)).

### Tenant isolation

Tenants share one PostgreSQL schema. Isolation is enforced in the service layer by `organizationId` filters on tenant-scoped queries. The PQC health endpoint is scoped to `request.user.orgId`, not configurable by the caller.

### Personal data

- Scanner IP addresses are stored as SHA-256 hashes. Scan records also store the user agent as received and, when the scanner shares it, the reported location.
- Devices are identified by the `X-Device-Fingerprint` header when the client sends one; otherwise by a SHA-256 hash of browser, OS and device type. Device records also store the approximate city and country derived from the IP address.
- Login events store the IP address, approximate location, user agent and device fingerprint.

### Retention

The `qrauth-cleanup` worker runs hourly and applies these periods platform-wide:

| Data | Retention |
|---|---|
| Auth sessions | Deleted 24 hours after resolution or expiry |
| Refresh tokens | Deleted once expired or revoked |
| OIDC authorization codes, access tokens, sessions | Deleted once expired (authorization codes one hour after expiry) |
| OIDC refresh tokens | Deleted 7 days after the token family's lifetime |
| Login events | Deleted after 90 days |
| Scans | After 365 days the hashed IP and user agent are removed; the scan record is kept for aggregate analytics |
| Audit logs | Deleted after 730 days (2 years) |
| Trusted devices | Auto-revoked after the period set in the organization's device policy (`autoRevokeAfterDays`), when set |
| Issuance log entries | Kept indefinitely |
| Tenant signing keys | Revoked 30 days after rotation; key records retained |
| MAC secrets | Deleted 7 days after retirement |

### Right to erasure and access

Users can export their data with `GET /api/v1/account/export` and delete their account with `DELETE /api/v1/account/delete-account`. Account deletion removes the user's link to organization-owned QR codes and scans, which remain with the organization.

---

## GDPR

Our Data Processing Agreement is published at [qrauth.io/dpa](https://qrauth.io/dpa) and our sub-processor list at [qrauth.io/subprocessors](https://qrauth.io/subprocessors). Under the DPA, QRAuth acts as processor for its tenants (controllers). The DPA covers the purposes and categories of processing, processor obligations, sub-processors, international transfers, security measures, data subject rights and breach notification.

Platform features that may support a controller's GDPR obligations:

- Data export and account deletion endpoints (Articles 15, 17 and 20).
- Automated retention periods enforced by the cleanup worker (Article 5(1)(e)), listed above.
- SHA-256 hashing of scanner IP addresses before storage.
- Organization audit logs (`GET /api/v1/organizations/:id/audit-logs`).

These features support compliance; they do not by themselves make a deployment GDPR-compliant. Tenants requiring a signed DPA can contact the team via the pathway in [Requesting a Compliance Review](#requesting-a-compliance-review) below.

---

## Requesting a Compliance Review

Enterprise and government-tier tenants can request a formal compliance review before deployment. The review covers:

- Mapping of the QRAuth threat model to the tenant's specific compliance requirements (NIST, ISO 27001, SOC 2, eIDAS, NIS2, sector-specific regulations)
- Cryptographic architecture walkthrough with the QRAuth security team
- Review of the tenant's configuration (device policy, signing-key rotation, data retention)
- Access to the full [ALGORITHM.md](ALGORITHM.md) specification and the protocol test vectors
- A written assessment delivered within 10 business days of the review call

To request a review, contact **security@qrauth.io** with:

- Your organisation name and the regulatory framework you need to align against
- The QRAuth plan you are evaluating
- Any specific controls or certifications the review must address

Reviews for government-tier tenants are provided at no cost. Enterprise reviews are available under the standard engineering support agreement.

---

## See Also

- **[ALGORITHM.md](ALGORITHM.md)** — full cryptographic architecture specification
- **[Security](SECURITY.md)** — post-quantum coverage, cryptographic primitives, key management
- **[THREAT_MODEL.md](THREAT_MODEL.md)** — adversary capabilities, attack scenarios
- **[QRVA Protocol](packages/docs/guide/protocol.md)** — wire format, canonical payload, Merkle construction
