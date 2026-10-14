<!-- Canonical source: packages/docs/guide/compliance.md. Keep in sync. -->

# Compliance

QRAuth is a security product. Enterprise and regulated-industry buyers evaluate it against formal compliance frameworks before deployment. This page lists our active and planned certifications, our alignment with post-quantum cryptographic standards, data-handling practices, and the pathway for requesting a formal compliance review.

---

## Certifications Roadmap

| Certification | Target / Status | Notes |
|---|---|---|
| NIST FIPS 205 (SLH-DSA) alignment | Shipped — Q2 2026 | QR batch signing layer; `ALGORITHM.md` specifies the full architecture |
| NIST FIPS 204 (ML-DSA) alignment | Shipped — Q2 2026 | WebAuthn PQC bridge (ML-DSA-44) for high-security tenants |
| NIST FIPS 202 (SHA-3) adoption | Shipped — Q2 2026 | All new cryptographic operations use SHA3-256 |
| NIST FIPS 198 (HMAC) | Shipped — Q2 2026 | HMAC-SHA3-256 for the symmetric fast path |
| eIDAS 2.0 compatibility | 2026–2027 | EU regulation in force May 2024; member-state integration window |
| SOC 2 Type I | Q4 2026 | Baseline security controls attestation |
| SOC 2 Type II | Q2 2027 | Operational effectiveness over time |
| GDPR compliance | Launch (Q3 2026) | EU data protection; mandatory for EU market operation |
| ISO 27001 | Q4 2027 | Information security management system |
| NIST FIPS 203 (ML-KEM) alignment | Roadmap (Phase PQC-3) | Planned for JWT key exchange once TLS-level support is in place |
| PQC Architecture Review | Available now on request | Provided to government and enterprise tenants pre-deployment |

The three FIPS alignment rows are listed as "Shipped" because the algorithms are implemented, tested end-to-end, covered by cross-language test vectors, and deployed in the production architecture. They are not formal FIPS certifications — NIST-approved modules go through the Cryptographic Module Validation Program, and QRAuth's validation pathway is a 2027 target. The "Shipped" status means the code paths exist and match the FIPS specifications; the formal certificates are a separate track.

---

## Post-Quantum Cryptographic Compliance

QRAuth aligns with the NIST post-quantum cryptography standards finalized in August 2024:

### FIPS 205 (SLH-DSA / SPHINCS+)

SLH-DSA is the hash-based signature scheme standardised as FIPS 205. QRAuth uses SLH-DSA-SHA2-128s for tenant signing-key operations — the root of the QR-batch signing hierarchy. The choice of SLH-DSA over ML-DSA (FIPS 204) for the batch root is deliberate: SLH-DSA's security reduces solely to hash function preimage resistance, without any dependence on structured algebraic hardness assumptions. Lattice-based signatures (ML-DSA) are likely secure under current cryptanalysis but carry a structured-assumption risk that hash-based schemes do not. For the long-lived, high-assurance QR signing path, we prefer the most conservative assumption available.

Implementation reference: `packages/api/src/services/slhdsa-adapter.ts`, via `@noble/post-quantum`. The adapter is audited and pinned to SLH-DSA-SHA2-128s parameter set (32-byte public key, 64-byte private key, 7,856-byte signature, ~128-bit post-quantum security).

### FIPS 204 (ML-DSA / CRYSTALS-Dilithium)

ML-DSA is the lattice-based signature scheme standardised as FIPS 204. QRAuth uses ML-DSA-44 for the WebAuthn PQC bridge — a per-credential signature that runs alongside the WebAuthn ECDSA-P256 assertion for bridged passkeys. ML-DSA is the right choice here because the bridge runs on interactive latency (sub-10ms sign, sub-5ms verify), which rules out SLH-DSA's larger signing cost. The 2,420-byte ML-DSA signature also fits comfortably inside a browser IndexedDB payload and a single HTTP request.

Implementation reference: `packages/api/src/services/ml-dsa-adapter.ts`. Tenant enforcement via `DevicePolicy.bridgePolicy` (required / optional / disabled).

### FIPS 202 (SHA-3)

Every new cryptographic operation in QRAuth uses SHA3-256 (Keccak) instead of SHA-256. SHA3-256 has the same classical security as SHA-256 and uses a different internal construction (sponge vs Merkle-Damgård), which provides defence-in-depth against future attacks on either family. The symmetric fast path uses HMAC-SHA3-256 as specified in FIPS 198.

SHA-256 remains present in legacy code paths — specifically in the original ECDSA-P256 signing layer for tokens issued before the PQC cutover. Those tokens verify under SHA-256 until they are re-issued; every new token uses SHA3-256.

### FIPS 203 (ML-KEM / CRYSTALS-Kyber)

ML-KEM is the lattice-based key encapsulation mechanism standardised as FIPS 203. QRAuth does not currently use ML-KEM in the application layer — key exchange is handled at the TLS terminator. Cloudflare is deploying hybrid X25519+ML-KEM768 in production as of 2025, which eliminates the TLS key-exchange harvest surface for Cloudflare-fronted deployments without any QRAuth-side change. Direct application-layer ML-KEM use is on the Phase PQC-3 roadmap if we move to an edge deployment model where Cloudflare is not in the path.

### NIST SP 800-208 (Stateful Hash-Based Signatures)

SP 800-208 provides guidance on stateful hash-based signature schemes (XMSS, LMS). QRAuth's SLH-DSA parameter set is stateless, so the strict state-management requirements of SP 800-208 do not apply verbatim. We do, however, follow the spirit of the guidance in our key lifecycle management: atomic leaf index tracking where relevant, monotonic rotation scheduling, and hard-delete of retired key material after the grace window. The key rotation worker in `packages/api/src/workers/index.ts` implements this lifecycle.

### Harvest Surface Elimination (NIST IR 8309, CISA PQC Guidance)

NIST IR 8309 and the CISA Post-Quantum Cryptography Initiative both identify "harvest now, decrypt later" as a critical concern for long-lived cryptographic assets. QRAuth's transparency log is designed to eliminate this harvest surface entirely: every log entry is an opaque SHA3-256 commitment, every batch root entry carries a SHA3-256 hash of the tenant's public key instead of the key itself, and the only asymmetric artifact in the log is the SLH-DSA signature over the batch root, which is hash-based and does not expose the private key under any known quantum algorithm.

The formal threat model analysis is in [Threat Model § Scenario D — Transparency Log Harvest](./threat-model.md#d--transparency-log-harvest).

---

## Data Handling

### Encryption

All customer data is encrypted at rest (AES-256-GCM, FIPS 197) and in transit (TLS 1.3, RFC 8446). Database and file-storage encryption is handled by the managed infrastructure layer (Neon for Postgres, Cloudflare R2 or equivalent for files). TLS termination uses the deployment front-end (Cloudflare on qrauth.io production).

Key material for batch signing is stored in the signer service's local filesystem with `mode 0600` permissions. Key material for HMAC MAC secrets is stored in the `OrgMacKey` table in Postgres, encrypted at the database layer. MAC key rotation runs every 90 days with a 30-day grace window and a 7-day retired-before-purge window (see [Security § Key rotation](./security.md#key-rotation)).

### Tenant isolation

All tenant data is logically isolated at the schema level in PostgreSQL. Every query that touches tenant-scoped tables is filtered by `organizationId` in the service layer; there is no cross-tenant join at the API surface. The PQC health endpoint is explicitly org-scoped via `request.user.orgId`, not configurable by the caller.

### PII minimisation

Scanner IP addresses are hashed with SHA-256 before storage. User agents are truncated to the first 128 characters. Device fingerprints are composite hashes (hardware + UA + device type), never raw identifiers. Tokens in the transparency log are referenced by their `commitment` hash, not their plaintext value.

### Data residency

EU tenants can specify EU-only data storage at signup. The production stack supports Neon EU regions and Cloudflare EU Workers. Data residency is configured at the tenant level; once set, the tenant's data never leaves the selected region without an explicit export request.

### Retention

Default retention for scan events is 90 days, configurable per tenant. Transparency log entries are retained indefinitely (the log is append-only and tamper-evident; retention is a feature, not a compliance burden). Audit logs are retained for 7 years. Signing key material is retained until 7 days after the `RETIRED` transition, then hard-deleted.

### Right to erasure

Tenant deletion purges all associated data within 30 days. Transparency log entries for the deleted tenant are replaced with a tombstone record so the append-only chain remains tamper-evident. Signing keys are hard-deleted. User data stored under the tenant (devices, passkeys, auth sessions) is purged in the same 30-day window.

---

## GDPR

QRAuth operates as a data processor for its tenants (data controllers). The standard Data Processing Addendum covers:

- The legal basis for processing (Article 6(1)(b) — performance of a contract)
- The categories of personal data processed (IP hashes, device fingerprints, user agents, WebAuthn public keys)
- The purposes of processing (QR verification, fraud detection, device trust, passwordless authentication)
- Sub-processor disclosures (Neon, Cloudflare, Stripe, the TLS provider)
- Data subject rights (access, rectification, erasure, portability, objection)
- Security measures (this document + `ALGORITHM.md`)
- Data breach notification procedures (72-hour window, incident response runbook)
- International transfers (Standard Contractual Clauses for non-EU storage; EU-only regions available on request)

Tenants requiring a signed DPA can contact the team via the pathway in [Requesting a Compliance Review](#requesting-a-compliance-review) below.

---

## Requesting a Compliance Review

Enterprise and government-tier tenants can request a formal compliance review before deployment. The review covers:

- Mapping of the QRAuth threat model to the tenant's specific compliance requirements (NIST, ISO 27001, SOC 2, eIDAS, sector-specific regulations)
- Cryptographic architecture walkthrough with the QRAuth security team
- Review of the tenant's configuration (bridge policy, key rotation schedule, retention policy)
- Access to the full `ALGORITHM.md` specification and the protocol test vectors
- A written assessment delivered within 10 business days of the review call

To request a review, contact **security@qrauth.io** with:

- Your organisation name and the regulatory framework you need to align against
- The QRAuth tier you are evaluating (standard, enterprise, government)
- Any specific controls or certifications the review must address

Reviews for government-tier tenants are provided at no cost. Enterprise reviews are available under the standard engineering support agreement.

---

## See Also

- **`ALGORITHM.md`** — full cryptographic architecture specification
- **[Security](./security.md)** — threat model, cryptographic primitives, key management
- **[Threat Model](./threat-model.md)** — adversary capabilities, attack scenarios
- **[QRVA Protocol](./protocol.md)** — wire format, canonical payload, Merkle construction
