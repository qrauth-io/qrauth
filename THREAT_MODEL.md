<!-- Canonical source: packages/docs/guide/threat-model.md. Keep in sync. -->

# Threat Model

This document describes the adversaries QRAuth is designed to defend against, the assets under protection, and the specific attack scenarios we address in the architecture. It is written for enterprise security review and is grounded in the specification in `ALGORITHM.md`.

---

## Scope

This threat model covers the QRAuth platform: the API server, the signer service, the SDKs, the verification flow, and the transparency log. It does not cover: physical attacks on authenticator hardware (Secure Enclave, TPM), supply-chain compromise of cryptographic libraries, social engineering attacks on platform administrators, or adversaries who have already obtained the tenant's private keys outside the system.

The model assumes the adversary has unlimited network capacity, can observe all public QRAuth traffic (including the transparency log), can target any number of tokens simultaneously, and may possess a Cryptographically Relevant Quantum Computer (CRQC) at some point in the future. The model does **not** assume the adversary has write access to the API server's filesystem, the signer service's filesystem, or the tenant's signing keys.

---

## Adversary Capabilities

The architecture must remain secure against an adversary with the capabilities in each column below. "Near-term quantum" covers a 5-10 year horizon in which some asymmetric schemes are broken but not all; "long-term CRQC" is the steady-state assumption that every Shor-vulnerable primitive is broken.

| Capability | Classical | Near-term Quantum (5–10y) | Long-term CRQC |
|---|---|---|---|
| Observe transparency log | Yes | Yes | Yes |
| Record all TLS traffic today | Yes | Yes | Yes |
| Break ECDSA-P256 from public key | No | Possible | Yes |
| Break RSA-2048 | No | Possible | Yes |
| Break ML-DSA (lattice) | No | No | Unknown |
| Break SLH-DSA (hash-based) | No | No | No (only Grover's) |
| Break SHA3-256 preimage | No | No | No (only Grover's → 128-bit) |
| Break HMAC-SHA3-256 | No | No | No |
| Break AES-256 | No | No | No (Grover's → 128-bit effective) |

The quantum-vulnerable primitives are ECDSA-P256 and RSA. Every other primitive the platform depends on holds even against a long-term CRQC (with a Grover-related security degradation of at most 50%).

---

## Assets Under Protection

The assets we defend are, in order of sensitivity:

- **Tenant SLH-DSA private keys** — the roots of QR-batch signing trust. Compromise lets an attacker forge arbitrary QR codes under the tenant's identity.
- **Tenant ECDSA private keys** — the classical leg of hybrid signing. Compromise has the same impact as above but only in regions that still accept the classical leg.
- **Tenant MAC secrets** — the hot-path symmetric verification key. Compromise lets an attacker bypass the fast path but does not let them forge signatures; the asymmetric legs still reject.
- **User session tokens (JWTs)** — HS256-signed, short-lived. Compromise yields impersonation of a single user session until expiry.
- **User WebAuthn credentials** — origin-bound to QRAuth, stored in authenticator hardware. Compromise lets an attacker authenticate as that user.
- **User PQC bridge private keys** — ML-DSA-44 keys stored in browser IndexedDB. Compromise paired with a WebAuthn compromise bypasses the bridged passkey defense.
- **The transparency log** — append-only, public, tamper-evident. The asset here is integrity, not confidentiality.
- **The PQC-health aggregate data** — per-org metrics about the migration state. Low sensitivity but should not leak cross-tenant.

---

## Attack Scenarios

### A — Harvest Now, Attack Later

**Description.** The adversary records every public QRAuth artifact they can access today — transparency log entries, verification responses, QR images — and archives them. When a Cryptographically Relevant Quantum Computer becomes available in 5–10 years, they use Shor's algorithm to derive tenant private keys from any public key material they captured. They then forge arbitrary QR codes under those keys, potentially years after the recording.

**Preconditions.** The adversary needs continuous access to public QRAuth surfaces and a future CRQC. Both are reasonable assumptions for a nation-state adversary.

**Impact.** If exploitable, the attacker would retroactively forge signatures on any archived public key. They could produce QR codes that claim to be from any captured tenant and pass any signature check that still trusts the classical leg.

**Mitigation.** The transparency log contains no recoverable public key material — only SHA3-256 commitments and SLH-DSA signatures over batch roots. SLH-DSA is hash-based (FIPS 205); no known quantum algorithm recovers private keys from its signatures. The tenant's ECDSA public key is still recoverable from classical signatures, but tokens signed under the hybrid algorithm require **both** ECDSA and SLH-DSA verifications to pass — a quantum break of ECDSA leaves the SLH-DSA leg intact and the forged token is rejected. See `ALGORITHM.md` §2.2 Scenario A.

### B — Protocol Downgrade

**Description.** The adversary forces a verifier to accept a token under a weaker algorithm version than the issuer intended. For example, they craft a token that claims `alg_version = 'ecdsa-p256-sha256-v1'` but whose payload would actually be rejected under the hybrid algorithm.

**Preconditions.** The verifier must be willing to accept the weaker version for the tenant in question, and the adversary must have access to the weaker algorithm's forgery surface (classical ECDSA break or an equivalent).

**Impact.** Successful downgrade lets an attacker present a legacy-signed token in a context that would otherwise require the hybrid algorithm, bypassing the PQC defense.

**Mitigation.** Every verifier strictly classifies `alg_version` into accepted / deprecated / rejected / unknown via `checkAlgVersion()`. The classifier is byte-identical across every first-party SDK and pinned by cross-language test vectors. Deprecated versions are accepted with a warning, and the warning surfaces in the response so operators see the degradation. Rejected and unknown versions fail closed. Future sunset dates move `ecdsa-p256-sha256-v1` from deprecated to rejected, at which point legacy tokens stop verifying entirely. The protocol has no "default to weakest" path. See `ALGORITHM.md` §11.

### C — Server or KMS Compromise

**Description.** The adversary gains write access to the API server or its filesystem. They read the SLH-DSA private key and forge signatures at will.

**Preconditions.** Full code execution on the API host. This is outside the quantum threat model — it is a classical compromise and the adversary already has what they need without quantum computing.

**Impact.** The adversary can forge any QR signature for any tenant whose key is present on the compromised host. If the API host holds the private keys (`SLH_DSA_SIGNER=local`), this is immediate. If not, the impact is limited to whatever the API box stores.

**Mitigation.** Production deployments use `SLH_DSA_SIGNER=http`, which keeps private keys on a separate signer host. The signer host has no inbound internet routes and accepts requests only from the API server's private IP range with a bearer-authenticated HTTP protocol. A compromise of the API host yields zero key material. The signer host is itself a much smaller attack surface: it runs a single 200-line fastify server with no database, no user-facing routes, and no external dependencies beyond the Node standard library and `@noble/post-quantum`. mTLS between the two hosts is a future hardening step. See [Security § Key Management Architecture](./security.md#key-management-architecture).

### D — Transparency Log Harvest

**Description.** The adversary scrapes the full transparency log over time and attempts to reconstruct tenant signing keys from the captured data. This is a specific instance of Scenario A but worth calling out separately because the transparency log is the adversary's highest-volume public data source.

**Preconditions.** Continuous scraping of the public transparency endpoints.

**Impact.** If the log exposed recoverable signatures or public keys, this would be a direct harvest surface. A long-term CRQC could derive private keys from enough samples.

**Mitigation.** Every transparency log entry in QRVA v2 carries only opaque commitments — a SHA3-256 hash over (token || tenant_id || destination_hash || geo_hash || expiry || nonce). Without the original nonce, the commitment reveals nothing about the payload. Batch root entries carry SLH-DSA signatures over Merkle roots (SLH-DSA signatures do not expose the private key) and `SHA3-256(tenant_public_key)` — the hash, not the key itself. Auditors retrieve the real public key via an authenticated endpoint and compare hashes. There is nothing in the log a quantum computer can use to derive a signing key. See `ALGORITHM.md` §8.

### E — WebAuthn Credential Forgery

**Description.** The adversary uses a future CRQC to recover a user's WebAuthn ECDSA-P256 private key from captured assertion public keys, then forges assertions to authenticate as that user.

**Preconditions.** The adversary has recorded at least one WebAuthn assertion from the target user (which exposes the public key in the ceremony) and has a CRQC.

**Impact.** Without mitigation, a successful attack impersonates the user for every QRAuth-backed application that accepts WebAuthn authentication.

**Mitigation.** Government-tier tenants configure `bridgePolicy: 'required'` on their organization, which enables the WebAuthn PQC bridge. The bridge adds a parallel ML-DSA-44 signature over the same challenge — the ML-DSA private key lives in the user's browser IndexedDB, scoped to the passkey's credential ID. Verification requires **both** the ECDSA WebAuthn assertion and the ML-DSA bridge signature. A quantum break of ECDSA does not defeat the lattice-based ML-DSA leg. For non-government tenants, the bridge is optional; they accept the residual risk in exchange for a simpler user experience, and they are flagged in the PQC health dashboard as running with the bridge off. The long-term fix is post-quantum WebAuthn, which the FIDO Alliance is standardising. See `ALGORITHM.md` §9.

### F — Real-Time Proxy / MitM

**Description.** The adversary stands up a proxy between the user and QRAuth that forwards requests and relays responses in real time. The user sees what looks like a legitimate verification page; the adversary captures the verification outcome or redirects it to their own destination.

**Preconditions.** The adversary can induce the user to visit a phishing domain (not `qrauth.io`) and run a transparent forwarder to the real API.

**Impact.** If undetected, the proxy can harvest the user's trust decision and potentially replay authentication to authorize actions on an attacker-controlled destination.

**Mitigation.** This is a classical attack, not a quantum one, and it is defended by Tiers 2 and 3 of the classical security model. Tier 2 renders a server-generated ephemeral visual proof (user location, device type, timestamp, procedural visual fingerprint) that a proxied page cannot reproduce without also successfully proxying the image pipeline — a slow operation that shows up in the Tier 3 latency analysis. Tier 3 composite signals (TLS fingerprint, canvas fingerprint, JS environment, latency profile) identify real-time MitM with high confidence and drop the token's trust score below the acceptance threshold. Proxied requests are not quantum-vulnerable in a way that changes with CRQC availability, so the classical mitigations are sufficient.

---

## Mitigations Summary

| Scenario | Mitigation | Residual Risk |
|---|---|---|
| A — Harvest Now, Attack Later | SLH-DSA root signing; hybrid verification; commitment-only log | Very low — requires both ECDSA and SLH-DSA breaks simultaneously |
| B — Protocol Downgrade | Strict `alg_version` classifier pinned in every SDK | Low — depends on every third-party verifier using the reference classifier |
| C — Server or KMS Compromise | Air-gapped signer service (`SLH_DSA_SIGNER=http`) | Low-medium — the signer host is itself a target but a much smaller attack surface |
| D — Transparency Log Harvest | Commitment-only log entries; public-key hashes not keys | Very low — no known cryptanalytic path against SLH-DSA or SHA3-256 |
| E — WebAuthn Credential Forgery | WebAuthn PQC bridge (ML-DSA-44) for high-security tenants | Medium — non-bridged tenants carry ECDSA-P256 exposure until FIDO PQC lands |
| F — Real-Time Proxy / MitM | Tiers 2 and 3 of the classical security model | Low — classical attack, classical mitigation |

---

## Out of Scope

- **Physical attacks on authenticator hardware.** Compromise of a Secure Enclave, TPM, or Titan chip is a device-level concern and outside the QRAuth threat model.
- **Supply-chain compromise of cryptographic libraries.** QRAuth depends on `@noble/post-quantum`, `@noble/hashes`, and Node's built-in `crypto`. We monitor security advisories but cannot defend against a malicious publication in any of these packages.
- **Social engineering against platform administrators.** Phishing or coercion targeting QRAuth operators is a human-process concern addressed by the operational security playbook, not by cryptographic architecture.
- **Pre-existing key compromise.** If the adversary already holds a tenant's private key at `t=0` — via an insider, a historical breach, or an operational mistake — no subsequent cryptographic mitigation can recover. The [Security § Incident Response](./security.md#incident-response) section describes the response procedure.

---

## Review Schedule

This threat model is reviewed:

- **After every cryptographic primitive change.** When a new algorithm enters `ALG_VERSION_POLICY` or an existing one moves between accepted / deprecated / rejected, the threat model is updated to reflect the change in the adversary capability table and any affected scenarios.
- **Annually, regardless of other triggers.** Once per calendar year, the full document is audited against the latest NIST, FIPS, and CISA guidance on post-quantum cryptography, and against the current state of the quantum computing research field.
- **On any disclosed vulnerability in a dependency.** If `@noble/post-quantum`, `@noble/hashes`, or Node's crypto module ships a CVE, we assess whether the threat model assumptions still hold and update accordingly.
- **On any significant change to the adversary landscape.** For example: publication of a practical quantum attack on SLH-DSA (not expected before 2040 at the earliest), a FIDO Alliance PQC WebAuthn standard, or a regulatory change that affects the `ecdsa-p256-sha256-v1` sunset timeline.

The changelog for this document lives in the file's git history. Review notes are kept in the QRAuth internal security team's runbook.

---

## See Also

- **`ALGORITHM.md`** §2 — authoritative threat model from the cryptographic architecture spec
- **[Security](./security.md)** — cryptographic primitives and key management
- **[QRVA Protocol](./protocol.md)** — wire format and verification flow
- **[Compliance](./compliance.md)** — certifications and audit pathways
