<!-- Authoritative threat model. packages/docs/guide/threat-model.md is a summary that links here. -->

# Threat Model

This document describes the adversaries QRAuth is designed to defend against, the assets under protection, and the specific attack scenarios we address in the architecture. It is written for enterprise security review and is grounded in the specification in [`ALGORITHM.md`](ALGORITHM.md).

---

## Scope

This threat model covers the QRAuth platform: the API server, the signer service, the SDKs, the verification flow, and the issuance log. It does not cover: physical attacks on authenticator hardware (Secure Enclave, TPM), supply-chain compromise of cryptographic libraries, social engineering attacks on platform administrators, or adversaries who have already obtained the tenant's private keys outside the system.

The model assumes the adversary has unlimited network capacity, can observe all public QRAuth traffic, can target any number of tokens simultaneously, and may possess a Cryptographically Relevant Quantum Computer (CRQC) at some point in the future. The model does **not** assume the adversary has write access to the API server's filesystem, the signer service's filesystem, or the tenant's signing keys.

---

## Adversary Capabilities

The architecture must remain secure against an adversary with the capabilities in each column below. "Near-term quantum" covers a 5-10 year horizon in which some asymmetric schemes are broken but not all; "long-term CRQC" is the steady-state assumption that every Shor-vulnerable primitive is broken.

| Capability | Classical | Near-term Quantum (5–10y) | Long-term CRQC |
|---|---|---|---|
| Observe public QRAuth endpoints | Yes | Yes | Yes |
| Record all TLS traffic today | Yes | Yes | Yes |
| Break ECDSA-P256 from public key | No | Possible | Yes |
| Break RSA-2048 | No | Possible | Yes |
| Break ML-DSA (lattice) | No | No | Unknown |
| Break SLH-DSA (hash-based) | No | No | No (only Grover's) |
| Break SHA3-256 preimage | No | No | No (only Grover's → 128-bit) |
| Break HMAC-SHA3-256 | No | No | No |
| Break AES-256 | No | No | No (Grover's → 128-bit effective) |

The quantum-vulnerable primitives are ECDSA-P256, RSA, and the X25519 key exchange in TLS. The other primitives the platform depends on (SLH-DSA-SHA2-128s, ML-DSA-44, SHA3-256, SHA-256, HMAC, AES-256) have no known quantum attack beyond Grover's algorithm, which at most halves their effective security in bits.

---

## Assets Under Protection

The assets we defend are, in order of sensitivity:

- **Tenant SLH-DSA private keys** — sign Merkle batch roots, the post-quantum leg of hybrid QR signatures.
- **Tenant ECDSA private keys** — the classical leg of hybrid QR signatures and the sole signature on proximity attestations and auth-session approvals; ES256 OIDC ID tokens for the platform organization. Compromise of a tenant's signing keys lets an attacker issue artifacts that verify under the tenant's identity.
- **OIDC RSA private keys** — sign RS256 OIDC ID tokens.
- **Tenant MAC secrets** — the MAC pre-filter key. Compromise does not let an attacker produce verifiable QR codes; the asymmetric legs still apply.
- **User session tokens (JWTs)** — HS256-signed, short-lived. Compromise yields impersonation of a single user session until expiry.
- **User WebAuthn credentials** — origin-bound to QRAuth, stored in authenticator hardware. Compromise lets an attacker authenticate as that user.
- **User PQC bridge private keys** — ML-DSA-44 keys stored in browser IndexedDB. Compromise paired with a WebAuthn compromise bypasses the bridged passkey defense.
- **The issuance log** — hash-chained; tamper-evident against parties who can read but not write the database, when cross-checked against a previously saved snapshot. The asset here is integrity, not confidentiality.
- **The PQC-health aggregate data** — per-org metrics about the migration state. Low sensitivity but should not leak cross-tenant.

---

## Attack Scenarios

### A — Harvest Now, Attack Later

**Description.** The adversary records every public QRAuth artifact they can access today — issuance-log data, verification responses, QR images — and archives them. When a Cryptographically Relevant Quantum Computer becomes available in 5–10 years, they use Shor's algorithm to derive tenant private keys from any public key material they captured. They then forge arbitrary QR codes under those keys, potentially years after the recording.

**Preconditions.** The adversary needs continuous access to public QRAuth surfaces and a future CRQC. Both are reasonable assumptions for a nation-state adversary.

**Impact.** If exploitable, the attacker would retroactively forge signatures on any archived public key. They could produce QR codes that claim to be from any captured tenant and pass any signature check that still trusts the classical leg.

**Mitigation.** Every new QR code carries a hybrid signature. A hybrid row verifies only if its ECDSA-P256 signature verifies and the Merkle leaf recomputed from the row's canonical data and stored nonce verifies, through the inclusion proof, against a batch root signed with SLH-DSA-SHA2-128s. Both legs bind the same payload. SLH-DSA is hash-based (FIPS 205); no known quantum algorithm recovers its private keys from signatures or public keys. See `ALGORITHM.md` §4 and §6.

### B — Protocol Downgrade

**Description.** The adversary forces a verifier to accept a token under a weaker algorithm version than the issuer intended. For example, they craft a token that claims `alg_version = 'ecdsa-p256-sha256-v1'` but whose payload would actually be rejected under the hybrid algorithm.

**Preconditions.** The verifier must be willing to accept the weaker version for the tenant in question, and the adversary must have access to the weaker algorithm's forgery surface (classical ECDSA break or an equivalent).

**Impact.** Successful downgrade lets an attacker present a legacy-signed token in a context that would otherwise require the hybrid algorithm, bypassing the PQC defense.

**Mitigation.** The QRAuth verifier classifies `alg_version` into accepted / deprecated / rejected / unknown via `checkAlgVersion()` from `@qrauth/shared`. Rejected and unknown versions fail closed; a deprecated version verifies with a warning in the response. `ecdsa-p256-sha256-v1` is rejected, and the deprecated set is currently empty. Because the canonical form commits to `alg_version` as its first field, a signature cannot be reinterpreted under a different version. The protocol has no "default to weakest" path. See `ALGORITHM.md` §11.

### C — Server or KMS Compromise

**Description.** The adversary gains write access to the API server or its filesystem and attempts to obtain or use tenant signing keys to forge signatures.

**Preconditions.** Full code execution on the API host. This is outside the quantum threat model — it is a classical compromise and the adversary already has what they need without quantum computing.

**Impact.** The adversary can forge signatures for any tenant whose keys it can use. With local signing (`ECDSA_SIGNER=local`, `SLH_DSA_SIGNER=local`, used in development) the keys are loaded in the API process.

**Mitigation.** In production all signing runs on a separate signer host (`ECDSA_SIGNER=http`, `SLH_DSA_SIGNER=http`): the API sends canonical bytes and receives signatures. Tenant keys are generated on the API host, encrypted at rest (AES-256-GCM envelope under `SIGNER_MASTER_KEY`), and provisioned to the signer host. The signer binds to a private network address, is firewalled to the private subnet, and authenticates every request with a bearer token (constant-time comparison, dual-token rotation). It is a small fastify service with no database and no user-facing routes, depending on `fastify`, `lru-cache` and `@noble/post-quantum`. See [SECURITY.md § Key Management Architecture](SECURITY.md#key-management-architecture) and `ALGORITHM.md` §10 and §13.1.

### D — Issuance Log Harvest

**Description.** The adversary scrapes the issuance log over time and attempts to reconstruct tenant signing keys from the captured data. This is a specific instance of Scenario A but worth calling out separately because the issuance log is a high-volume public data source.

**Preconditions.** Continuous scraping of the public issuance-log endpoints.

**Impact.** If the log exposed recoverable signatures or public keys, this would be a direct harvest surface. A long-term CRQC could derive private keys from enough samples.

**Mitigation.** Issuance-log entries consist of hashes: the SHA-256 chain hash and, for hybrid rows, the SHA3-256 Merkle leaf hash, the inclusion-proof hashes and a SHA3-256 reference to the batch root. Batch roots are signed with SLH-DSA-SHA2-128s, whose signatures give no known quantum path to the private key. See `ALGORITHM.md` §8.

### E — WebAuthn Credential Forgery

**Description.** The adversary uses a future CRQC to recover a user's WebAuthn ECDSA-P256 private key from captured assertion public keys, then forges assertions to authenticate as that user.

**Preconditions.** The adversary has recorded at least one WebAuthn assertion from the target user (which exposes the public key in the ceremony) and has a CRQC.

**Impact.** Without mitigation, a successful attack impersonates the user for every QRAuth-backed application that accepts WebAuthn authentication.

**Mitigation.** Passkeys registered with a bridge key carry an additional ML-DSA-44 signature over the WebAuthn challenge, verified alongside the WebAuthn assertion when present. The bridge private key is generated and stored in the browser (IndexedDB); the server stores only the public key. Organizations have a per-organization bridge policy setting, and the PQC health dashboard reports how many passkeys have a bridge key. The long-term fix is post-quantum WebAuthn, which the FIDO Alliance is standardising. See `ALGORITHM.md` §9.

### F — Real-Time Proxy / MitM

**Description.** The adversary stands up a proxy between the user and QRAuth that forwards requests and relays responses in real time. The user sees what looks like a legitimate verification page; the adversary captures the verification outcome or redirects it to their own destination.

**Preconditions.** The adversary can induce the user to visit a phishing domain (not `qrauth.io`) and run a transparent forwarder to the real API.

**Impact.** If undetected, the proxy can harvest the user's trust decision and potentially replay authentication to authorize actions on an attacker-controlled destination.

**Mitigation.** This is a classical attack, not a quantum one. The verification page renders a per-request ephemeral visual proof (approximate location, browser and OS, timestamp, and a keyed fingerprint) and checks in the browser that it is served from a QRAuth hostname. Destination domains similar to another organization's verified domain lower the trust score. WebAuthn passkeys are origin-bound, so an assertion made on a proxy domain is not valid for QRAuth. The risk does not change with CRQC availability.

---

## Mitigations Summary

| Scenario | Mitigation | Residual Risk |
|---|---|---|
| A — Harvest Now, Attack Later | Hybrid QR signatures: ECDSA-P256 plus Merkle inclusion proof against an SLH-DSA-SHA2-128s-signed batch root | Low — no known quantum attack on SLH-DSA-SHA2-128s or SHA3-256 |
| B — Protocol Downgrade | Strict `alg_version` classifier in the QRAuth verifier; legacy version rejected | Low — QR verification is performed by the QRAuth verifier |
| C — Server or KMS Compromise | Separate signer host on a private network (`ECDSA_SIGNER=http`, `SLH_DSA_SIGNER=http`); keys encrypted at rest | Low-medium — the signer host is itself a target but a much smaller attack surface |
| D — Issuance Log Harvest | Log entries are hashes; batch roots signed with SLH-DSA-SHA2-128s | Very low — no known cryptanalytic path against SLH-DSA or SHA3-256 |
| E — WebAuthn Credential Forgery | Optional WebAuthn PQC bridge (ML-DSA-44) | Medium — passkeys without a bridge key carry ECDSA-P256 exposure until FIDO PQC lands |
| F — Real-Time Proxy / MitM | Ephemeral visual proof, hostname check, domain-similarity scoring, WebAuthn origin binding | Medium — classical attack, classical mitigation |

---

## Out of Scope

- **Physical attacks on authenticator hardware.** Compromise of a Secure Enclave, TPM, or Titan chip is a device-level concern and outside the QRAuth threat model.
- **Supply-chain compromise of cryptographic libraries.** QRAuth depends on `@noble/post-quantum` (and its `@noble/hashes` dependency), `@simplewebauthn/server`, `@fastify/jwt`, `jose`, and Node's built-in `crypto`. We monitor security advisories but cannot defend against a malicious publication in any of these packages.
- **Social engineering against platform administrators.** Phishing or coercion targeting QRAuth operators is a human-process concern addressed by the operational security playbook, not by cryptographic architecture.
- **Pre-existing key compromise.** If the adversary already holds a tenant's private key at `t=0` — via an insider, a historical breach, or an operational mistake — no subsequent cryptographic mitigation can recover. The [SECURITY.md § Incident Response](SECURITY.md#incident-response) section describes the response procedure.

---

## Review Schedule

This threat model is reviewed:

- **After every cryptographic primitive change.** When a new algorithm enters `ALG_VERSION_POLICY` or an existing one moves between accepted / deprecated / rejected, the threat model is updated to reflect the change in the adversary capability table and any affected scenarios.
- **Annually, regardless of other triggers.** Once per calendar year, the full document is audited against the latest NIST, FIPS, and CISA guidance on post-quantum cryptography, and against the current state of the quantum computing research field.
- **On any disclosed vulnerability in a dependency.** If `@noble/post-quantum`, `@noble/hashes`, or Node's crypto module ships a CVE, we assess whether the threat model assumptions still hold and update accordingly.
- **On any significant change to the adversary landscape.** For example: publication of a practical quantum attack on SLH-DSA (not expected before 2040 at the earliest), a FIDO Alliance PQC WebAuthn standard, or a regulatory change that affects algorithm choices.

The changelog for this document lives in the file's git history. Review notes are kept in the QRAuth internal security team's runbook.

---

## See Also

- **[`ALGORITHM.md`](ALGORITHM.md)** — cryptographic architecture specification
- **[SECURITY.md](SECURITY.md)** — cryptographic primitives and key management
- **[QRVA Protocol](packages/docs/guide/protocol.md)** — wire format and verification flow
- **[COMPLIANCE.md](COMPLIANCE.md)** — standards alignment and audit pathways
