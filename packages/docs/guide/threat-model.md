# Threat Model

This page summarises the adversaries QRAuth is designed to defend against, the assets under protection, and the attack scenarios we address. The full threat model is maintained in [THREAT_MODEL.md](https://github.com/qrauth-io/qrauth/blob/main/THREAT_MODEL.md); it is grounded in the specification in [ALGORITHM.md](https://github.com/qrauth-io/qrauth/blob/main/ALGORITHM.md). Where this summary and THREAT_MODEL.md differ, THREAT_MODEL.md is authoritative.

---

## Scope

The threat model covers the QRAuth platform: the API server, the signer service, the SDKs, the verification flow, and the issuance log. It does not cover physical attacks on authenticator hardware, supply-chain compromise of cryptographic libraries, social engineering against platform administrators, or adversaries who already hold a tenant's private keys.

The model assumes the adversary can observe all public QRAuth traffic, can target any number of tokens, and may possess a Cryptographically Relevant Quantum Computer (CRQC) in the future. It does not assume write access to the API server's or the signer service's filesystem.

---

## Quantum-vulnerable and quantum-resistant primitives

ECDSA-P256 and RSA are the Shor-vulnerable primitives. SLH-DSA-SHA2-128s, ML-DSA-44, SHA3-256, HMAC and AES-256 are not known to be broken by a quantum computer (Grover's algorithm reduces the effective security of hash functions and AES-256 to 128 bits). Which QRAuth artifacts use which primitive is listed in [Security § Post-quantum coverage](./security.md#post-quantum-coverage).

---

## Scenarios

| Scenario | Summary of mitigation |
|---|---|
| A — Harvest now, attack later | Every new QR code carries a hybrid signature. A hybrid row verifies only if the ECDSA-P256 signature verifies and the row's Merkle inclusion proof verifies against an SLH-DSA-SHA2-128s-signed batch root. |
| B — Protocol downgrade | The verifier classifies `alg_version` and fails closed on rejected and unknown versions. `ecdsa-p256-sha256-v1` is rejected. |
| C — Server or key compromise | In production all signing runs on a separate signer host reached over a private network with bearer-token authentication. Keys are generated on the API host, encrypted at rest (AES-256-GCM) and provisioned to the signer. See [Security § Key Management Architecture](./security.md#key-management-architecture). |
| D — Issuance log harvest | The issuance log is hash-chained and stores, for hybrid rows, the SHA3-256 Merkle leaf hash and a reference to the SLH-DSA-signed batch root. It is a forensic record, tamper-evident against parties who can read but not write the database when cross-checked against a saved snapshot. |
| E — WebAuthn credential forgery | Passkeys registered with a bridge key carry an additional ML-DSA-44 signature, verified alongside the WebAuthn assertion when present. Passkeys without a bridge key rely on ECDSA-P256. |
| F — Real-time proxy / MitM | The verification page shows per-request ephemeral visual proof, and WebAuthn passkeys are origin-bound. |

The full scenario analysis, residual-risk assessment and review schedule are in [THREAT_MODEL.md](https://github.com/qrauth-io/qrauth/blob/main/THREAT_MODEL.md). An RFC 6962-style issuance log with signed tree heads and external witnesses is planned in [ADR-0001](https://github.com/qrauth-io/qrauth/blob/main/docs/adr/0001-transparency-log.md).

---

## See Also

- **[THREAT_MODEL.md](https://github.com/qrauth-io/qrauth/blob/main/THREAT_MODEL.md)** — full threat model
- **[ALGORITHM.md](https://github.com/qrauth-io/qrauth/blob/main/ALGORITHM.md)** — cryptographic architecture specification
- **[Security](./security.md)** — post-quantum coverage, cryptographic primitives, key management
- **[QRVA Protocol](./protocol.md)** — wire format and verification flow
- **[Compliance](./compliance.md)** — standards alignment and audit pathways
