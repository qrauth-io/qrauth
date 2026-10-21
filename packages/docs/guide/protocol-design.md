---
title: 'QRVA: Protocol Design'
description: 'Design decisions and open questions for QRVA, a cryptographic verification protocol for physical QR codes.'
---

# QRVA: A protocol for cryptographic verification of physical QR codes
## Design decisions and open questions

*Published by the QRAuth team — April 2026*

---

Physical QR codes have no trust layer. A camera decoding a QR sticker on a parking meter, government sign, or payment terminal has no mechanism to verify that the code was placed by the claimed authority. It reads a URL and opens it. That is the entire security model, and it has been sufficient until recently only because the attack surface was underexploited.

It is no longer underexploited.

NYC's Department of Transportation issued an official consumer alert in June 2025 after fraudulent stickers appeared on ParkNYC meters city-wide. Austin PD confirmed 29 compromised pay stations. In Southend-on-Sea, councils manually removed approximately 100 fake QR stickers from parking signage. These incidents share one property: every existing mitigation failed silently. The codes looked legitimate. The phones decoded them without hesitation. Safe Browsing had nothing to flag because the phishing domains were freshly registered. HTTPS verified the attacker's server correctly.

QRVA is a proposed protocol for fixing this at the infrastructure layer. This post describes the threat model it was designed against, the rationale behind each technical decision, and — critically — what we believe is not yet solved. We are publishing before a formal security audit because the protocol needs scrutiny at the design stage, not after it hardens.

---

## 1. Threat model

We identified six distinct attack classes against physical QR codes. They are ordered by attacker sophistication, not frequency. The first two are overwhelmingly common. The remainder are currently theoretical but become relevant as the lower tiers are defended.

### T1 — Physical sticker overlay

The dominant real-world attack. The attacker prints a QR code sticker pointing to a lookalike domain (`parkng-thessaloniki.gr`, `paybyphone-nyc.com`) and places it over or adjacent to a legitimate code. No technical capability is required beyond a label printer and physical access. The victim scans the overlay, lands on a convincing phishing page, and submits payment credentials.

**Why existing mitigations fail:** Safe Browsing and Apple's equivalent maintain reputation databases of known-malicious domains. A freshly registered domain has no reputation. The typical window between domain registration and victim contact is hours; blocklist propagation takes days. HTTPS is irrelevant — the attacker's server has a valid certificate for their domain. Visual inspection cannot distinguish a printed QR from a genuine one.

### T2 — Legitimate domain, fraudulent QR registration

A more sophisticated variant: the attacker does not use a lookalike domain. Instead, they generate their own signing keys, create a QR code pointing to a legitimate-looking endpoint, and place it physically. Without a registry of legitimate issuers and their associated locations, there is no way to distinguish this from a genuine code.

**Why existing mitigations fail:** Nothing in a standard QR payload identifies the issuer or the authorized deployment location. Any entity can generate a QR code pointing to any URL.

### T3 — Static page cloning

The attacker scrapes the legitimate verification page and hosts an identical copy on their domain. The victim scans a fraudulent code, lands on the cloned page, and is presented with a convincing trust indicator.

**Why existing mitigations fail:** Client-side rendering (React SPAs, static HTML) is trivially cloneable. Visual trust indicators generated client-side can be reproduced.

### T4 — Real-time MitM proxy

Rather than cloning the page, the attacker proxies all requests through their server to the legitimate verification endpoint and relays responses to the victim. This defeats static clone detection — responses are genuinely fresh — but introduces detectable artifacts: an additional TLS hop, measurable latency overhead, and a mismatch between the TLS fingerprint the victim's browser presents and the fingerprint the proxy presents to the origin.

### T5 — Geospatial spoofing

Against a protocol that performs geospatial binding, an attacker who knows the registered coordinates of a legitimate QR code can instruct the victim's browser to report those exact coordinates. The browser's Geolocation API is user-controllable and does not authenticate GPS data.

### T6 — Tenant key compromise

If an attacker compromises a tenant's ECDSA signing key, they can issue arbitrarily many QR codes that verify as legitimate under that tenant's identity. This is the highest-severity attack class and the one most analogous to a compromised TLS certificate.

---

## 2. Protocol response to each attack class

QRVA addresses T1 and T2 with a signed registry: every QR code is issued by a cryptographically identified tenant against a registered physical location. A code that was not issued by the claimed authority will fail signature verification. Each code is tied to its signing tenant, and the tenant's trust level and KYC status are shown to the scanner.

T3 is addressed by server-generated ephemeral proof: the verification page shows per-request data rendered on the server (location resolved from the IP address, device, timestamp, and a proof ID) and an SVG pattern derived from a keyed per-scan hash. A static copy of the page does not carry this per-request data.

For users who have enrolled a passkey, WebAuthn origin binding applies to T4; see section 5.

T5 is not addressed cryptographically. Scan coordinates are reported by the client; section 4 describes what geospatial binding does and does not provide.

T6 is mitigated by 90-day key rotation, tenant keys encrypted at rest (AES-256-GCM) and used on an isolated signer host, a signing-key-created webhook, and a hash-chained issuance log. It is not fully addressed; see section 6.3.

---

## 3. Why ECDSA-P256 and not the alternatives

The signing algorithm choice received more internal discussion than any other decision. The two serious candidates were ECDSA-P256 and Ed25519. The case for Ed25519 is strong: it is faster, has a simpler implementation surface, eliminates the nonce dependency that makes naive ECDSA implementations dangerous, and has no known patent issues. In a fresh cryptographic system with no compatibility constraints, Ed25519 would be the default choice.

QRVA has compatibility constraints.

**WebAuthn authenticator key material.** Tier 4 of the security model uses WebAuthn passkeys. The FIDO2 specification mandates P256 (COSE algorithm -7) as the required algorithm for Level 1 authenticators. Ed25519 (COSE algorithm -8) is optional and not universally supported in hardware authenticators, particularly older Android FIDO2 implementations and some YubiKey models. Using P256 for both QR signing (the classical leg of the hybrid signature) and passkey authentication means a single classical curve to audit and no algorithm negotiation surface.

**KMS availability.** P256 has near-universal support across KMS and HSM products; Ed25519 support is uneven across providers. QRAuth tenant keys are stored as AES-256-GCM envelopes and used on an isolated signer host (see [Signing Architecture](/guide/signing-architecture)); choosing P256 keeps hardware-backed custody available to deployments that need it.

**FIPS compliance.** P256 is specified in FIPS 186-4. Ed25519 is not FIPS-approved. For US government and regulated-industry tenants, FIPS compliance is a procurement requirement, not a preference.

**The nonce problem.** Standard ECDSA requires a unique, unpredictable nonce per signature. Nonce reuse leaks the private key. QRAuth signs with Node's `crypto` module (OpenSSL), which draws ECDSA nonces from its CSPRNG.

**Why not P384?** The security level of P256 is 128 bits against classical computers, considered sufficient against all known classical attacks. P384 provides 192 bits. Neither curve resists a quantum adversary, which is why QRVA v2 adds an SLH-DSA-SHA2-128s leg (see [QRVA Protocol](/guide/protocol)) rather than moving to a larger curve. Signatures are stored server-side (DER-encoded) and never embedded in the QR image, so signature size does not affect scannability.

---

## 4. Why geospatial binding, and what it does not solve

Geospatial binding addresses T2 directly: it is not enough to verify that a QR code was signed by a legitimate tenant. The code must have been registered at the location where it is being scanned.

The registration model: when a tenant generates a QR code, they supply GPS coordinates and an accuracy radius in meters. This tuple is cryptographically bound into the signed payload. At scan time, the verifier requests the scanner's location via the browser Geolocation API and computes the Haversine distance between the scan location and the registered centroid. If the code requires proximity and the distance exceeds the registered radius, or no location is supplied, verification fails. Otherwise the distance is shown as advisory.

### What geospatial binding solves

For a code that requires proximity, a copy placed five blocks from the original fails verification when the scanner's browser reports its actual coordinates.

### What geospatial binding does not solve

**GPS accuracy constraints.** Consumer GPS in open-sky conditions provides approximately ±3–10m accuracy. In urban canyons — precisely where parking meter fraud concentrates — multipath reflections from buildings degrade accuracy to ±20–50m. Indoor environments have no GPS signal at all and fall back to WiFi triangulation (±15–40m) or cell tower triangulation (±100–300m). The practical minimum registration radius that avoids false negatives in urban environments is approximately 15m. This means the geospatial check cannot distinguish between two codes on opposite sides of the same city block.

**The Geolocation API is not authenticated.** The browser's `navigator.geolocation` API reports coordinates but does not attest their authenticity. A user with root access to their device can override reported coordinates. A sophisticated attacker who knows the registered coordinates can claim to be within the radius trivially. This is not a novel observation — it applies to any geolocation-dependent verification system. QRVA treats geolocation as a client-reported signal, not a cryptographic guarantee.

**Radius selection is a tenant responsibility.** The protocol does not prescribe a radius. A restaurant QR on a table has a meaningfully different appropriate radius than a billboard QR visible from 50m. Incorrect radius selection — too small generates false negatives that erode user trust; too large degrades the security property — is a systematic misconfiguration risk that is invisible to end users. We have not yet defined guidance or tooling for radius selection. This is an open problem.

---

## 5. Where WebAuthn fits, and what it does not solve

WebAuthn passkeys are origin-bound at the hardware level. A passkey created for `https://qrauth.io` will authenticate only on `https://qrauth.io`. This is not enforced by JavaScript — it is enforced by the authenticator (Secure Enclave on iOS, Titan chip on Pixel, TPM on Windows). A phishing page at any other origin physically cannot activate the passkey prompt, regardless of how convincingly it impersonates the legitimate page.

This makes WebAuthn the only component of QRVA's security model that is cryptographically unphishable. Tier 1 (signing) can be defeated if the key is compromised. Tier 2 (anti-cloning) is heuristic. WebAuthn's origin binding is unconditional.

### What WebAuthn solves in QRVA

For returning users who have enrolled a passkey, WebAuthn provides hardware-attested confirmation that they are on the genuine qrauth.io origin, not a proxy or clone. Combined with Tier 1 signature verification, this creates a two-factor trust chain: the QR code was signed by the legitimate issuer (cryptographic), and the user is on the genuine verification endpoint (hardware-attested).

### What WebAuthn does not solve

**The first scan.** A user scanning a QRVA code for the first time has no passkey. They fall through to Tier 1–3. Tier 4 is only available after opt-in enrollment, which requires a deliberate action by the user at the end of a successful verification. In practice, most users will never enroll a passkey for a parking meter interaction. This is expected behavior — the lower tiers carry the majority of real-world traffic.

**The passkey proves user identity, not code legitimacy.** A passkey enrolled on `qrauth.io` confirms that the user is on the genuine verification page. It does not confirm that the QR code being verified was placed by its claimed issuer. A legitimate QRVA-verified page can still display a fraudulent result if the upstream code registry has been manipulated. Passkey authentication is an endpoint integrity check, not an end-to-end code authenticity check.

**Cross-device enrollment.** A passkey enrolled on an iPhone is stored in iCloud Keychain and syncs to other Apple devices. It does not transfer to Android. A user who switches device platforms must re-enroll. This is a usability constraint that reduces passkey adoption in practice.

---

## 6. Open questions — what we want scrutinized

These are the areas we believe carry the most residual risk. We are publishing them explicitly because we want informed critique at the design stage.

### 6.1 Issuance log integrity

Every issuance appends an entry to a hash-chained issuance log; each entry stores the previous entry's hash. This is tamper-evident against someone who can read but not write the database, when cross-checked against a previously saved snapshot of the log. It is not tamper-evident against an operator with database write access, and it cannot prove to an independent verifier that an entry has not been omitted.

Certificate Transparency (RFC 6962) solves this with a Merkle tree log, signed tree heads and inclusion proofs that clients can independently verify. An RFC 6962-style log with signed tree heads and external witnesses is planned, specified in [ADR-0001](https://github.com/qrauth-io/qrauth/blob/main/docs/adr/0001-transparency-log.md).

### 6.2 Tenant identity bootstrapping

QRVA's security model assumes that the mapping between a tenant identifier and a real-world organization is trustworthy. A municipality operating parking meters is a legitimate tenant. An attacker registering as that municipality is not.

The current spec describes a KYC verification flow but does not define its rigor. The fundamental question is: what evidence is required to register as `Municipality of Thessaloniki` versus an attacker who claims to be? For the protocol to provide meaningful issuer trust in high-stakes deployments (government payments, healthcare facility navigation, regulated financial terminals), the tenant identity verification process needs to be specified with the same rigor as the cryptographic components.

This is partially analogous to the domain validation problem in TLS: DV certificates verify domain control but not organizational identity. EV certificates verify organizational identity through a defined process. QRVA currently only has a DV equivalent.

### 6.3 Key compromise response time

If a tenant's signing key is compromised, codes signed with that key verify as legitimate under the tenant's identity. Revoking an individual QR code takes effect on the next scan.

Certificate Transparency addressed the analogous problem by making issuance publicly auditable in near-real-time, so a rogue certificate becomes detectable quickly. For QRVA, the RFC 6962-style log planned in [ADR-0001](https://github.com/qrauth-io/qrauth/blob/main/docs/adr/0001-transparency-log.md) is the corresponding mechanism. Today, tenants are notified of new signing keys by a security webhook.

### 6.4 The geolocation API trust boundary

As noted in section 4, the browser Geolocation API is not authenticated, and scan coordinates are reported by the client. We are interested in whether any existing mechanism — such as the secure enclave attestation primitives available on modern iOS and Android — could provide authenticated location claims that the application layer could verify.

Specifically: can a QRVA-integrated mobile application request a location claim from the device's secure enclave that is attested by the device manufacturer and not spoofable by user-space software? We believe this is architecturally possible on modern Apple and Google hardware but have not found a documented API surface for it. If you know of one, we want to hear from you.

---

## Conclusion

QRVA is infrastructure that should exist. The threat is real, is growing, and is currently met only by manual sticker inspection. The protocol design borrows from proven primitives — ECDSA-P256 and SLH-DSA-SHA2-128s signatures, a hash-chained issuance log (an RFC 6962-style log is planned), WebAuthn's origin binding — applied to a problem those systems were not designed to address.

The open points in the current design are the issuance log integrity (no signed tree heads or witnesses yet), key compromise response, and the tenant identity bootstrapping (no equivalent of EV validation). These are design-stage problems, which is the right stage to find them.

The reference implementation is at [github.com/qrauth-io/qrauth](https://github.com/qrauth-io/qrauth). The protocol specification is at [`/guide/protocol`](/guide/protocol). If you find a flaw in the signing model or the geospatial scheme, open an issue or reach out directly.

We want this attacked before it is deployed at scale.
