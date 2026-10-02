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

QRVA addresses T1 and T2 with a signed registry: every QR code is issued by a cryptographically identified tenant against a registered physical location. A code that was not issued by the claimed authority will fail signature verification. A code issued by a fraudster claiming to be a legitimate authority will fail tenant KYC.

T3 is addressed by server-generated ephemeral visual proof: a rasterized PNG rendered per-request containing time-bound, location-derived, and device-derived data that a cloned page cannot reproduce. The image is generated server-side using Sharp. It is not HTML or CSS and is not reproducible from a static clone.

T4 is addressed by heuristic anti-proxy detection. This is the weakest tier and is discussed at length in section 5.

T5 is partially addressed by cross-referencing browser Geolocation API output against IP geolocation. A meaningful discrepancy (browser asserts Times Square, IP resolves to Eastern Europe) contributes negatively to the composite trust score. This is a heuristic, not a cryptographic guarantee.

T6 is addressed by key rotation, tenant-scoped keys managed in KMS, and a transparency log that allows detection of unauthorized issuances. It is not fully addressed. The gap is discussed in section 5.

---

## 3. Why ECDSA-P256 and not the alternatives

The signing algorithm choice received more internal discussion than any other decision. The two serious candidates were ECDSA-P256 and Ed25519. The case for Ed25519 is strong: it is faster, has a simpler implementation surface, eliminates the nonce dependency that makes naive ECDSA implementations dangerous, and has no known patent issues. In a fresh cryptographic system with no compatibility constraints, Ed25519 would be the default choice.

QRVA has compatibility constraints.

**WebAuthn authenticator key material.** Tier 4 of the security model uses WebAuthn passkeys. The FIDO2 specification mandates P256 (COSE algorithm -7) as the required algorithm for Level 1 authenticators. Ed25519 (COSE algorithm -8) is optional and not universally supported in hardware authenticators, particularly older Android FIDO2 implementations and some YubiKey models. Using P256 throughout the stack — for QR signing, transparency log entries, and passkey authentication — means a single key type to audit, a single curve implementation to trust, and no algorithm negotiation surface.

**KMS availability.** QRVA tenant keys are managed in AWS KMS or HashiCorp Vault, never in application memory. AWS KMS supports P256 natively. Ed25519 was added to AWS KMS in late 2023 but is not available in all regions and is absent from several alternative KMS providers used by enterprise tenants. P256 has near-universal KMS support.

**FIPS compliance.** P256 is specified in FIPS 186-4. Ed25519 is not FIPS-approved. For US government and regulated-industry tenants, FIPS compliance is a procurement requirement, not a preference.

**The nonce problem.** Standard ECDSA requires a unique, unpredictable nonce per signature. Nonce reuse leaks the private key. We mitigate this by implementing deterministic ECDSA per RFC 6979, which derives the nonce deterministically from the private key and message hash. This eliminates the nonce management risk while retaining P256.

**Why not P384?** The security level of P256 is 128 bits against classical computers, considered sufficient against all known classical attacks. P384 provides 192 bits — a meaningful margin against quantum adversaries, but quantum computers capable of breaking P256 are not an imminent threat for the use cases QRVA addresses. P384 produces 96-byte compact signatures versus 64 bytes for P256. QR code payload capacity is finite — higher density QRs are harder to scan in degraded conditions (dirt, damage, poor lighting). The 32-byte difference is not negligible at scale.

---

## 4. Why geospatial binding, and what it does not solve

Geospatial binding addresses T2 directly: it is not enough to verify that a QR code was signed by a legitimate tenant. The code must have been registered at the location where it is being scanned.

The registration model: when a tenant generates a QR code, they supply GPS coordinates and an accuracy radius in meters. This tuple is cryptographically bound into the signed payload. At scan time, the verifier requests the scanner's location via the browser Geolocation API and computes the Haversine distance between the scan location and the registered centroid. If the distance exceeds the registered radius, the verification fails or degrades the trust score depending on tenant configuration.

### What geospatial binding solves

A cloned QR code placed five blocks from the original legitimate code will fail verification when scanned at its new location. A fraudster cannot simply print a copy of a legitimate code and redeploy it — the geospatial check will catch displacement.

### What geospatial binding does not solve

**GPS accuracy constraints.** Consumer GPS in open-sky conditions provides approximately ±3–10m accuracy. In urban canyons — precisely where parking meter fraud concentrates — multipath reflections from buildings degrade accuracy to ±20–50m. Indoor environments have no GPS signal at all and fall back to WiFi triangulation (±15–40m) or cell tower triangulation (±100–300m). The practical minimum registration radius that avoids false negatives in urban environments is approximately 15m. This means the geospatial check cannot distinguish between two codes on opposite sides of the same city block.

**The Geolocation API is not authenticated.** The browser's `navigator.geolocation` API reports coordinates but does not attest their authenticity. A user with root access to their device can override reported coordinates. A sophisticated attacker who knows the registered coordinates can claim to be within the radius trivially. This is not a novel observation — it applies to any geolocation-dependent verification system. QRVA treats geolocation as a probabilistic signal, not a cryptographic guarantee. The cross-reference against IP geolocation adds friction but does not close this gap.

**Radius selection is a tenant responsibility.** The protocol does not prescribe a radius. A restaurant QR on a table has a meaningfully different appropriate radius than a billboard QR visible from 50m. Incorrect radius selection — too small generates false negatives that erode user trust; too large degrades the security property — is a systematic misconfiguration risk that is invisible to end users. We have not yet defined guidance or tooling for radius selection. This is an open problem.

---

## 5. Where WebAuthn fits, and what it does not solve

WebAuthn passkeys are origin-bound at the hardware level. A passkey created for `https://qrauth.io` will authenticate only on `https://qrauth.io`. This is not enforced by JavaScript — it is enforced by the authenticator (Secure Enclave on iOS, Titan chip on Pixel, TPM on Windows). A phishing page at any other origin physically cannot activate the passkey prompt, regardless of how convincingly it impersonates the legitimate page.

This makes WebAuthn the only component of QRVA's security model that is cryptographically unphishable. Tier 1 (signing) can be defeated if the key is compromised. Tiers 2 and 3 (anti-cloning and anti-proxy) are heuristic. WebAuthn's origin binding is unconditional.

### What WebAuthn solves in QRVA

For returning users who have enrolled a passkey, WebAuthn provides hardware-attested confirmation that they are on the genuine qrauth.io origin, not a proxy or clone. Combined with Tier 1 signature verification, this creates a two-factor trust chain: the QR code was signed by the legitimate issuer (cryptographic), and the user is on the genuine verification endpoint (hardware-attested).

### What WebAuthn does not solve

**The first scan.** A user scanning a QRVA code for the first time has no passkey. They fall through to Tier 1–3. Tier 4 is only available after opt-in enrollment, which requires a deliberate action by the user at the end of a successful verification. In practice, most users will never enroll a passkey for a parking meter interaction. This is expected behavior — the lower tiers carry the majority of real-world traffic.

**The passkey proves user identity, not code legitimacy.** A passkey enrolled on `qrauth.io` confirms that the user is on the genuine verification page. It does not confirm that the QR code being verified was placed by its claimed issuer. A legitimate QRVA-verified page can still display a fraudulent result if the upstream code registry has been manipulated. Passkey authentication is an endpoint integrity check, not an end-to-end code authenticity check.

**Cross-device enrollment.** A passkey enrolled on an iPhone is stored in iCloud Keychain and syncs to other Apple devices. It does not transfer to Android. A user who switches device platforms must re-enroll. This is a usability constraint that reduces passkey adoption in practice.

---

## 6. Open questions — what we want scrutinized

These are the areas we believe carry the most residual risk. We are publishing them explicitly because we want informed critique at the design stage.

### 6.1 Anti-proxy detection against an adaptive adversary

The current anti-proxy detection model relies on four heuristic signals: TLS fingerprint (JA3/JA4), round-trip latency, canvas fingerprint, and HTTP header analysis.

**JA3/JA4 durability.** JA3 and JA4 fingerprint the TLS ClientHello to identify client software. Tools like `curl-impersonate` can clone the TLS fingerprint of a target browser. A sophisticated adversary running their proxy on a common cloud provider, impersonating a Chrome fingerprint, will produce a JA3 hash indistinguishable from a legitimate Chrome client. We do not yet have a reliable answer for how to detect TLS fingerprint spoofing at the application layer.

**Canvas fingerprint erosion.** Canvas fingerprinting exploits subtle per-device rendering differences in the HTML5 canvas. Firefox's Resist Fingerprinting mode and Brave's farbling mechanism both randomize canvas output per-origin to defeat tracking. As privacy-focused browsers increase market share, canvas fingerprint consistency as a signal will degrade. An adversary who operates their proxy using a privacy browser already evades this signal.

**Latency threshold.** The latency heuristic assumes a minimum RTT overhead from the additional proxy hop. This assumption breaks when both the victim's client and the attacker's proxy have edge-cached access to QRVA's verification infrastructure — for example, when both are terminating through Cloudflare Workers. In this configuration, the proxy-added latency can fall below our current detection threshold of approximately 50ms.

We believe a robust anti-proxy model requires cooperation from the verification endpoint's CDN layer — specifically, mutual TLS authentication that the browser can initiate but a proxy cannot relay without detection. We have not designed this.

### 6.2 Transparency log integrity

The current transparency log is append-only by operational convention. Entries are written on QR code issuance and are publicly queryable. This provides auditability in the same sense that a database with an append flag provides auditability: it works against an honest-but-curious operator but fails against a compromised one.

Certificate Transparency (RFC 6962) solves this with a Merkle tree structure and inclusion proofs that clients can independently verify. A CT log that omits an entry cannot produce a valid inclusion proof for that entry. We referenced RFC 6962 in the QRVA spec but have not implemented Merkle inclusion proofs. The transparency log in the current implementation cannot prove to an independent verifier that a given entry has not been silently omitted.

This is a known gap. The implementation work is straightforward; the deployment model for distributing Signed Tree Heads to verifiers is not yet designed.

### 6.3 Tenant identity bootstrapping

QRVA's security model assumes that the mapping between a tenant identifier and a real-world organization is trustworthy. A municipality operating parking meters is a legitimate tenant. An attacker registering as that municipality is not.

The current spec describes a KYC verification flow but does not define its rigor. The fundamental question is: what evidence is required to register as `Municipality of Thessaloniki` versus an attacker who claims to be? For the protocol to provide meaningful issuer trust in high-stakes deployments (government payments, healthcare facility navigation, regulated financial terminals), the tenant identity verification process needs to be specified with the same rigor as the cryptographic components.

This is partially analogous to the domain validation problem in TLS: DV certificates verify domain control but not organizational identity. EV certificates verify organizational identity through a defined process. QRVA currently only has a DV equivalent.

### 6.4 Key compromise response time

If a tenant's signing key is compromised, every QR code issued under that key appears legitimate until the key is revoked. Revocation propagates to the Cloudflare Workers edge through a cache TTL that is currently set at 5 minutes. During that window, an attacker holding a compromised key can issue and verify fraudulent codes.

For low-value use cases this window is acceptable. For payment terminals and government identity applications, 5 minutes of fraudulent verification capability after a known compromise is not acceptable. Certificate Transparency solved the analogous problem by making issuance publicly auditable in near-real-time — a rogue certificate becomes detectable within seconds. QRVA's transparency log propagation is currently batch-based, not real-time.

We are aware of this and have not yet designed a sub-second revocation propagation mechanism.

### 6.5 The geolocation API trust boundary

As noted in section 4, the browser Geolocation API is not authenticated. We cross-reference it against IP geolocation, but both signals are ultimately attacker-controllable. We are interested in whether any existing mechanism — such as the secure enclave attestation primitives available on modern iOS and Android — could provide authenticated location claims that the application layer could verify.

Specifically: can a QRVA-integrated mobile application request a location claim from the device's secure enclave that is attested by the device manufacturer and not spoofable by user-space software? We believe this is architecturally possible on modern Apple and Google hardware but have not found a documented API surface for it. If you know of one, we want to hear from you.

---

## Conclusion

QRVA is infrastructure that should exist. The threat is real, is growing, and is currently met only by manual sticker inspection. The protocol design borrows from proven primitives — ECDSA signatures, Certificate Transparency's log model, WebAuthn's origin binding — applied to a problem those systems were not designed to address.

The weakest points in the current design are the anti-proxy detection model (heuristic against an adaptive adversary), the transparency log integrity (no Merkle proofs), and the tenant identity bootstrapping (no equivalent of EV validation). These are design-stage problems, which is the right stage to find them.

The reference implementation is at [github.com/qrauth-io/qrauth](https://github.com/qrauth-io/qrauth). The protocol specification is at [`/guide/protocol`](/guide/protocol). If you find a flaw in the signing model, the geospatial scheme, or the anti-proxy heuristics — particularly the latency threshold assumption and the canvas fingerprint erosion problem — open an issue or reach out directly.

We want this attacked before it is deployed at scale.
