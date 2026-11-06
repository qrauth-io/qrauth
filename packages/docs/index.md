---
layout: home
hero:
  name: QRAuth
  text: Documentation
  tagline: Cryptographic QR code verification & authentication platform
  actions:
    - theme: brand
      text: Quickstart
      link: /guide/quickstart
    - theme: alt
      text: API Reference
      link: /api/overview
    - theme: alt
      text: View on GitHub
      link: https://github.com/qrauth-io/qrauth
    - theme: alt
      text: Protocol Design
      link: /guide/protocol-design
features:
  - icon: 🔏
    title: Hybrid Post-Quantum Signing
    details: Every QR code is signed with ECDSA-P256, and its Merkle batch root with SLH-DSA-SHA2-128s (FIPS 205). In production, signing runs on a separate signer service.
    link: /guide/signing-architecture
  - icon: 🔐
    title: Web Components
    details: Drop-in <qrauth-login>, <qrauth-2fa>, and <qrauth-ephemeral> elements. One script tag, no build step.
    link: /guide/web-components
  - icon: ✨
    title: Living Codes
    details: Animated QR codes whose frames change on a configurable interval (1000 ms by default), each carrying an HMAC-SHA-256 tag checked by the frame-verify endpoint.
    link: /guide/living-codes
  - icon: 📍
    title: Proximity Verification
    details: Signed attestations that a device reported a location within a QR code's registered radius. The location is client-reported; not proof of physical presence.
    link: /guide/proximity
  - icon: ⏱️
    title: Ephemeral Access
    details: Time-limited, scope-constrained sessions. No account creation. Auto-expires.
    link: /guide/ephemeral
  - icon: 📱
    title: Device Trust
    details: Device registry with trust levels. NEW → TRUSTED → SUSPICIOUS → REVOKED state machine.
    link: /guide/device-trust
  - icon: 🛡️
    title: Trust Reveal
    details: Full-screen animated verification with visual fingerprint. Fraud detection with alarm UX.
    link: /guide/trust-reveal
---
