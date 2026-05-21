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
    details: Every QR code is dual-signed with ECDSA-P256 and SLH-DSA (FIPS 205). Isolated signer service. Zero private keys on the API server.
    link: /guide/signing-architecture
  - icon: 🔐
    title: Web Components
    details: Drop-in <qrauth-login>, <qrauth-2fa>, and <qrauth-ephemeral> elements. One script tag, no build step.
    link: /guide/web-components
  - icon: ✨
    title: Living Codes
    details: Animated cryptographic QR codes that change every 500ms. Screenshots are useless after one frame.
    link: /guide/living-codes
  - icon: 📍
    title: Proximity Verification
    details: Domain-separated signed JWT attestations proving a device was physically near a QR code. Offline-verifiable via SDK.
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
