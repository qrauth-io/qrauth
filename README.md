<p align="center">
  <img src=".github/images/hero.png" alt="QRAuth — Identity verification infrastructure" width="800" />
</p>

<p align="center">
  <strong>Cryptographic authentication infrastructure with QR codes, passkeys, and device trust.</strong>
</p>

<p align="center">
  <a href="https://qrauth.io">Website</a> &middot;
  <a href="https://docs.qrauth.io">Docs</a> &middot;
  <a href="https://docs.qrauth.io/api">API Reference</a> &middot;
  <a href="https://github.com/qrauth-io/qrauth/issues">Issues</a>
</p>

<!-- TODO: Record a demo GIF showing: scan a Living Code → Trust Reveal overlay → verified state → visual fingerprint. Save as docs/demo.gif -->
<p align="center">
  <img src="docs/demo.gif" alt="QRAuth demo — Living Code scan and Trust Reveal" width="700" />
</p>

---

QRAuth is an identity verification platform that unifies QR-based authentication and WebAuthn passkeys under a single identity model. Same-device? Passkeys. Cross-device? QR scan. Both under one SDK, one identity, zero app installs — users scan with their phone camera and verify in the browser. No proprietary app required.

It includes animated cryptographic QR codes (Living Codes) with dual-engine rendering (Canvas 2D + CanvasKit/Skia WASM) that rotate frames every second with HMAC-signed payloads — making screenshots and replay attacks impossible — a Trust Reveal UX with full-screen verification overlays and crystalline visual fingerprints, a device trust registry (NEW/TRUSTED/SUSPICIOUS/REVOKED) with user dashboard, ephemeral delegated access for account-free temporary sessions, a Proximity Verification API that issues signed JWT attestations proving physical presence, drop-in Web Components (`<qrauth-login>`, `<qrauth-2fa>`, `<qrauth-ephemeral>`), a 6-signal fraud detection engine (Phase 3), hybrid ECDSA-P256 + SLH-DSA (FIPS 205) post-quantum QR signing with Merkle batch issuance and commitment-only transparency log, geospatial binding (PostGIS) with Haversine verification, a multi-tenant admin control plane with KYC workflows and audit trails, and developer SDKs for Node.js and Python.

### Three Use Cases

1. **Identity Verification** — Passwordless login via QR scan or passkey. Like WhatsApp Web: scan a QR code on your phone to authenticate a desktop session, or tap a passkey for instant biometric sign-in. No password, no app install.
2. **QR Fraud Protection** — Cryptographic verification that a physical or digital QR code is legitimate, untampered, and issued by the claimed organization. ECDSA-P256 signatures, geospatial binding, and transparency logs.
3. **Physical Access Control** — Scan to unlock physical spaces, devices, and assets. Device trust levels control which devices can authenticate, with automatic anomaly detection.

Think of it as **Auth0 for physical and cross-device authentication**. Auth0 became the authentication layer for web identities. QRAuth adds the physical layer — QR codes, device trust, and passkeys.

<p align="center">
  <img src=".github/images/dashboard-create.png" alt="QRAuth Dashboard — Create signed QR codes" width="700" />
  <br />
  <em>Dashboard: create cryptographically signed QR codes with content types, templates, and live preview</em>
</p>

---

## Table of Contents

- [How QRAuth Compares](#how-qrauth-compares)
- [Problem](#problem)
- [Solution](#solution)
- [Quick Start](#quick-start)
- [SDKs](#sdks)
- [Architecture](#architecture)
- [Animated QR — Living Codes](#animated-qr--living-codes)
- [Ephemeral Delegated Access](#ephemeral-delegated-access)
- [Proximity Verification API](#proximity-verification-api)
- [Web Components](#web-components)
- [Security Model](#security-model)
- [QRVA Open Protocol](#qrva-open-protocol)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [API Reference](#api-reference)
- [Embeddable Verification Widget](#embeddable-verification-widget)
- [Mobile App](#mobile-app)
- [Multi-Tenant Architecture](#multi-tenant-architecture)
- [Webhooks and Events](#webhooks-and-events)
- [Getting Started (Development)](#getting-started-development)
- [Deployment](#deployment)
- [Compliance](#compliance)
- [Status](#status)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## How QRAuth Compares

| Capability | QRAuth | Passkeys Only | Auth0 / Clerk | TOTP / 2FA | Magic Links |
|---|---|---|---|---|---|
| Passwordless | Yes | Yes | Optional | No | Yes |
| Cross-device auth (desktop via phone) | Yes (QR) | Limited | No | No | No |
| WebAuthn/FIDO2 passkeys | Yes (built-in) | Yes | Plugin | No | No |
| Device trust registry | Yes (NEW/TRUSTED/SUSPICIOUS) | No | No | No | No |
| Fraud detection engine | 6-signal + adaptive AI | No | Basic | No | No |
| Geospatial binding | Yes (PostGIS) | No | No | No | No |
| Physical QR verification | Yes | No | No | No | No |
| Proximity attestation (signed JWT) | Yes | No | No | No | No |
| Transparency log | Yes (append-only) | No | No | No | No |
| Challenge-response protocol | Yes (ECDSA-P256) | Yes (WebAuthn) | OAuth2 | HMAC | Token |
| Works without app install | Yes (web-based) | Yes | Yes | No (app needed) | Yes |
| Works on kiosks/smart TVs | Yes | No | No | No | No |

**Key distinction:** QRAuth and passkeys are complementary, not competitive. QRAuth natively supports passkeys — use passkeys for platform-native flows and QR auth for cross-device, kiosk, and physical scenarios. Both are unified under one identity, one dashboard, one SDK.

---

## Problem

QR code fraud is a global epidemic. Scammers print fake QR code stickers and paste them over legitimate ones on parking meters, government signs, and payment terminals. Victims scan the code, land on a convincing phishing site, and enter payment credentials. There is currently no built-in mechanism to verify that a physical QR code was placed by the legitimate authority.

Real-world incidents (2025-2026):

- Austin, TX: 29 compromised parking pay stations discovered
- NYC DOT: Urgent public warning about fraudulent QR codes on parking meters
- Southend-on-Sea, UK: ~100 fake QR stickers removed from parking signage
- Bucharest, Romania: City Hall warning about fake QR codes on parking meters (March 2026)
- Thessaloniki, Greece: Arrest of individual replacing metal parking signs with plastic ones containing fraudulent QR codes (March 2026)
- INTERPOL Operation Red Card 2.0: 651 suspects arrested across 16 nations (February 2026)

The fraud detection market for ticketing alone is valued at USD 1.87 billion (2024), growing at 16.2% CAGR to USD 5.47 billion by 2033. The broader QR code payment and verification market is orders of magnitude larger.

---

## Solution

QRAuth is **infrastructure, not an app**. It provides the invisible verification layer that any QR-generating application can embed via SDK or API.

### The Platform Model

```
┌──────────────────────────────────────────────────────────────────┐
│                     Applications (Your Products)                 │
│                                                                  │
│  Parking App    Payment App    Event Platform    Restaurant POS  │
│      │              │               │                │           │
│      └──────────────┴───────────────┴────────────────┘           │
│                             │                                    │
│                    @qrauth/sdk integration                       │
│                             │                                    │
├─────────────────────────────┼────────────────────────────────────┤
│                      QRAuth Platform                             │
│                                                                  │
│   Signing Engine ─── Verification Edge ─── Geo Registry          │
│   Fraud Detection ── WebAuthn Service ─── Event/Webhook Bus      │
│   Transparency Log ─ Tenant Management ── Analytics Pipeline     │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### How It Works

1. **Developer integrates SDK**: `npm install @qrauth/node` — generates signed QR codes and verifies them via API.
2. **QR code is deployed**: The QR encodes a short verification URL (`https://qrauth.io/v/[token]`) or the app verifies server-side via SDK.
3. **User scans**: Any phone camera opens the verification URL. No app install required. The page shows issuer identity, location match, and an ephemeral visual proof.
4. **Trust escalates**: Returning users create WebAuthn passkeys for cryptographic, unphishable verification.
5. **Events fire**: Every scan, verification, and fraud detection triggers webhooks to the integrating application.

### Key Differentiators

- **Identity platform, not a QR tool**: QR codes and passkeys are authentication methods — the platform handles identity, device trust, and fraud.
- **Device trust registry**: Every login detects and registers the device. Users manage trusted devices with trust levels (NEW/TRUSTED/SUSPICIOUS) and revocation.
- **WebAuthn passkeys**: Native support for passkey registration and authentication. Passkeys and QR auth coexist under one identity.
- **6-signal fraud detection**: Duplicate location, proxy detection, geo-impossibility, scan velocity, bot detection, device clustering — with adaptive per-org scoring.
- **Developer-first**: Node.js and Python SDKs. 10-line integration.
- **Challenge-response protocol**: ECDSA-P256 signatures with content hashing — not static tokens.
- **Open protocol (QRVA)**: Published specification anyone can implement. QRAuth is the reference implementation.
- **No app install required**: Web-based verification works on any phone camera.
- **Multi-tenant control plane**: Dashboard with KYC workflows, audit trails, fraud incident management, session visibility, and analytics.
- **AI security agent**: Daily automated analysis that creates fraud rules going live in <60 seconds.
- **Transparency log**: Public, append-only audit trail of all issued QR codes.

---

## Quick Start

### Install the SDK

```bash
npm install @qrauth/node
```

### Generate a Signed QR Code

```typescript
import { QRAuth } from '@qrauth/node';

const qrauth = new QRAuth({
  tenantId: 'parking-thessaloniki',
  apiKey: process.env.QRAUTH_API_KEY,
});

const qr = await qrauth.create({
  destination: 'https://parking.thessaloniki.gr/pay/zone-b',
  location: { lat: 40.6321, lng: 22.9414, radius: 15 },
  metadata: { zone: 'B', rate: '2.00/hr' },
  expiresIn: '1y',
});

console.log(qr.verificationUrl);
// https://qrauth.io/v/xK9m2pQ7

console.log(qr.qrImageUrl);
// https://api.qrauth.io/qr/xK9m2pQ7.png
```

### Verify a Scanned QR Code (Server-Side)

```typescript
const result = await qrauth.verify('xK9m2pQ7', {
  scannerLat: 40.6325,
  scannerLng: 22.9410,
});

console.log(result);
// {
//   verified: true,
//   issuer: { name: 'Municipality of Thessaloniki', trustLevel: 'government' },
//   locationMatch: { matched: true, distance: 12 },
//   trustScore: 94,
//   destination: 'https://parking.thessaloniki.gr/pay/zone-b'
// }
```

### Embed the Verification Badge (Client-Side)

```html
<script src="https://cdn.qrauth.io/badge.js"></script>
<div data-qrauth-badge="xK9m2pQ7"></div>
```

This renders an inline trust badge inside your application — the user never leaves your app.

---

## SDKs

QRAuth provides first-class SDKs for major platforms. Each SDK handles signing, verification, key caching, and webhook consumption. Node.js and Python are stable today; additional languages are coming soon.

| SDK | Package | Status |
|---|---|---|
| Node.js / TypeScript | `@qrauth/node` | v0.1.2 — Stable |
| Python | `qrauth` (PyPI) | v0.1.2 — Stable |
| Web Components | `@qrauth/web-components` | v0.1.0 — Stable |
| Animated QR | `@qrauth/animated-qr` | v0.1.0 — Stable |
| Go | `github.com/qrauth-io/qrauth-go` | Planned |
| PHP | `qrauth/qrauth-php` (Composer) | Planned |
| Swift (iOS) | `QRAuth` (SPM) | Planned |
| Kotlin (Android) | `io.qrauth:sdk` (Maven) | Planned |
| React Wrapper | `@qrauth/react` | Planned |

### SDK Design Principles

Every SDK follows the same contract:

```
qrauth.create(options)   → Generate a signed QR code
qrauth.verify(token)     → Verify a QR code (server-side)
qrauth.revoke(token)     → Revoke a QR code
qrauth.on(event, fn)     → Listen to webhook events
qrauth.tenant()          → Get tenant configuration
```

### React Component

```tsx
import { QRAuthBadge } from '@qrauth/react';

function PaymentPage({ qrToken }) {
  return (
    <div>
      <h2>Scan to Pay</h2>
      <QRAuthBadge
        token={qrToken}
        theme="dark"
        showLocation={true}
        onVerified={(result) => console.log('Verified:', result)}
        onFraudDetected={(alert) => notifyAdmin(alert)}
      />
    </div>
  );
}
```

---

## Architecture

### System Overview

```
                          ┌─────────────────────────┐
                          │     Developer Portal    │
                          │   docs.qrauth.io        │
                          │   API Explorer + Guides │
                          └────────────┬────────────┘
                                       │
                          ┌────────────▼─────────────┐
                          │      API Gateway         │
                          │      (Node/Fastify)      │
                          │      api.qrauth.io       │
                          └────────────┬─────────────┘
                                       │
          ┌────────────────────────────┼────────────────────────────┐
          │                            │                            │
┌─────────▼──────────┐   ┌─────────────▼────────────┐   ┌─────────────▼──────────┐
│  Tenant Manager    │   │  QR Signing Engine       │   │  Geo Registry          │
│  (Isolation, keys, │   │  (ECDSA-P256, KMS)       │   │  (PostGIS)             │
│   branding, config)│   │                          │   │                        │
└────────────────────┘   └──────────────────────────┘   └────────────────────────┘
                                       │
                          ┌────────────▼─────────────┐
                          │   Verification Edge      │
                          │   (Cloudflare Workers)   │
                          │   qrauth.io/v/[token]    │
                          └────────────┬─────────────┘
                                       │
          ┌────────────────────────────┼────────────────────────────┐
          │                            │                            │
┌─────────▼──────────┐   ┌─────────────▼────────────┐   ┌─────────────▼──────────┐
│  Fraud Detection   │   │  Event / Webhook Bus     │   │  Analytics Pipeline    │
│  (ML pipeline)     │   │  (Redis Streams)         │   │  (ClickHouse)          │
└────────────────────┘   └──────────────────────────┘   └────────────────────────┘
                                       │
                          ┌────────────▼─────────────┐
                          │   Transparency Log       │
                          │   (Append-only, public)  │
                          └──────────────────────────┘
```

### Core Services

**API Gateway (Node.js / Fastify)** — Entry point for all SDK and portal operations. Handles authentication (JWT + API keys), per-tenant rate limiting, request validation, and routing. Exposes RESTful endpoints for tenant management, QR code lifecycle, verification, analytics, and webhook configuration.

**Tenant Manager** — Manages multi-tenant isolation. Each tenant receives: an isolated namespace, dedicated signing keys (KMS-backed), custom branding for verification pages, an independent user pool for WebAuthn passkeys, separate analytics partitions, and configurable webhook endpoints. Supports SSO/SAML for enterprise tenants.

**QR Signing Engine** — Core cryptographic service. Generates ECDSA-P256 key pairs per tenant, signs QR payloads, and manages key rotation. Private keys are stored in AWS KMS or HashiCorp Vault — never in application memory.
```
signature = ECDSA_Sign(tenant_private_key, SHA256(token + destination_url + geo_hash + expiry))
```

**Geo Registry (PostGIS)** — Stores the physical location of every registered QR code. Each registration includes GPS coordinates, accuracy radius, and location metadata. Supports spatial queries for verification and fraud detection.

**Verification Edge (Cloudflare Workers)** — The public-facing verification endpoint deployed globally on edge nodes for sub-50ms cryptographic verification. Handles token lookup, signature verification, geospatial matching, and anti-proxy detection at the edge. Visual proof generation runs on the Fly.io API server (requires native image processing unavailable in V8 isolates).

**Event / Webhook Bus (Redis Streams)** — Every platform event (scan, verification, fraud detection, QR creation, revocation) is published to a stream. Tenants configure webhook endpoints to receive events in real-time. Supports retry with exponential backoff, dead-letter queues, and event replay.

**Fraud Detection Pipeline** — ML pipeline that analyzes scan patterns in real-time. Detects anomalies: new QR codes appearing at locations with existing registrations, sudden changes in scan patterns, scans from known proxy IP ranges, and geographic impossibilities. Per-tenant tuning allows customers to adjust sensitivity thresholds.

**Analytics Pipeline (ClickHouse)** — Columnar time-series database for scan event storage and analysis. Powers tenant dashboards (scan counts, peak times, geographic heatmaps) and feeds the fraud detection model. Handles millions of scan events per day. Data is partitioned per tenant for isolation.

**Transparency Log** — Public, append-only ledger of all QR code issuances. Each entry contains: tenant ID, token, destination URL hash, registration timestamp, and geolocation hash. Third parties can audit the log to verify QR code legitimacy. Inspired by Certificate Transparency (RFC 6962).

---

## Security Model

QRAuth implements a four-tier progressive security model. Each tier builds on the previous, and users automatically escalate through tiers over time. All tiers are active simultaneously — there is no manual configuration required.

### Tier 1 — Cryptographic Signing (Baseline)

Every QR code generated through QRAuth includes a digital signature created using ECDSA-P256 with the tenant's private key (managed in KMS).

**Verification flow:**
```
1. User scans QR → browser opens https://qrauth.io/v/[token]
2. Edge worker looks up token → retrieves: destination_url, tenant_id, signature, geo_data
3. Edge worker fetches tenant's public key (cached at edge)
4. Edge worker verifies: ECDSA_Verify(public_key, signature, payload_hash)
5. If valid → display verified issuer identity and destination URL
6. If invalid → display fraud warning + trigger alert event
```

**Defeats:** QR codes pointing to arbitrary URLs that were never registered on the platform.

### Tier 2 — Ephemeral Server-Generated Visual Proof (Anti-Cloning)

The verification page renders a **server-generated image** (PNG, computed per-request) containing personalized, time-bound information that a cloned page cannot reproduce:

- **User's approximate location** (derived from IP geolocation): "Thessaloniki, Central Macedonia"
- **User's device type** (from User-Agent): "iPhone 15, Safari"
- **Exact timestamp** (to the second): "14:32:07 EEST"
- **Procedural visual fingerprint**: A unique abstract pattern generated from `HMAC(server_secret, token + timestamp + client_ip_hash)`

The image is rendered server-side using Sharp/Canvas. It is a rasterized image (not HTML/CSS), making pixel-perfect reproduction computationally expensive.

**Defeats:** Static page cloning. A cloned page shows stale timestamps, wrong locations, and missing visual fingerprints.

### Tier 3 — Anti-Proxy Detection (Anti-MitM)

Defends against real-time reverse proxying where a scammer forwards requests to the real QRAuth server and relays responses to the victim.

| Signal | Method | Confidence | Availability |
|---|---|---|---|
| TLS Fingerprint (JA3/JA4) | Compare TLS handshake against User-Agent claim | High | Requires Cloudflare Bot Management (Enterprise) |
| Latency Analysis | Measure RTT to edge; proxied requests add 50-200ms | Medium | All tiers |
| Canvas Fingerprint | Hash of canvas render output; differs between devices | High | All tiers |
| JS Environment Integrity | `window.location.origin` check, `performance.getEntries()` validation | Medium | All tiers |
| IP/Geo Consistency | IP geolocation vs. browser Geolocation API comparison | Medium | All tiers |
| Header Analysis | Detect proxy-injected headers (X-Forwarded-For, Via) | Low-Medium | All tiers |

Each signal contributes to a composite trust score (0-100). Scores below threshold trigger a warning banner and a `fraud.proxy_detected` webhook event.

**Defeats:** Real-time page proxying. The proxy's TLS fingerprint, latency profile, and canvas output differ from a genuine browser.

### Tier 4 — WebAuthn Passkeys (Unphishable)

WebAuthn credentials are **origin-bound** at the OS/hardware level. A passkey created for `https://qrauth.io` will ONLY activate on `https://qrauth.io`. A phishing page on any other domain physically cannot trigger the passkey prompt. This is enforced by the authenticator (Secure Enclave, Titan chip, TPM), not by JavaScript.

**Enrollment flow:**
```
1. User verifies a QR code via Tier 1-3 (first visit)
2. Verification page offers: "Create a passkey for instant verification"
3. User taps → biometric prompt (Face ID / fingerprint)
4. Browser generates key pair, private key stored in Secure Enclave
5. Public key sent to QRAuth server, associated with tenant's user pool
6. Future scans trigger passkey automatically
```

**Defeats:** Everything — including sophisticated real-time proxying, social engineering, and domain spoofing.

### Tier 5 — Post-Quantum Cryptographic Layer

QRAuth's signing infrastructure is built on a hash-native architecture. Real-time verification at the edge uses HMAC-SHA3-256 and Merkle inclusion proofs — zero asymmetric operations in the sub-50ms response window. The security of this path reduces to SHA3-256 preimage resistance alone: Grover's algorithm degrades 256-bit to 128-bit effective security, which remains computationally intractable for any conceivable hardware.

Asymmetric signing happens offline, infrequently, to sign Merkle tree roots using SLH-DSA-SHA2-128s (FIPS 205). The transparency log publishes only opaque hash commitments — no key material, no recoverable signatures. An adversary harvesting the public log today gains nothing actionable, even with a future quantum computer.

QR tokens issued after the PQC cutover carry `alg_version = 'hybrid-ecdsa-slhdsa-v1'` — both the classical ECDSA-P256 leg and the post-quantum SLH-DSA leg must verify at scan time. A break of either algorithm leaves the other intact.

**Defeats:** Harvest-now-attack-later adversaries with a future Cryptographically Relevant Quantum Computer.

Full implementation specification: [`ALGORITHM.md`](./ALGORITHM.md). Operator-facing dashboard: [`/dashboard/pqc-health`](./packages/web/src/pages/dashboard/pqc-health.tsx). Threat model: [`THREAT_MODEL.md`](./THREAT_MODEL.md).

### Tier Summary

| Tier | Defeats | Requires | User Friction |
|---|---|---|---|
| 1 - Signed QR | Unregistered fake QRs | Nothing (automatic) | None |
| 2 - Visual Proof | Static page cloning | Nothing (automatic) | None |
| 3 - Anti-Proxy | Real-time MitM proxying | Nothing (automatic) | None |
| 4 - WebAuthn | All known phishing vectors | One-time passkey creation | Biometric tap |
| 5 - Post-Quantum | Quantum key recovery from harvested signatures | Architecture-level (automatic) | None |

---

## Animated QR — Living Codes

Living Codes are animated, cryptographically signed QR codes that rotate frames at a configurable interval (default: 1 second). Each frame encodes a unique HMAC-SHA256 signature, making screenshot-and-forward attacks, screen sharing relays, and replay attacks impossible.

<p align="center">
  <img src=".github/images/living-codes-demo.gif" alt="Living Codes — animated cryptographic QR code demo" width="700" />
  <br />
  <em>Living Code rotating frames every 500ms with HMAC-SHA256 signed payloads</em>
</p>

**Live demo:** [qrauth.io/demo/qranimation](https://qrauth.io/demo/qranimation)

### How It Works

1. Server creates a display session and issues a per-session `frameSecret` (HMAC key derived from the server secret + session ID)
2. Client generates frames every 1 second: `URL?f=FRAME_INDEX&t=TIMESTAMP&h=HMAC_HEX`
3. Scanner reads the current frame — server validates the HMAC, timestamp freshness (5s window), and frame index (replay detection)
4. Stale or replayed frames are rejected server-side

> **Important security distinction:** Scanning or screenshotting an animated frame captures a valid URL that *resolves in the browser* (the page loads). However, the HMAC signature embedded in the URL *expires within seconds server-side*. The server validates three properties: timestamp freshness (<5s), HMAC integrity (recomputed from the frame secret), and frame index monotonicity (each frame is single-use). A forwarded screenshot passes URL resolution but fails cryptographic validation — the QR is always scannable, but only the live frame is cryptographically valid.

### Usage

```typescript
import { AnimatedQRRenderer } from '@qrauth/animated-qr';

const renderer = new AnimatedQRRenderer({
  canvas: document.getElementById('qr') as HTMLCanvasElement,
  size: 300,
  baseUrl: session.verifyUrl,       // from POST /api/v1/animated-qr/session
  frameSecret: session.frameSecret, // per-session HMAC key
  frameInterval: 1000,              // ms between frame rotations (default: 1000)
  theme: 'light',                   // 'light' (recommended) or 'dark'
});

await renderer.start();

// React to trust signals from your fraud engine
renderer.setTrustState({ hueShift: 120, pulseSpeed: 2.5 });

// Stop animation when QR is scanned (keeps last frame visible)
renderer.freeze();

// Resume with a fresh session
renderer.stop();
```

### Trust-Reactive Animation

The QR's visual state reflects its security status in real-time, driven by the fraud detection pipeline:

| Server State | Visual Behavior |
|---|---|
| Clean | Calm, slow pulse. Finder patterns glow green. |
| Elevated scan velocity | Animation accelerates, subtle amber hue shift |
| Fraud flagged | Module jitter, red hue shift, finder patterns pulse fast |
| Revoked | Modules dissolve away — code visually disintegrates |

### Dual Renderer Architecture

Two rendering engines with a shared interface (`IAnimatedQRRenderer`):

| Engine | Size | GPU | Best For |
|---|---|---|---|
| Canvas 2D (default) | ~15 KB gzipped | No | Broad compatibility, kiosks, digital signage |
| CanvasKit (Skia WASM) | ~6 MB lazy-load | WebGL | Premium visual effects, high-end devices |

Both engines implement the full animation pipeline: frame rotation, module transitions, finder pattern glow, pulse rings, color wash, and all trust-reactive effects. The CanvasKit renderer uses hardware-accelerated Skia surfaces with automatic software fallback.

### Trust Reveal UX

When a QR code is scanned and verified, a full-screen overlay fires on the verification page:

**Successful verification:** Shield pop-in (0.6s) → status text → organization name → crystalline visual fingerprint (staggered 0.4–0.8s delays). Color sweep from deep blue to verified green over 3 seconds. The visual fingerprint is a deterministic SVG generated from `SHA256(timestamp + location + device_id + token)` — unique to this exact scan.

**Failed verification (fraud detected):** Red flash → "FRAUDULENT CODE DETECTED" alarm with pulse animation. Escalating red color sweep. Event logged to audit trail with device fingerprint and geolocation.

### Resource Usage

The renderer is designed to be lightweight:

| State | FPS | CPU Impact |
|---|---|---|
| Transitions active (~300ms after frame rotation) | 60 fps | Moderate |
| Idle (between frame rotations) | ~15 fps | Low |
| Off-screen (scrolled away) | 0 fps | None (IntersectionObserver pauses) |
| Tab backgrounded | 0 fps | None (rAF suspended by browser) |

- **Canvas 2D bundle:** ~15 KB gzipped (including QR encoder)
- **CanvasKit bundle:** ~6 MB WASM (lazy-loaded on first use, served from CDN)
- **Frame generation:** < 5ms per frame (HMAC + QR encode + canvas draw)
- **Benchmark harness:** `src/benchmark.ts` measures frame gen, render time, p50/p95/p99, memory allocation
- **For constrained hardware** (kiosks, digital signage): use Canvas 2D with `frameInterval: 2000` or higher

### API Endpoints

- `POST /api/v1/animated-qr/session` — Create a display session (app-authenticated). Returns `{ frameSecret, baseUrl, ttlSeconds }`.
- `POST /api/v1/animated-qr/validate` — Validate a scanned frame (public). Checks HMAC, timestamp, and replay. Returns `{ valid, reason? }`.

### Package

- **npm:** `@qrauth/animated-qr`
- **License:** MIT
- **Dependencies:** `qrcode` (proven QR matrix generation)
- **Browser support:** All modern browsers (Canvas 2D + Web Crypto API)

---

## Ephemeral Delegated Access

Time-limited, scope-constrained sessions requiring no account creation. A developer generates a QR with embedded permissions and TTL, a guest scans it, gets a scoped session, and the session auto-expires. No credentials, no signup, no PII stored.

### Use Cases

- **Hotel room controls:** Guest scans QR at check-in, gets 72h access to room controls
- **Restaurant ordering:** Diner scans table QR, scoped to that table's menu
- **Contractor access:** IT generates a 4-hour session — no account, no offboarding
- **Event attendance:** Scan entrance QR for day-pass access to event app

### Usage

```typescript
// Server-side: create an ephemeral session
const session = await qrauth.createEphemeralSession({
  scopes: ['read:menu', 'write:order'],
  ttl: '30m',
  maxUses: 1,
  deviceBinding: true,
  metadata: { table: 'A12' },
});
// Returns: { sessionId, token, claimUrl, expiresAt }

// Client-side: user scans the QR and claims the session
const claimed = await qrauth.claimEphemeralSession(token, {
  deviceFingerprint: '...',
});
// Returns: { sessionId, status, scopes, metadata, expiresAt }

// Revoke immediately
await qrauth.revokeEphemeralSession(sessionId);
```

### API Endpoints

- `POST /api/v1/ephemeral` — Create session (app-authenticated)
- `POST /api/v1/ephemeral/:token/claim` — Claim session (public, rate-limited)
- `GET /api/v1/ephemeral/:id` — Get session status (app-authenticated)
- `GET /api/v1/ephemeral` — List sessions (app-authenticated)
- `DELETE /api/v1/ephemeral/:id` — Revoke session (app-authenticated)

Available in Node.js SDK (`createEphemeralSession`, `claimEphemeralSession`, `revokeEphemeralSession`, `listEphemeralSessions`) and Python SDK (snake_case equivalents).

---

## Proximity Verification API

Formalizes physical proximity as a signed attestation. When a user scans a QR code, QRAuth issues a `ProximityAttestation` JWT proving a specific device was physically near a specific QR code at a specific time. The attestation is verifiable by third parties without calling the QRAuth API.

### How It Works

QR scanning inherently proves physical proximity — you must see the code to scan it. This is a property passwords and passkeys fundamentally cannot provide. The Proximity API makes this property cryptographically verifiable.

```typescript
// After scan, retrieve the proximity attestation
const attestation = await qrauth.getProximityAttestation(scanToken, {
  clientLat: 40.6325,
  clientLng: 22.9410,
});
// Returns: { jwt, claims, publicKey, keyId }

// Third-party verification (offline, no API call needed)
const result = await qrauth.verifyProximityAttestation(attestation.jwt, publicKey);
// Returns: { valid: true, claims: { sub, loc, proximity, iat, exp } }
```

### ProximityAttestation JWT Claims

```json
{
  "sub": "device_id_hash",
  "iss": "qrauth.io",
  "loc": "sx3b4f",
  "proximity": { "distance": 12.4, "matched": true, "radiusM": 50 },
  "iat": 1714200000,
  "exp": 1714200300
}
```

### Key Properties

- **Binary proximity:** scanned / not scanned (not distance-based guessing)
- **Offline verification:** any third party can verify with the organization's public key
- **Short TTL:** 5-minute attestation window prevents replay
- **ES256 signatures:** ECDSA-P256, same key infrastructure as QR signing

### Use Cases

- **Attendance verification:** Employee scans office QR → signed attestation proves physical presence. Replaces badge-tap systems with zero hardware cost.
- **Location-gated transactions:** Approve high-value transaction only if user is physically at branch. Attestation attached to audit trail.
- **Physical access control:** Scan QR at building entrance → door unlocks. No NFC reader, no badge provisioning.
- **Proof of visit:** Insurance adjuster, field service tech, delivery confirmation — verifiable proof of being at a location.

### API Endpoints

- `POST /api/v1/proximity/:token` — Create proximity attestation (with `clientLat`, `clientLng`)
- `POST /api/v1/proximity/verify` — Verify a ProximityAttestation JWT (offline-capable with public key)

---

## Web Components

Framework-agnostic custom elements using Shadow DOM. Single `<script>` tag + one custom element = working auth. No npm install, no React, no build step.

### `<qrauth-login>`

Drop-in authentication button with full PKCE flow, QR display, status polling, and event dispatching.

```html
<script src="https://cdn.qrauth.io/v1/components.js"></script>
<qrauth-login
  tenant="your-client-id"
  theme="dark"
  scopes="identity email"
  on-auth="handleLogin">
</qrauth-login>
```

**Features:**
- Two display modes: `display="button"` (opens modal) or `display="inline"`
- PKCE flow: no client secret needed in the browser
- Events: `qrauth:authenticated`, `qrauth:expired`, `qrauth:error`, `qrauth:scanned`
- CSS custom properties for theming (`--qrauth-primary`, `--qrauth-bg`, etc.)
- Dark theme via `theme="dark"` attribute

### `<qrauth-2fa>`

Drop-in second-factor authentication. Augments an existing login flow — users keep their password/passkey, add QR as a second factor. The Trojan horse: enter as 2FA, expand to primary auth.

```html
<qrauth-2fa
  tenant="your-client-id"
  session-token="existing-session-token"
  theme="dark">
</qrauth-2fa>
```

**Features:**
- Step indicator ("Step 2 of 2 — Verify identity")
- Compact 160x160 QR display with countdown timer
- Events: `qrauth:verified`, `qrauth:denied`, `qrauth:expired`, `qrauth:error`
- PKCE code challenge/verifier flow (S256)
- Polling with exponential backoff (2–5s intervals)
- `auto-start` attribute for immediate session creation

### `<qrauth-ephemeral>`

Ephemeral access QR with TTL countdown and claim status tracking. No account creation required for the end user.

```html
<qrauth-ephemeral
  tenant="your-client-id"
  scopes="read:menu write:order"
  ttl="30m"
  max-uses="1"
  device-binding>
</qrauth-ephemeral>
```

**Features:**
- TTL countdown with live timer (supports seconds, minutes, hours, days)
- Multi-use session support with `useCount`/`maxUses` badge
- Two display modes: `display="button"` (modal) or `display="inline"`
- Events: `qrauth:claimed`, `qrauth:expired`, `qrauth:revoked`, `qrauth:error`
- Auto-close modal on claim (2.2s delay)

### Bundle & Distribution

- **Package:** `@qrauth/web-components` (~23 KB gzipped)
- **CDN:** `https://cdn.qrauth.io/v1/components.js` (IIFE) or `components.esm.js` (ESM)
- **npm:** `npm install @qrauth/web-components`
- **Components:** `<qrauth-login>`, `<qrauth-2fa>`, `<qrauth-ephemeral>`
- **Animated QR:** `@qrauth/animated-qr` (MIT, separate package)

---

## QRVA Open Protocol

QRAuth is built on the **QRVA (QR Verification and Authentication)** open protocol specification. The protocol defines the standard for signing, verifying, and authenticating physical QR codes.

### Why Open?

Auth0 succeeded because it built on open standards (OAuth 2.0, OIDC). QRAuth follows the same playbook. An open protocol:

- Accelerates ecosystem adoption — competitors building compatible implementations expand the market
- Builds institutional trust — governments and enterprises prefer open standards over proprietary lock-in
- Enables standardization — an IETF Internet-Draft positions QRVA for future RFC adoption (note: standardization takes 2-5 years from initial draft)
- QRAuth wins as the **reference implementation** with the best DX, trust registry, and network effects

### Protocol Specification

The QRVA protocol defines:

**1. QR Payload Format**
```
https://[verifier-domain]/v/[token]
```
Where `token` is a URL-safe base64-encoded structure containing: issuer identifier, payload hash, signature, and optional metadata.

**2. Signing Algorithm**
- ECDSA with P-256 curve (FIPS 186-4)
- SHA-256 hash of canonical payload
- 64-byte compact signature format

**3. Verification Flow**
- Token resolution → Signature verification → Geospatial check → Trust score computation
- Each step is independently cacheable at the edge

**4. Geospatial Binding**
- WGS84 coordinates with accuracy radius
- Haversine distance computation for scan-time matching

**5. Transparency Log**
- Append-only Merkle tree structure
- Inclusion proofs for any issued token
- Compatible with Certificate Transparency (RFC 6962) tooling

**6. Event Schema**
- Standardized event types: `qr.created`, `qr.scanned`, `qr.verified`, `qr.failed`, `fraud.detected`, `fraud.proxy_detected`, `passkey.enrolled`, `passkey.verified`
- JSON event format with tenant, token, timestamp, and context

The full specification is published at `docs.qrauth.io/protocol` and as a standalone document in `docs/PROTOCOL.md`.

### Reference Implementation

This repository IS the reference implementation. Third parties can build compatible verifiers and signers using the protocol spec. A compliance test suite is provided at `packages/protocol-tests/` to validate compatibility.

---

## Tech Stack

### Backend

| Component | Technology | Rationale |
|---|---|---|
| API Gateway | Node.js 22 + Fastify | High throughput, low overhead, TypeScript-native |
| Verification Edge | Cloudflare Workers | Sub-50ms cryptographic verification, edge-cached keys |
| Database (relational) | PostgreSQL 16 + PostGIS | Geospatial queries, ACID, tenant isolation |
| Database (analytics) | ClickHouse | Columnar storage for billions of scan events |
| Post-Quantum Signing | SLH-DSA-SHA2-128s (FIPS 205) via `@noble/post-quantum` | Hash-based; security assumption reduces to SHA3-256 preimage resistance only |
| Hash Functions | SHA3-256 (Keccak, FIPS 202) | All new cryptographic operations; replaces SHA-256 |
| Signer Service | `packages/signer-service` (Local / HTTP backend) | Air-gapped signing; `SLH_DSA_SIGNER` env var selects backend; private keys never live on the API host in production |
| Key Management | Signer service + filesystem (local) / HTTP backend (prod); AWS KMS / HashiCorp Vault adapters on the roadmap | Bearer-authenticated private-network delegation; see `SECURITY.md` |
| Cache | Redis (Upstash for edge) | Token lookup, rate limiting, session state |
| Event Bus | Redis Streams | Webhook dispatch, event sourcing |
| Image Generation | Sharp (libvips) | Server-side visual proof rendering (Fly.io API only — not compatible with Cloudflare Workers) |
| Queue | BullMQ (Redis-backed) | Async fraud detection, alert delivery, batch signer, reconciler |
| ML Pipeline | Python + scikit-learn → ONNX | Anomaly detection, exportable to edge |

### SDKs and Frontend

| Component | Technology | Rationale |
|---|---|---|
| SDKs | TypeScript, Python (stable); Go, PHP, Swift, Kotlin (planned) | Native experience per ecosystem |
| Embeddable Widget | Vanilla JS (badge.js) | Zero dependencies, <5KB gzipped |
| React Component | @qrauth/react | First-class React integration |
| Tenant Portal | React + TypeScript + Vite | SPA with real-time dashboard |
| Verification Page | Vanilla HTML/JS (edge-rendered) | Zero deps, fast TTFB |
| Developer Docs | Mintlify or Nextra | Interactive API explorer |

### Mobile App

| Component | Technology | Rationale |
|---|---|---|
| Framework | React Native + Expo | Cross-platform, shared logic with web |
| QR Scanner | vision-camera + ML Kit | Native camera, fast decode |
| WebAuthn | react-native-passkeys | Native passkey integration |
| NFC | react-native-nfc-manager | Future tamper-evident tag support |
| Push | Expo Notifications + FCM/APNs | Fraud alerts |
| Offline DB | WatermelonDB | Cached issuer keys, offline verify |

### Infrastructure

| Component | Technology | Rationale |
|---|---|---|
| Containers | Docker + Fly.io / Railway | Simple deploy, global distribution |
| CI/CD | GitHub Actions | Automated test, stage, prod pipeline |
| Monitoring | Grafana + Prometheus | Service health, latency tracking |
| Errors | Sentry | Runtime error capture, all services |
| DNS / CDN | Cloudflare | Edge cache, DDoS, Workers runtime |
| Secrets | Doppler or 1Password Connect | Centralized secret management |

---

## Project Structure

```
qrauth/
├── README.md
├── docker-compose.yml
├── .env.example
├── turbo.json                        # Turborepo monorepo config
│
├── packages/
│   ├── api/                          # Fastify API Gateway
│   │   ├── src/
│   │   │   ├── server.ts
│   │   │   ├── routes/
│   │   │   │   ├── tenants.ts        # Tenant CRUD, onboarding, config
│   │   │   │   ├── qrcodes.ts        # QR generation + signing
│   │   │   │   ├── verify.ts         # Verification (non-edge fallback)
│   │   │   │   ├── webhooks.ts       # Webhook endpoint management
│   │   │   │   └── analytics.ts      # Dashboard data endpoints
│   │   │   ├── services/
│   │   │   │   ├── signing.ts        # ECDSA key management + signing
│   │   │   │   ├── tenants.ts        # Tenant isolation logic
│   │   │   │   ├── geo.ts            # PostGIS geospatial queries
│   │   │   │   ├── fraud.ts          # Fraud detection orchestration
│   │   │   │   ├── events.ts         # Event bus (Redis Streams)
│   │   │   │   └── alerts.ts         # Notification dispatch
│   │   │   ├── middleware/
│   │   │   │   ├── auth.ts           # JWT + API key + tenant scoping
│   │   │   │   ├── rateLimit.ts      # Per-tenant rate limiting
│   │   │   │   └── validate.ts       # Zod schema validation
│   │   │   └── lib/
│   │   │       ├── crypto.ts         # ECDSA utilities, HMAC helpers
│   │   │       ├── db.ts             # PostgreSQL connection pool
│   │   │       └── cache.ts          # Redis client
│   │   ├── prisma/
│   │   │   └── schema.prisma
│   │   ├── tests/
│   │   └── package.json
│   │
│   ├── edge/                         # Cloudflare Workers verification
│   │   ├── src/
│   │   │   ├── worker.ts             # Edge verification handler
│   │   │   ├── verify.ts             # Signature verification logic
│   │   │   ├── antiProxy.ts          # Latency + canvas checks (JA3/JA4 requires Enterprise)
│   │   │   ├── visualProof.ts        # Visual proof request (delegates to API for image gen)
│   │   │   ├── webauthn.ts           # Passkey challenge/response
│   │   │   └── geo.ts               # Location matching at edge
│   │   ├── wrangler.toml
│   │   └── package.json
│   │
│   ├── animated-qr/                  # @qrauth/animated-qr (Living Codes renderer)
│   │   ├── src/
│   │   │   ├── index.ts              # Public API exports
│   │   │   ├── qr-encoder.ts         # QR matrix generation (wraps qrcode lib)
│   │   │   ├── frame-signer.ts       # HMAC frame signing (Web Crypto API)
│   │   │   ├── renderer.ts           # Canvas 2D animated renderer
│   │   │   ├── renderer-canvaskit.ts  # CanvasKit/Skia WASM renderer (WebGL)
│   │   │   ├── renderer-interface.ts  # Shared IAnimatedQRRenderer interface
│   │   │   ├── benchmark.ts          # Performance harness (Canvas2D vs CanvasKit)
│   │   │   └── types.ts              # Type definitions
│   │   └── package.json
│   │
│   ├── web-components/               # @qrauth/web-components (Shadow DOM)
│   │   ├── src/
│   │   │   ├── base.ts               # QRAuthElement base class
│   │   │   ├── login.ts              # <qrauth-login> custom element
│   │   │   ├── twofa.ts              # <qrauth-2fa> second factor component
│   │   │   ├── ephemeral.ts          # <qrauth-ephemeral> temporary access component
│   │   │   └── index.ts
│   │   ├── scripts/
│   │   │   └── bundle.js             # esbuild bundler (IIFE + ESM output)
│   │   └── package.json
│   │
│   ├── sdk-node/                     # @qrauth/node SDK
│   │   ├── src/
│   │   │   ├── index.ts              # Main QRAuth client class
│   │   │   ├── signing.ts            # QR creation methods
│   │   │   ├── verification.ts       # Verify methods
│   │   │   ├── webhooks.ts           # Webhook event consumer
│   │   │   └── types.ts              # Public TypeScript interfaces
│   │   ├── tests/
│   │   └── package.json
│   │
│   ├── sdk-python/                   # qrauth Python SDK
│   │   ├── qrauth/
│   │   │   ├── __init__.py
│   │   │   ├── client.py
│   │   │   ├── signing.py
│   │   │   ├── verification.py
│   │   │   └── webhooks.py
│   │   ├── tests/
│   │   └── pyproject.toml
│   │
│   ├── sdk-go/                       # qrauth-go SDK
│   │   ├── qrauth.go
│   │   ├── signing.go
│   │   ├── verification.go
│   │   ├── webhooks.go
│   │   └── go.mod
│   │
│   ├── sdk-php/                      # qrauth-php SDK
│   │   ├── src/
│   │   │   ├── QRAuth.php
│   │   │   ├── Signing.php
│   │   │   ├── Verification.php
│   │   │   └── Webhooks.php
│   │   ├── tests/
│   │   └── composer.json
│   │
│   ├── badge/                        # @qrauth/badge.js (embeddable widget)
│   │   ├── src/
│   │   │   ├── badge.ts              # Embeddable verification badge
│   │   │   ├── styles.ts             # Inline styles (no CSS deps)
│   │   │   └── api.ts                # Verification API client
│   │   └── package.json
│   │
│   ├── react/                        # @qrauth/react component
│   │   ├── src/
│   │   │   ├── QRAuthBadge.tsx       # React verification badge
│   │   │   ├── QRAuthProvider.tsx     # Context provider
│   │   │   └── hooks.ts              # useQRAuth, useVerification
│   │   └── package.json
│   │
│   ├── portal/                       # Tenant dashboard (React SPA)
│   │   ├── src/
│   │   │   ├── pages/
│   │   │   │   ├── Dashboard.tsx     # Overview: scans, fraud, health
│   │   │   │   ├── QRCodes.tsx       # QR management + generation
│   │   │   │   ├── Locations.tsx     # Geospatial deployment map
│   │   │   │   ├── Analytics.tsx     # Scan patterns, heatmaps
│   │   │   │   ├── Fraud.tsx         # Fraud incident log
│   │   │   │   ├── Webhooks.tsx      # Webhook config + event log
│   │   │   │   ├── APIKeys.tsx       # API key management
│   │   │   │   ├── Branding.tsx      # Custom verification page styling
│   │   │   │   ├── Team.tsx          # Team members, roles, SSO
│   │   │   │   └── Settings.tsx      # Tenant config, billing
│   │   │   ├── components/
│   │   │   ├── hooks/
│   │   │   └── lib/
│   │   ├── tests/
│   │   └── package.json
│   │
│   ├── mobile/                       # React Native mobile app
│   │   ├── app/
│   │   │   ├── (tabs)/
│   │   │   │   ├── scan.tsx          # QR scanner + instant verification
│   │   │   │   ├── history.tsx       # Scan history + fraud reports
│   │   │   │   ├── alerts.tsx        # Push notification center
│   │   │   │   └── settings.tsx      # Passkey management, preferences
│   │   │   ├── verify/
│   │   │   │   └── [token].tsx       # Deep-link verification screen
│   │   │   └── _layout.tsx
│   │   ├── lib/
│   │   │   ├── crypto.ts            # Shared ECDSA verification
│   │   │   ├── offlineCache.ts      # Cached keys (WatermelonDB)
│   │   │   ├── passkeys.ts          # WebAuthn integration
│   │   │   └── nfc.ts              # NFC tag reading (future)
│   │   └── package.json
│   │
│   ├── protocol-tests/              # QRVA compliance test suite
│   │   ├── src/
│   │   │   ├── signing.test.ts      # Signing compliance tests
│   │   │   ├── verification.test.ts # Verification compliance tests
│   │   │   ├── geo.test.ts          # Geospatial compliance tests
│   │   │   └── events.test.ts       # Event schema compliance tests
│   │   └── package.json
│   │
│   └── shared/                      # Shared types, constants, utilities
│       ├── src/
│       │   ├── types.ts             # TypeScript interfaces
│       │   ├── constants.ts         # Protocol constants
│       │   ├── crypto.ts            # Shared crypto utilities
│       │   ├── events.ts            # Event type definitions
│       │   └── validation.ts        # Shared Zod schemas
│       └── package.json
│
├── infra/
│   ├── docker/
│   │   ├── Dockerfile.api
│   │   ├── Dockerfile.portal
│   │   └── Dockerfile.mobile
│   ├── terraform/
│   │   ├── main.tf
│   │   ├── database.tf
│   │   ├── kms.tf
│   │   └── monitoring.tf
│   └── ansible/
│       └── playbooks/
│
├── docs/
│   ├── PROTOCOL.md                  # QRVA protocol specification
│   ├── SECURITY.md                  # Security model deep-dive
│   ├── API.md                       # Full API documentation
│   ├── SDK_GUIDE.md                 # SDK integration guide
│   ├── WEBHOOKS.md                  # Webhook event reference
│   ├── MULTI_TENANT.md              # Tenant architecture guide
│   ├── DEPLOYMENT.md                # Self-hosted deployment guide
│   ├── THREAT_MODEL.md              # Threat modeling document
│   └── COMPLIANCE.md                # SOC2, GDPR, ISO compliance
│
└── scripts/
    ├── setup.sh                     # Local development setup
    ├── seed.sh                      # Seed database with test data
    ├── generate-keys.sh             # Generate test ECDSA key pairs
    └── publish-sdks.sh              # Publish all SDKs to registries
```

---

## API Reference

### Authentication

All API endpoints are tenant-scoped. Authenticate via Bearer token (JWT) or API key.

```
Authorization: Bearer <jwt_token>
# or
X-API-Key: <api_key>
```

All requests are scoped to the authenticated tenant. Cross-tenant access is not possible.

### Endpoints

#### Tenants

```
POST   /api/v1/tenants                     # Create new tenant
GET    /api/v1/tenants/:id                  # Get tenant config
PATCH  /api/v1/tenants/:id                  # Update tenant settings
POST   /api/v1/tenants/:id/verify           # Submit KYC verification
GET    /api/v1/tenants/:id/keys             # List signing keys
POST   /api/v1/tenants/:id/keys/rotate      # Rotate signing key
PATCH  /api/v1/tenants/:id/branding         # Update verification page branding
```

#### QR Codes

```
POST   /api/v1/qrcodes                     # Generate signed QR code
GET    /api/v1/qrcodes                     # List tenant's QR codes (paginated)
GET    /api/v1/qrcodes/:token              # Get QR code details
PATCH  /api/v1/qrcodes/:token              # Update destination URL
DELETE /api/v1/qrcodes/:token              # Revoke QR code
POST   /api/v1/qrcodes/bulk               # Bulk generate (up to 1000)
```

#### Verification (Public — No Auth Required)

```
GET    /v/[token]                          # Web verification page (edge)
GET    /api/v1/verify/:token               # API verification (for SDKs)
POST   /api/v1/verify/:token/webauthn      # WebAuthn challenge/response
```

#### Webhooks

```
POST   /api/v1/webhooks                    # Register webhook endpoint
GET    /api/v1/webhooks                    # List configured webhooks
PATCH  /api/v1/webhooks/:id               # Update webhook
DELETE /api/v1/webhooks/:id               # Remove webhook
GET    /api/v1/webhooks/:id/logs          # View delivery logs
POST   /api/v1/webhooks/:id/test          # Send test event
POST   /api/v1/events/replay              # Replay events (time range)
```

#### Analytics

```
GET    /api/v1/analytics/scans            # Scan event history
GET    /api/v1/analytics/heatmap          # Geographic scan heatmap
GET    /api/v1/analytics/fraud            # Fraud incident log
GET    /api/v1/analytics/summary          # Dashboard summary stats
GET    /api/v1/analytics/export           # CSV/JSON export
```

#### Proximity Attestation

```
POST   /api/v1/proximity/:token               # Create proximity attestation (with clientLat, clientLng)
POST   /api/v1/proximity/verify               # Verify ProximityAttestation JWT (offline-capable)
```

#### Transparency Log (Public — No Auth Required)

```
GET    /api/v1/transparency/log           # Query transparency log
GET    /api/v1/transparency/proof/:token  # Get inclusion proof for token
```

### Example: Generate a Signed QR Code

```bash
curl -X POST https://api.qrauth.io/api/v1/qrcodes \
  -H "X-API-Key: qra_live_sk_..." \
  -H "Content-Type: application/json" \
  -d '{
    "destination_url": "https://parking.thessaloniki.gr/pay/zone-b",
    "label": "Parking Zone B - Tsimiski Street",
    "location": {
      "lat": 40.6321,
      "lng": 22.9414,
      "radius_m": 15
    },
    "metadata": {
      "zone": "B",
      "rate": "2.00/hr"
    },
    "expires_at": "2027-01-01T00:00:00Z"
  }'
```

**Response:**

```json
{
  "token": "xK9m2pQ7",
  "verification_url": "https://qrauth.io/v/xK9m2pQ7",
  "qr_image_url": "https://api.qrauth.io/qr/xK9m2pQ7.png",
  "signature": "MEUCIQD...base64...==",
  "tenant_id": "ten_parking_thess",
  "created_at": "2026-04-01T12:00:00Z",
  "expires_at": "2027-01-01T00:00:00Z",
  "transparency_log_index": 48291
}
```

### Example: Verify (API)

```bash
curl https://api.qrauth.io/api/v1/verify/xK9m2pQ7 \
  -H "X-Client-Lat: 40.6325" \
  -H "X-Client-Lng: 22.9410"
```

**Response:**

```json
{
  "verified": true,
  "issuer": {
    "tenant_id": "ten_parking_thess",
    "name": "Municipality of Thessaloniki",
    "verified_since": "2026-03-15T00:00:00Z",
    "trust_level": "government"
  },
  "destination_url": "https://parking.thessaloniki.gr/pay/zone-b",
  "location_match": {
    "matched": true,
    "distance_m": 12,
    "registered_address": "Tsimiski Street, Zone B"
  },
  "security": {
    "signature_valid": true,
    "proxy_detected": false,
    "trust_score": 94,
    "transparency_log_verified": true
  },
  "metadata": {
    "zone": "B",
    "rate": "2.00/hr"
  },
  "scanned_at": "2026-04-01T14:32:07Z"
}
```

---

## Embeddable Verification Widget

The verification widget is QRAuth's equivalent of Auth0's Lock. It's a drop-in component that renders a verification badge inside the partner's application. The user never leaves the partner's app — trust is established inline.

### JavaScript (Vanilla)

```html
<!-- Minimal: just the badge -->
<script src="https://cdn.qrauth.io/badge.js"></script>
<div data-qrauth-badge="xK9m2pQ7"></div>

<!-- Full configuration -->
<script src="https://cdn.qrauth.io/badge.js"></script>
<div
  data-qrauth-badge="xK9m2pQ7"
  data-theme="dark"
  data-show-location="true"
  data-show-issuer="true"
  data-locale="el"
></div>
```

### Programmatic API

```javascript
const badge = QRAuth.badge('xK9m2pQ7', {
  container: document.getElementById('verify-container'),
  theme: 'dark',
  locale: 'el',
  onVerified: (result) => {
    console.log('Verified:', result.issuer.name);
    window.location.href = result.destination_url;
  },
  onFailed: (error) => {
    showAlert('This QR code could not be verified.');
  },
  onFraudDetected: (alert) => {
    reportToAdmin(alert);
  },
});
```

### Widget Size

- `badge.js`: <5KB gzipped
- Zero external dependencies
- No CSS files — all styles are inline/shadow DOM
- Works in all modern browsers (Chrome 80+, Safari 14+, Firefox 78+, Edge 80+)

---

## Mobile App

The mobile app is the **highest-security verification channel** — the dedicated verification terminal for physical access infrastructure and power users. For developers integrating QRAuth into their own applications, the SDKs and APIs are the primary interface.

### Capabilities Beyond Web

- **Native QR scanning** with real-time verification overlay (verify before opening any URL)
- **WebAuthn passkey management** with biometric binding (Face ID, fingerprint)
- **Offline verification** using cached tenant public keys (no internet at scan time)
- **Push notifications** for fraud alerts near the user's location
- **NFC tag reading** for future tamper-evident physical verification
- **Scan history** with fraud reporting

### Offline Verification Flow

```
1. App periodically syncs tenant public keys → stores in WatermelonDB
2. User scans QR code (no internet required)
3. App parses QRAuth token from URL
4. App verifies ECDSA signature against cached public key
5. App checks GPS against cached geospatial data
6. Displays verification result with "offline" indicator
7. When connectivity returns, uploads scan event for analytics
```

### Platform Support

| Platform | Minimum Version | Passkey Support | NFC Support |
|---|---|---|---|
| iOS | 16.0+ | Yes (Keychain) | Yes (Core NFC) |
| Android | 9.0+ (API 28) | Yes (FIDO2) | Yes (NfcAdapter) |

---

## Multi-Tenant Architecture

Every QRAuth customer operates in a fully isolated tenant. This is the foundation that enables enterprise pricing and compliance.

### Tenant Isolation

```
Tenant: parking-thessaloniki
├── Signing Keys (KMS-isolated, auto-rotatable)
├── QR Code Registry (namespace-scoped)
├── Geospatial Data (PostGIS, schema-isolated)
├── WebAuthn User Pool (independent credential store)
├── Webhook Endpoints (tenant-specific)
├── Analytics Partition (ClickHouse, partition key = tenant_id)
├── Branding Config (logo, colors, verification page copy)
├── Rate Limits (per-tier, configurable)
├── API Keys (multiple per tenant, scoped permissions)
└── Team Members (roles: owner, admin, developer, viewer)
```

### Custom Verification Page Branding

Enterprise tenants can customize the verification page appearance:

```json
{
  "branding": {
    "logo_url": "https://thessaloniki.gr/logo.png",
    "primary_color": "#1E3A8A",
    "background_color": "#F8FAFC",
    "display_name": "Thessaloniki Parking",
    "support_url": "https://thessaloniki.gr/support",
    "custom_css": "/* optional CSS overrides */"
  }
}
```

The verification page at `qrauth.io/v/[token]` renders with the tenant's branding while maintaining QRAuth's trust indicators (the QRAuth seal is always visible to establish trust chain).

### SSO / SAML (Enterprise)

Enterprise tenants can configure SSO for their team members:
- SAML 2.0 (Okta, Azure AD, Google Workspace)
- OIDC (any compliant provider)
- SCIM provisioning for automated user lifecycle

---

## Webhooks and Events

Every platform action emits an event. Tenants configure webhook endpoints to receive events in real-time, enabling automated workflows (Slack alerts, analytics pipelines, incident response).

### Event Types

| Event | Description | Payload |
|---|---|---|
| `qr.created` | New QR code generated | token, destination, location, metadata |
| `qr.updated` | QR code destination changed | token, old_destination, new_destination |
| `qr.revoked` | QR code revoked | token, reason |
| `qr.expired` | QR code reached expiry | token |
| `scan.completed` | QR code scanned and verified | token, scanner_location, trust_score |
| `scan.failed` | Verification failed | token, reason, scanner_location |
| `fraud.detected` | Anomaly detected | token, alert_type, confidence, details |
| `fraud.proxy_detected` | Proxy/MitM detected | token, ja3_hash, latency_ms |
| `passkey.enrolled` | User created a passkey | user_id, device_type |
| `passkey.verified` | Passkey verification succeeded | user_id, token |

### Webhook Delivery

- **Format**: JSON POST to configured HTTPS endpoint
- **Signing**: Every webhook is signed with `HMAC-SHA256(webhook_secret, payload)` in the `X-QRAuth-Signature` header
- **Retry**: Exponential backoff (1s, 5s, 30s, 5m, 30m, 2h) on failure
- **Dead Letter**: Failed events after all retries are stored for 30 days (replayable)
- **Filtering**: Subscribe to specific event types per endpoint

### Example Webhook Payload

```json
{
  "id": "evt_a1b2c3d4",
  "type": "fraud.detected",
  "tenant_id": "ten_parking_thess",
  "created_at": "2026-04-01T14:32:07Z",
  "data": {
    "token": "xK9m2pQ7",
    "alert_type": "duplicate_location",
    "confidence": 0.92,
    "details": {
      "registered_destination": "https://parking.thessaloniki.gr/pay/zone-b",
      "scanned_destination": "https://parkng-thessaloniki.gr/pay",
      "location": { "lat": 40.6321, "lng": 22.9414 },
      "scanner_ip_country": "GR"
    }
  }
}
```

### Verifying Webhook Signatures (Node.js SDK)

```typescript
import { QRAuth } from '@qrauth/node';

const qrauth = new QRAuth({ webhookSecret: process.env.QRAUTH_WEBHOOK_SECRET });

app.post('/webhooks/qrauth', (req, res) => {
  const event = qrauth.webhooks.verify(
    req.body,
    req.headers['x-qrauth-signature']
  );

  switch (event.type) {
    case 'fraud.detected':
      slackAlert(`Fraud detected on ${event.data.token}: ${event.data.alert_type}`);
      break;
    case 'scan.completed':
      analyticsTrack('qr_scan', event.data);
      break;
  }

  res.status(200).send('ok');
});
```

---

## Getting Started (Development)

### Prerequisites

- Node.js 20+
- PostgreSQL 16 with PostGIS extension
- Redis 7+
- Docker (optional, for containerized development)
- Turborepo (`npm install -g turbo`)

### Local Setup

```bash
# Clone
git clone https://github.com/qrauth-io/qrauth.git
cd qrauth

# Install dependencies (monorepo)
npm install

# Copy environment variables
cp .env.example .env

# Generate development ECDSA key pair
./scripts/generate-keys.sh

# Start PostgreSQL + Redis + ClickHouse
docker compose up -d

# Run database migrations
turbo run db:migrate --filter=api

# Seed with test data
turbo run db:seed --filter=api

# Start all services in development mode
turbo run dev
```

This starts:
- **API Gateway**: `http://localhost:3000`
- **Tenant Portal**: `http://localhost:5173`
- **Verification Page**: `http://localhost:3000/v/[token]`
- **Developer Docs**: `http://localhost:3001`

### Environment Variables

```bash
# Core
NODE_ENV=development
PORT=3000

# Database
DATABASE_URL=postgresql://qrauth:qrauth@localhost:5432/qrauth
REDIS_URL=redis://localhost:6379
CLICKHOUSE_URL=http://localhost:8123

# Cryptography
KMS_PROVIDER=local                         # local | aws | vault
ECDSA_PRIVATE_KEY_PATH=./keys/dev.pem      # Local dev only
VISUAL_PROOF_SECRET=<random-64-chars>

# WebAuthn
WEBAUTHN_RP_NAME=QRAuth
WEBAUTHN_RP_ID=localhost
WEBAUTHN_ORIGIN=http://localhost:3000

# Cloudflare (production only)
CF_ACCOUNT_ID=
CF_API_TOKEN=

# Billing
STRIPE_SECRET_KEY=
STRIPE_WEBHOOK_SECRET=

# Alerts
SMTP_HOST=
SMTP_PORT=
SMTP_USER=
SMTP_PASS=
```

---

## Deployment

### Production Architecture

```
                     ┌──────────────┐
                     │  Cloudflare   │
                     │  DNS + CDN    │
                     └──────┬───────┘
                            │
              ┌─────────────┼─────────────┐
              │             │             │
    ┌─────────▼───┐  ┌──────▼──────┐  ┌───▼──────────┐
    │ CF Workers  │  │ Fly.io /    │  │ Cloudflare   │
    │ (verify     │  │ Railway     │  │ Pages        │
    │  edge)      │  │ (API +      │  │ (Portal +    │
    │             │  │  services)  │  │  Docs)       │
    └─────────────┘  └──────┬──────┘  └──────────────┘
                            │
              ┌─────────────┼─────────────┐
              │             │             │
    ┌─────────▼───┐  ┌──────▼──────┐  ┌───▼──────────┐
    │ PostgreSQL  │  │ Redis       │  │ ClickHouse   │
    │ + PostGIS   │  │ (Upstash)   │  │ Cloud        │
    │ (Neon)      │  │             │  │              │
    └─────────────┘  └─────────────┘  └──────────────┘
```

### Infrastructure Cost (MVP)

| Service | Provider | Monthly Cost |
|---|---|---|
| Edge Verification | Cloudflare Workers (free tier) | $0 |
| API + Services | Fly.io (2x shared-cpu) | $10-20 |
| PostgreSQL + PostGIS | Neon (free tier) | $0 |
| Redis | Upstash (free tier) | $0 |
| Analytics | ClickHouse Cloud (dev) | $25 |
| Portal + Docs | Cloudflare Pages (free) | $0 |
| Domain (qrauth.io) | Registrar | ~$30/year |
| **Total MVP** | | **$35-75/month** |

---

## Compliance

QRAuth is a security product. Enterprise buyers in regulated industries will not evaluate without certifications.

### Planned Certifications

| Certification | Target Date | Purpose |
|---|---|---|
| NIST FIPS 205 (SLH-DSA) | Shipped — Q2 2026 | Post-quantum QR signing ([`ALGORITHM.md`](./ALGORITHM.md), [`SECURITY.md`](./SECURITY.md)) |
| NIST FIPS 204 (ML-DSA) | Shipped — Q2 2026 | WebAuthn PQC bridge for bridged passkeys |
| NIST FIPS 202 (SHA-3) | Shipped — Q2 2026 | Default hash function for all new cryptographic operations |
| SOC 2 Type I | Q4 2026 | Baseline security controls attestation |
| SOC 2 Type II | Q2 2027 | Operational effectiveness over time |
| GDPR Compliance | Launch (Q3 2026) | EU data protection (mandatory for EU market) |
| ISO 27001 | Q4 2027 | Information security management system |
| eIDAS 2.0 Compatibility | 2026–2027 | EU regulation in force May 2024; member-state integration window |

### Data Handling

- All scan data is encrypted at rest (AES-256) and in transit (TLS 1.3)
- Tenant data is logically isolated (schema-level in PostgreSQL, partition-level in ClickHouse)
- PII minimization: scanner IP addresses are hashed before storage
- Data residency: EU tenants can specify EU-only data storage (Fly.io + Neon EU regions)
- Retention policies: configurable per tenant (default 90 days for scan events)
- Right to erasure: tenant deletion purges all associated data within 30 days

---

## Status

QRAuth is in active development. The core platform, SDKs, and all major subsystems are shipped and running in production.

**Shipped:** Hybrid ECDSA-P256 + SLH-DSA (FIPS 205) QR signing with Merkle batch architecture, WebAuthn PQC bridge (ML-DSA-44, FIPS 204), commitment-only transparency log, symmetric HMAC-SHA3-256 fast path, air-gapped signer service, PQC health dashboard, cross-language test vectors (Node + Python), ECDSA-P256 classical leg, WebAuthn passkeys, device trust registry, 6-signal fraud detection (Phase 3), Living Codes (animated QR), ephemeral delegated access, proximity attestation, web components, Node.js + Python SDKs, multi-tenant dashboard, background workers.

See the [changelog](https://docs.qrauth.io/changelog) for release history.

---

## Roadmap

<details>
<summary>View full roadmap — Phase 0–2 shipped, Phase 3 in progress</summary>

**Phase 0 — Minimum Credible Launch** (shipped)
- Node.js SDK, OpenAPI spec, React dashboard, API key self-service

**Phase 1 — Developer Experience** (shipped)
- Webhook delivery (HMAC-signed, retry), usage metering + plan enforcement, quickstart guide, onboarding flow

**Phase 2 — Platform Maturity** (shipped)
- QRVA protocol specification, Stripe billing + pricing page, dashboard analytics, Python SDK

**Phase 3 — Scale & Differentiation** (in progress)
- [ ] Edge verification (Cloudflare Workers)
- [ ] Go, PHP, Swift, Kotlin SDKs (on demand)
- [ ] White-label verification pages
- [ ] WebAuthn passkey verification
- [ ] Custom domains

**Post-Quantum Migration Track** (parallel to phases above)
- [x] PQC-0 Foundation — SHA3-256, multi-source entropy, algorithm agility, cross-language test vectors
- [x] PQC-1 Hybrid Signing — Merkle batch architecture, SLH-DSA root signing, WebAuthn PQC bridge, PQC health dashboard
- [ ] PQC-2 Deprecation Campaign — SDK warnings, webhook v2 payloads, ECDSA sunset announcements
- [ ] PQC-3 ECDSA Removal — QRVA v3 protocol, PQC WebAuthn credentials, FIPS 140-3 submission

See [ROADMAP.md](ROADMAP.md) for the detailed task-level breakdown, including the full PQC migration track.

</details>

---

## Contributing

We welcome contributions — whether it's a bug report, feature request, SDK in a new language, or a fix. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions, code standards, and how to submit a PR.

Good first issues are tagged [`good first issue`](https://github.com/qrauth-io/qrauth/labels/good%20first%20issue).

---

## License

This project is licensed under the [BSL 1.1](LICENSE) (Business Source License) — free for non-commercial use, with automatic conversion to Apache 2.0 after 4 years. Commercial use requires a license from QRAuth.

The QRVA protocol specification (`docs/PROTOCOL.md`) is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — freely usable by anyone.

---

## Links

- **Website**: https://qrauth.io
- **Developer Docs**: https://docs.qrauth.io
- **API Reference**: https://docs.qrauth.io/api
- **Protocol Spec**: https://docs.qrauth.io/protocol
- **Status Page**: https://status.qrauth.io
- **GitHub**: https://github.com/qrauth-io/qrauth
- **Support**: https://github.com/qrauth-io/qrauth/issues

---

*Cryptographic verification infrastructure for every QR code in the physical world.*
