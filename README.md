# QRAuth — The Authentication Layer for Physical QR Codes

**Cryptographic verification infrastructure for every QR code in the physical world.**

QRAuth is a developer-first platform that makes physical QR codes tamper-proof and verifiable. It provides SDKs, APIs, and an embeddable verification widget that any application can integrate in minutes. Built on an open protocol (QRVA), QRAuth combines digital signatures, geospatial binding, anti-proxy detection, and WebAuthn passkeys to create the trust layer between QR code issuers and scanners.

Think of it as **Auth0, but for physical QR codes**. Auth0 became the authentication layer for digital identities. QRAuth becomes the authentication layer for physical QR codes.

---

## Table of Contents

- [Problem](#problem)
- [Solution](#solution)
- [Quick Start](#quick-start)
- [SDKs](#sdks)
- [Architecture](#architecture)
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
- [Pricing](#pricing)
- [Compliance](#compliance)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

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
│                     Applications (Your Products)                  │
│                                                                  │
│  Parking App    Payment App    Event Platform    Restaurant POS   │
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

- **Developer-first**: SDKs for Node.js, Python, Go, PHP, Swift, Kotlin. 10-line integration.
- **Embeddable widget**: Drop-in verification badge for any web or mobile app.
- **Open protocol (QRVA)**: Published specification anyone can implement. QRAuth is the reference implementation.
- **No app install required**: Web-based verification works on any phone.
- **Multi-tenant**: Each customer gets isolated keys, branding, analytics, and user pools.
- **Ephemeral visual proof**: Server-generated verification image that cannot be cloned.
- **Anti-proxy detection**: TLS fingerprinting, latency analysis, and canvas fingerprinting detect real-time page cloning.
- **WebAuthn passkeys**: Hardware-level, origin-bound authentication that is physically unphishable.
- **Webhook-driven**: Every event is observable and actionable by integrating applications.
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

QRAuth provides first-class SDKs for every major platform. Each SDK handles signing, verification, key caching, and webhook consumption.

| SDK | Package | Status |
|---|---|---|
| Node.js / TypeScript | `@qrauth/node` | Stable |
| Python | `qrauth` (PyPI) | Stable |
| Go | `github.com/qrauth/qrauth-go` | Stable |
| PHP | `qrauth/qrauth-php` (Composer) | Stable |
| Swift (iOS) | `QRAuth` (SPM) | Stable |
| Kotlin (Android) | `io.qrauth:sdk` (Maven) | Stable |
| Embeddable Widget | `@qrauth/badge.js` (CDN) | Stable |
| React Component | `@qrauth/react` | Stable |

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
                          │     Developer Portal     │
                          │   docs.qrauth.io         │
                          │   API Explorer + Guides   │
                          └────────────┬─────────────┘
                                       │
                          ┌────────────▼─────────────┐
                          │      API Gateway          │
                          │      (Node/Fastify)       │
                          │      api.qrauth.io        │
                          └────────────┬─────────────┘
                                       │
          ┌────────────────────────────┼────────────────────────────┐
          │                            │                            │
┌─────────▼─────────┐   ┌─────────────▼──────────┐   ┌─────────────▼──────────┐
│  Tenant Manager    │   │  QR Signing Engine      │   │  Geo Registry          │
│  (Isolation, keys, │   │  (ECDSA-P256, KMS)      │   │  (PostGIS)             │
│   branding, config)│   │                          │   │                        │
└────────────────────┘   └──────────────────────────┘   └────────────────────────┘
                                       │
                          ┌────────────▼─────────────┐
                          │   Verification Edge       │
                          │   (Cloudflare Workers)    │
                          │   qrauth.io/v/[token]     │
                          └────────────┬─────────────┘
                                       │
          ┌────────────────────────────┼────────────────────────────┐
          │                            │                            │
┌─────────▼─────────┐   ┌─────────────▼──────────┐   ┌─────────────▼──────────┐
│  Fraud Detection   │   │  Event / Webhook Bus    │   │  Analytics Pipeline    │
│  (ML pipeline)     │   │  (Redis Streams)        │   │  (ClickHouse)          │
└────────────────────┘   └──────────────────────────┘   └────────────────────────┘
                                       │
                          ┌────────────▼─────────────┐
                          │   Transparency Log        │
                          │   (Append-only, public)   │
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

**Verification Edge (Cloudflare Workers)** — The public-facing verification endpoint deployed globally on edge nodes for sub-50ms response times. Handles the full verification flow: token lookup, signature verification, geospatial matching, anti-proxy detection, ephemeral visual proof generation, and WebAuthn challenge/response.

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

| Signal | Method | Confidence |
|---|---|---|
| TLS Fingerprint (JA3/JA4) | Compare TLS handshake against User-Agent claim | High |
| Latency Analysis | Measure RTT to edge; proxied requests add 50-200ms | Medium |
| Canvas Fingerprint | Hash of canvas render output; differs between devices | High |
| JS Environment Integrity | `window.location.origin` check, `performance.getEntries()` validation | Medium |
| IP/Geo Consistency | IP geolocation vs. browser Geolocation API comparison | Medium |
| Header Analysis | Detect proxy-injected headers (X-Forwarded-For, Via) | Low-Medium |

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

### Tier Summary

| Tier | Defeats | Requires | User Friction |
|---|---|---|---|
| 1 - Signed QR | Unregistered fake QRs | Nothing (automatic) | None |
| 2 - Visual Proof | Static page cloning | Nothing (automatic) | None |
| 3 - Anti-Proxy | Real-time MitM proxying | Nothing (automatic) | None |
| 4 - WebAuthn | All known phishing vectors | One-time passkey creation | Biometric tap |

---

## QRVA Open Protocol

QRAuth is built on the **QRVA (QR Verification and Authentication)** open protocol specification. The protocol defines the standard for signing, verifying, and authenticating physical QR codes.

### Why Open?

Auth0 succeeded because it built on open standards (OAuth 2.0, OIDC). QRAuth follows the same playbook. An open protocol:

- Accelerates ecosystem adoption — competitors building compatible implementations expand the market
- Builds institutional trust — governments and enterprises prefer open standards over proprietary lock-in
- Enables standardization — ETSI, IETF, or ISO adoption makes QRVA the de facto method
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
| API Gateway | Node.js + Fastify | High throughput, low overhead, TypeScript-native |
| Verification Edge | Cloudflare Workers | Sub-50ms global, edge-cached keys |
| Database (relational) | PostgreSQL 16 + PostGIS | Geospatial queries, ACID, tenant isolation |
| Database (analytics) | ClickHouse | Columnar storage for billions of scan events |
| Key Management | AWS KMS / HashiCorp Vault | HSM-backed, FIPS 140-2 compliant |
| Cache | Redis (Upstash for edge) | Token lookup, rate limiting, session state |
| Event Bus | Redis Streams | Webhook dispatch, event sourcing |
| Image Generation | Sharp (libvips) | Server-side visual proof rendering |
| Queue | BullMQ (Redis-backed) | Async fraud detection, alert delivery |
| ML Pipeline | Python + scikit-learn → ONNX | Anomaly detection, exportable to edge |

### SDKs and Frontend

| Component | Technology | Rationale |
|---|---|---|
| SDKs | TypeScript, Python, Go, PHP, Swift, Kotlin | Native experience per ecosystem |
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
│   │   │   ├── antiProxy.ts          # JA3/JA4 + latency + canvas checks
│   │   │   ├── visualProof.ts        # Ephemeral image generation
│   │   │   ├── webauthn.ts           # Passkey challenge/response
│   │   │   └── geo.ts               # Location matching at edge
│   │   ├── wrangler.toml
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

The mobile app is the **highest-security verification channel** and the power-user tool. It is NOT the primary product — the SDKs and APIs are.

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
git clone https://github.com/qrauth/qrauth.git
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
    ┌─────────▼──┐  ┌──────▼──────┐  ┌───▼──────────┐
    │ CF Workers  │  │ Fly.io /    │  │ Cloudflare   │
    │ (verify     │  │ Railway     │  │ Pages        │
    │  edge)      │  │ (API +      │  │ (Portal +    │
    │             │  │  services)  │  │  Docs)       │
    └─────────────┘  └──────┬──────┘  └──────────────┘
                            │
              ┌─────────────┼─────────────┐
              │             │             │
    ┌─────────▼──┐  ┌──────▼──────┐  ┌───▼──────────┐
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
| Analytics | ClickHouse Cloud (dev) | $0-25 |
| Portal + Docs | Cloudflare Pages (free) | $0 |
| Domain (qrauth.io) | Registrar | ~$30/year |
| **Total MVP** | | **$10-50/month** |

---

## Pricing

Modeled after Auth0's developer-first pricing: generous free tier to build the developer base, self-serve Pro for growing apps, and enterprise for large organizations.

### Free

- 1,000 verifications/month
- 100 QR codes
- 1 signing key
- Web verification page (QRAuth-branded)
- Community support
- **$0/month**

### Pro

- 50,000 verifications/month
- Unlimited QR codes
- Geospatial binding
- Analytics dashboard
- Webhooks (up to 5 endpoints)
- Custom verification page branding
- Email support
- **$49-199/month** (self-serve, Stripe)

### Business

- 500,000 verifications/month
- Multi-tenant isolation
- White-label verification page
- Fraud detection + alerts
- Webhooks (unlimited)
- SSO / SAML
- SLA (99.9%)
- Priority support
- **$299-999/month**

### Enterprise

- Unlimited verifications
- Dedicated infrastructure
- Custom SLA (99.99%)
- On-premise deployment option
- SOC2 compliance report
- Dedicated CSM
- Custom integrations
- **Custom pricing**

### API Verification Calls (Add-On)

Third-party apps integrating QRAuth via SDK can purchase verification calls:
- $0.001 per verification (volume discounts available)
- At 10M verifications/month: $10K/month from API alone

---

## Compliance

QRAuth is a security product. Enterprise buyers in regulated industries will not evaluate without certifications.

### Planned Certifications

| Certification | Target Date | Purpose |
|---|---|---|
| SOC 2 Type I | Q4 2026 | Baseline security controls attestation |
| SOC 2 Type II | Q2 2027 | Operational effectiveness over time |
| GDPR Compliance | Launch (Q3 2026) | EU data protection (mandatory for EU market) |
| ISO 27001 | Q4 2027 | Information security management system |
| eIDAS Compatibility | 2028 | EU electronic identification (government tier) |

### Data Handling

- All scan data is encrypted at rest (AES-256) and in transit (TLS 1.3)
- Tenant data is logically isolated (schema-level in PostgreSQL, partition-level in ClickHouse)
- PII minimization: scanner IP addresses are hashed before storage
- Data residency: EU tenants can specify EU-only data storage (Fly.io + Neon EU regions)
- Retention policies: configurable per tenant (default 90 days for scan events)
- Right to erasure: tenant deletion purges all associated data within 30 days

---

## Roadmap

### Phase 1 — Core Platform + Node.js SDK (Weeks 1-4)

- [ ] Tenant registration + API key generation
- [ ] QR code generation with ECDSA-P256 signing
- [ ] `@qrauth/node` SDK (create, verify, revoke)
- [ ] Web verification page (edge-deployed on Cloudflare Workers)
- [ ] Ephemeral visual proof (server-rendered image)
- [ ] Basic geospatial binding
- [ ] Transparency log (append-only)
- [ ] Developer documentation site

### Phase 2 — Developer Experience + Widget (Weeks 5-8)

- [ ] `@qrauth/badge.js` embeddable verification widget
- [ ] `@qrauth/react` component
- [ ] Webhook/event system (Redis Streams)
- [ ] Tenant portal (dashboard, QR management, analytics)
- [ ] API explorer (interactive docs)
- [ ] Python SDK
- [ ] PHP SDK

### Phase 3 — Security Hardening (Weeks 9-12)

- [ ] Anti-proxy detection (JA3/JA4, latency, canvas fingerprint)
- [ ] WebAuthn passkey enrollment + verification
- [ ] Fraud detection ML model v1
- [ ] Alert system (email + webhook)
- [ ] Rate limiting + abuse prevention
- [ ] Go SDK

### Phase 4 — Mobile App + Scale (Weeks 13-18)

- [ ] React Native app (iOS + Android)
- [ ] Native QR scanner with verification overlay
- [ ] Passkey management in app
- [ ] Offline verification with cached keys
- [ ] Push notifications for fraud alerts
- [ ] ClickHouse analytics pipeline at scale
- [ ] Multi-language support (Greek, English, French, German, Spanish)

### Phase 5 — Enterprise + Compliance (Weeks 19-26)

- [ ] SSO / SAML integration
- [ ] White-label verification pages
- [ ] SOC 2 Type I audit
- [ ] Stripe billing integration
- [ ] On-premise deployment option
- [ ] Swift SDK (iOS native)
- [ ] Kotlin SDK (Android native)

### Phase 6 — Ecosystem + Standardization (Weeks 26+)

- [ ] QRVA protocol submission to IETF/ETSI
- [ ] Marketplace for integrations (Zapier, Make, n8n)
- [ ] NFC tamper-evident tag integration
- [ ] First municipal partnerships (case studies)
- [ ] Partner program for QR code printer manufacturers
- [ ] Bridge to iQR hardware product line

---

## Contributing

QRAuth is open-source under the Business Source License. We welcome contributions to the core platform, SDKs, and protocol specification.

### Development Workflow

```bash
# Create feature branch
git checkout -b feature/your-feature

# Run all tests
turbo run test

# Run linter
turbo run lint

# Type check
turbo run typecheck

# Submit PR against main
```

### Code Standards

- TypeScript strict mode across all packages
- ESLint + Prettier for formatting
- Zod for runtime schema validation
- Vitest for testing
- 80%+ coverage target for security-critical paths (signing, verification, WebAuthn)
- Every SDK must pass the QRVA protocol compliance test suite

### SDK Contribution Guidelines

New SDKs must:
1. Implement the full `QRAuth` client interface (create, verify, revoke, webhooks)
2. Pass all tests in `packages/protocol-tests/`
3. Include comprehensive type definitions
4. Provide a quickstart example in the README
5. Be published to the ecosystem's standard package registry

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
- **GitHub**: https://github.com/qrauth/qrauth
- **Email**: hello@qrauth.io

---

*The authentication layer for every QR code in the physical world.*
