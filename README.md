# QRAuth — Verified QR Code Security Platform

**Cryptographically signed, geospatially bound, anti-phishing QR code verification for the physical world.**

QRAuth is an open-source security platform that makes physical QR codes tamper-proof and verifiable. It combines digital signatures, geospatial binding, anti-proxy detection, and WebAuthn passkeys to create a trust layer for QR codes deployed on parking meters, government signs, payment terminals, restaurant menus, and any other public-facing surface.

---

## Table of Contents

- [Problem](#problem)
- [Solution](#solution)
- [Architecture](#architecture)
- [Security Model](#security-model)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [API Reference](#api-reference)
- [Mobile App](#mobile-app)
- [Getting Started](#getting-started)
- [Deployment](#deployment)
- [Business Model](#business-model)
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

The ticket fraud detection market alone is valued at USD 1.87 billion (2024), growing at 16.2% CAGR.

---

## Solution

QRAuth creates a **Certificate Authority for physical QR codes** — a trust infrastructure layer between QR code issuers and scanners.

### How It Works

1. **Issuer Registration**: Municipality, business, or institution registers on the QRAuth platform, undergoes KYC verification, and receives a cryptographic key pair.

2. **QR Code Generation**: Issuer generates QR codes through the platform. Each QR encodes a short verification URL:
   ```
   https://qrauth.io/v/[short-token]
   ```

3. **Scan & Verify**: Any user scans the QR with their phone camera (no app required). The URL opens a verification page showing issuer identity, registration date, location match, and a server-generated ephemeral visual proof.

4. **Progressive Trust**: Returning users are prompted to create a WebAuthn passkey for cryptographic, unphishable verification on future scans.

### Key Differentiators

- **No app install required** — web-based verification works on any phone
- **Ephemeral visual proof** — server-generated verification image that cannot be cloned
- **Geospatial binding** — QR codes are bound to physical GPS coordinates
- **Anti-proxy detection** — TLS fingerprinting, latency analysis, and canvas fingerprinting detect real-time page cloning
- **WebAuthn passkeys** — hardware-level, origin-bound authentication that is physically unphishable
- **Transparency log** — public, append-only audit trail of all issued QR codes

---

## Architecture

### System Overview

```
                          ┌─────────────────────┐
                          │    Issuer Portal     │
                          │    (React SPA)       │
                          └──────────┬───────────┘
                                     │
                          ┌──────────▼───────────┐
                          │    API Gateway        │
                          │    (Node/Fastify)     │
                          └──────────┬───────────┘
                                     │
               ┌─────────────────────┼─────────────────────┐
               │                     │                     │
    ┌──────────▼───────┐  ┌──────────▼──────────┐ ┌───────▼──────────┐
    │   Auth / KYC     │  │   QR Signing        │ │  Geo Registry    │
    │   Service        │  │   Service           │ │  Service         │
    │                  │  │   (ECDSA-P256)      │ │  (PostGIS)       │
    └──────────────────┘  └─────────────────────┘ └──────────────────┘
                                     │
                          ┌──────────▼───────────┐
                          │  Verification Edge   │
                          │  (Cloudflare Workers) │
                          └──────────┬───────────┘
                                     │
               ┌─────────────────────┼─────────────────────┐
               │                     │                     │
    ┌──────────▼───────┐  ┌──────────▼──────────┐ ┌───────▼──────────┐
    │  Fraud Detection │  │  Analytics Pipeline │ │  Alert Service   │
    │  (ML model)      │  │  (ClickHouse)       │ │  (Push/Email)    │
    └──────────────────┘  └─────────────────────┘ └──────────────────┘
                                     │
                          ┌──────────▼───────────┐
                          │  Transparency Log    │
                          │  (Append-only DB)    │
                          └──────────────────────┘
```

### Core Services

**API Gateway (Node.js / Fastify)**
Entry point for all issuer-facing operations. Handles authentication, rate limiting, request validation, and routing to internal services. Exposes RESTful endpoints for issuer management, QR code generation, and analytics.

**Auth / KYC Service**
Manages issuer registration, identity verification, and access control. Issuers undergo a verification process (document upload, domain ownership proof) before receiving signing capabilities. Supports OAuth2 for third-party integrations.

**QR Signing Service**
Core cryptographic engine. Generates ECDSA-P256 key pairs per issuer, signs QR payloads, and manages key rotation. Private keys are stored in AWS KMS or HashiCorp Vault — never in application memory. Signs payloads with:
```
signature = ECDSA_Sign(issuer_private_key, SHA256(token + destination_url + geo_hash + expiry))
```

**Geo Registry Service (PostGIS)**
Stores the physical location of every registered QR code. Each registration includes GPS coordinates, accuracy radius, and location metadata (address, description). Supports spatial queries: "find all registered QR codes within N meters of this point."

**Verification Edge (Cloudflare Workers)**
The public-facing verification endpoint. Deployed globally on edge nodes for sub-50ms response times. Handles the full verification flow: token lookup, signature verification, geospatial matching, anti-proxy checks, ephemeral proof generation, and WebAuthn challenge/response.

**Fraud Detection Service**
ML pipeline that analyzes scan patterns in real-time. Detects anomalies: new QR codes appearing at locations with existing registrations, sudden changes in scan patterns, scans from known proxy IP ranges, and geographic impossibilities (same user scanning in two cities within minutes).

**Analytics Pipeline (ClickHouse)**
Columnar time-series database for scan event storage and analysis. Powers the issuer dashboard (scan counts, peak times, geographic heatmaps) and feeds the fraud detection model. Handles millions of scan events per day.

**Alert Service**
Delivers real-time notifications to issuers and administrators when fraud is detected. Supports push notifications (via mobile app), email, SMS, and webhook integrations.

**Transparency Log**
Public, append-only ledger of all QR code issuances. Each entry contains: issuer ID, token, destination URL hash, registration timestamp, and geolocation hash. Third parties can audit the log to verify QR code legitimacy. Inspired by Certificate Transparency (RFC 6962).

---

## Security Model

QRAuth implements a four-tier progressive security model. Each tier builds on the previous, and users automatically escalate through tiers over time.

### Tier 1 — Cryptographic Signing (Baseline)

Every QR code generated through QRAuth includes a digital signature in its verification record. The signature is created using ECDSA-P256 with the issuer's private key (managed in KMS).

**Verification flow:**
```
1. User scans QR → browser opens https://qrauth.io/v/[token]
2. Edge worker looks up token → retrieves: destination_url, issuer_id, signature, geo_data
3. Edge worker fetches issuer's public key (cached at edge)
4. Edge worker verifies: ECDSA_Verify(public_key, signature, payload_hash)
5. If valid → display verified issuer identity and destination URL
6. If invalid → display fraud warning
```

**What this defeats:** QR codes pointing to arbitrary URLs that were never registered on the platform.

**What this does NOT defeat:** A scammer who clones the verification page itself.

### Tier 2 — Ephemeral Server-Generated Visual Proof (Anti-Cloning)

The verification page renders a **server-generated image** (PNG, computed per-request) containing personalized, time-bound information that a cloned page cannot reproduce:

- **User's approximate location** (derived from IP geolocation): "Thessaloniki, Central Macedonia"
- **User's device type** (from User-Agent): "iPhone 15, Safari"
- **Exact timestamp** (to the second): "14:32:07 EEST"
- **Procedural visual fingerprint**: A unique abstract pattern generated from `HMAC(server_secret, token + timestamp + client_ip_hash)`

The image is rendered server-side using Sharp or Canvas API. It is NOT HTML/CSS (which can be trivially cloned) — it is a rasterized image with anti-aliasing artifacts that differ per render, making pixel-perfect reproduction computationally expensive.

**What this defeats:** Static page cloning. The cloned page shows stale timestamps, wrong locations, and missing/incorrect visual fingerprints.

### Tier 3 — Anti-Proxy Detection (Anti-MitM)

Defends against real-time reverse proxying where a scammer forwards requests to the real QRAuth server and relays responses to the victim.

**Detection signals:**

| Signal | Method | Detection Confidence |
|---|---|---|
| TLS Fingerprint (JA3/JA4) | Compare TLS handshake against User-Agent claim | High |
| Latency Analysis | Measure RTT to edge; proxied requests add 50-200ms | Medium |
| Canvas Fingerprint | Hash of canvas render output; differs between devices | High |
| JavaScript Integrity | `window.location.origin` check, `performance.getEntries()` hostname validation | Medium |
| IP/Geo Consistency | IP geolocation vs. browser geolocation API comparison | Medium |
| Header Analysis | Detect proxy-injected headers (X-Forwarded-For, Via) | Low-Medium |

**Scoring:** Each signal contributes to a composite trust score (0-100). Scores below threshold trigger a warning banner on the verification page and log the incident for fraud analysis.

**What this defeats:** Real-time page proxying. The proxy's TLS fingerprint, latency profile, and canvas output differ from a genuine browser, triggering detection.

### Tier 4 — WebAuthn Passkeys (Unphishable)

The strongest security tier, leveraging hardware-backed cryptographic authentication.

**How WebAuthn defeats phishing:**
WebAuthn credentials are **origin-bound** at the OS/hardware level. A passkey created for `https://qrauth.io` will ONLY activate on `https://qrauth.io`. A phishing page on `https://qrauth-io.com` or any other domain physically cannot trigger the passkey prompt. This is enforced by the authenticator (Secure Enclave on Apple, Titan chip on Android, TPM on Windows), not by JavaScript — making it immune to code injection or proxy attacks.

**Enrollment flow:**
```
1. User verifies a QR code via Tier 1-3 (first visit)
2. Verification page offers: "Create a passkey for instant verification"
3. User taps → biometric prompt (Face ID / fingerprint)
4. Browser generates ECDSA key pair, private key stored in Secure Enclave
5. Public key sent to QRAuth server, associated with user's device
6. Enrollment complete — future scans trigger passkey automatically
```

**Verification flow (returning user):**
```
1. User scans any QRAuth code → browser opens verification URL
2. Browser detects existing passkey for qrauth.io → prompts biometric
3. Authenticator signs server challenge with private key
4. Server verifies signature with stored public key
5. Verification page shows: "Verified + Passkey Confirmed"
```

**What this defeats:** Everything. Including sophisticated real-time proxying, social engineering, and domain spoofing. If the passkey prompt doesn't appear, the user knows instantly that something is wrong.

### Security Tier Summary

| Tier | Defeats | Requires | User Friction |
|---|---|---|---|
| 1 - Signed QR | Unregistered fake QRs | Nothing (automatic) | None |
| 2 - Visual Proof | Static page cloning | Nothing (automatic) | None |
| 3 - Anti-Proxy | Real-time MitM proxying | Nothing (automatic) | None |
| 4 - WebAuthn | All known phishing vectors | One-time passkey creation | Biometric tap per scan |

---

## Tech Stack

### Backend

| Component | Technology | Rationale |
|---|---|---|
| API Gateway | Node.js + Fastify | High throughput, low overhead, TypeScript-native |
| Verification Edge | Cloudflare Workers | Sub-50ms global response, edge-cached keys |
| Database (relational) | PostgreSQL 16 + PostGIS | Geospatial queries, ACID compliance |
| Database (analytics) | ClickHouse | Columnar storage for billions of scan events |
| Key Management | AWS KMS / HashiCorp Vault | HSM-backed, FIPS 140-2 compliant |
| Cache | Redis (Upstash for edge) | Token lookup cache, rate limiting |
| Image Generation | Sharp (libvips) | Server-side visual proof rendering |
| Queue | BullMQ (Redis-backed) | Async fraud detection, alert delivery |
| ML Pipeline | Python + scikit-learn → ONNX | Anomaly detection model, exportable to edge |

### Frontend

| Component | Technology | Rationale |
|---|---|---|
| Issuer Portal | React + TypeScript + Vite | SPA with real-time dashboard |
| Verification Page | Vanilla HTML/JS (edge-rendered) | Zero dependencies, fast TTFB |
| UI Components | shadcn/ui + Tailwind CSS | Consistent design, accessible |
| Charts/Analytics | Recharts | Issuer dashboard visualizations |

### Mobile App

| Component | Technology | Rationale |
|---|---|---|
| Framework | React Native + Expo | Cross-platform, shared business logic with web |
| QR Scanner | expo-camera + vision-camera | Native camera access, fast decode |
| WebAuthn | react-native-passkeys | Native passkey integration |
| NFC | react-native-nfc-manager | Future tamper-evident tag reading |
| Push Notifications | Expo Notifications + FCM/APNs | Fraud alerts |
| Offline Storage | WatermelonDB | Cached issuer keys for offline verification |

### Infrastructure

| Component | Technology | Rationale |
|---|---|---|
| Container Orchestration | Docker + Fly.io or Railway | Simple deployment, global distribution |
| CI/CD | GitHub Actions | Automated testing, staging, production deploys |
| Monitoring | Grafana + Prometheus | Service health, latency tracking |
| Error Tracking | Sentry | Runtime error capture across all services |
| DNS / CDN | Cloudflare | Edge caching, DDoS protection, Workers runtime |

---

## Project Structure

```
qrauth/
├── README.md
├── docker-compose.yml
├── .env.example
├── packages/
│   ├── api/                        # Fastify API Gateway
│   │   ├── src/
│   │   │   ├── server.ts           # Fastify app bootstrap
│   │   │   ├── routes/
│   │   │   │   ├── issuers.ts      # Issuer CRUD + KYC
│   │   │   │   ├── qrcodes.ts      # QR code generation + signing
│   │   │   │   ├── verify.ts       # Verification endpoint (non-edge)
│   │   │   │   └── analytics.ts    # Dashboard data endpoints
│   │   │   ├── services/
│   │   │   │   ├── signing.ts      # ECDSA key management + signing
│   │   │   │   ├── geo.ts          # PostGIS geospatial queries
│   │   │   │   ├── fraud.ts        # Fraud detection orchestration
│   │   │   │   └── alerts.ts       # Notification dispatch
│   │   │   ├── middleware/
│   │   │   │   ├── auth.ts         # JWT + API key authentication
│   │   │   │   ├── rateLimit.ts    # Per-issuer rate limiting
│   │   │   │   └── validate.ts     # Request schema validation
│   │   │   └── lib/
│   │   │       ├── crypto.ts       # ECDSA utilities, HMAC helpers
│   │   │       ├── db.ts           # PostgreSQL connection pool
│   │   │       └── cache.ts        # Redis client
│   │   ├── prisma/
│   │   │   └── schema.prisma       # Database schema
│   │   ├── tests/
│   │   └── package.json
│   │
│   ├── edge/                       # Cloudflare Workers verification
│   │   ├── src/
│   │   │   ├── worker.ts           # Edge verification handler
│   │   │   ├── verify.ts           # Signature verification logic
│   │   │   ├── antiProxy.ts        # TLS/JA3 + latency + canvas checks
│   │   │   ├── visualProof.ts      # Ephemeral image generation
│   │   │   ├── webauthn.ts         # Passkey challenge/response
│   │   │   └── geo.ts              # Location matching at edge
│   │   ├── wrangler.toml
│   │   └── package.json
│   │
│   ├── portal/                     # Issuer dashboard (React SPA)
│   │   ├── src/
│   │   │   ├── pages/
│   │   │   │   ├── Dashboard.tsx    # Overview: scan counts, fraud alerts
│   │   │   │   ├── QRCodes.tsx      # QR code management + generation
│   │   │   │   ├── Locations.tsx    # Geospatial map of deployments
│   │   │   │   ├── Analytics.tsx    # Scan patterns, heatmaps
│   │   │   │   ├── Fraud.tsx        # Fraud incident log + details
│   │   │   │   └── Settings.tsx     # Account, keys, team management
│   │   │   ├── components/
│   │   │   ├── hooks/
│   │   │   └── lib/
│   │   ├── tests/
│   │   └── package.json
│   │
│   ├── mobile/                     # React Native mobile app
│   │   ├── app/
│   │   │   ├── (tabs)/
│   │   │   │   ├── scan.tsx        # QR scanner + instant verification
│   │   │   │   ├── history.tsx     # Scan history + fraud reports
│   │   │   │   ├── alerts.tsx      # Push notification center
│   │   │   │   └── settings.tsx    # Passkey management, preferences
│   │   │   ├── verify/
│   │   │   │   └── [token].tsx     # Deep-link verification screen
│   │   │   └── _layout.tsx
│   │   ├── lib/
│   │   │   ├── crypto.ts           # Shared ECDSA verification
│   │   │   ├── offlineCache.ts     # Cached issuer keys (WatermelonDB)
│   │   │   ├── passkeys.ts         # WebAuthn/passkey integration
│   │   │   └── nfc.ts              # NFC tag reading (future)
│   │   └── package.json
│   │
│   └── shared/                     # Shared types, constants, utilities
│       ├── src/
│       │   ├── types.ts            # TypeScript interfaces
│       │   ├── constants.ts        # Protocol constants
│       │   ├── crypto.ts           # Shared crypto utilities
│       │   └── validation.ts       # Shared Zod schemas
│       └── package.json
│
├── infra/                          # Infrastructure as Code
│   ├── docker/
│   │   ├── Dockerfile.api
│   │   ├── Dockerfile.portal
│   │   └── Dockerfile.mobile
│   ├── terraform/                  # Cloud infrastructure
│   │   ├── main.tf
│   │   ├── database.tf
│   │   ├── kms.tf
│   │   └── monitoring.tf
│   └── ansible/                    # Server configuration
│       └── playbooks/
│
├── docs/
│   ├── PROTOCOL.md                 # Formal protocol specification
│   ├── SECURITY.md                 # Security model deep-dive
│   ├── API.md                      # Full API documentation
│   ├── DEPLOYMENT.md               # Deployment guide
│   └── THREAT_MODEL.md             # Threat modeling document
│
└── scripts/
    ├── setup.sh                    # Local development setup
    ├── seed.sh                     # Seed database with test data
    └── generate-keys.sh            # Generate test ECDSA key pairs
```

---

## API Reference

### Authentication

All issuer API endpoints require authentication via Bearer token (JWT) or API key.

```
Authorization: Bearer <jwt_token>
# or
X-API-Key: <api_key>
```

### Endpoints

#### Issuers

```
POST   /api/v1/issuers              # Register new issuer
GET    /api/v1/issuers/:id          # Get issuer details
PATCH  /api/v1/issuers/:id          # Update issuer profile
POST   /api/v1/issuers/:id/verify   # Submit KYC verification
GET    /api/v1/issuers/:id/keys     # List signing keys
POST   /api/v1/issuers/:id/keys/rotate  # Rotate signing key
```

#### QR Codes

```
POST   /api/v1/qrcodes              # Generate signed QR code
GET    /api/v1/qrcodes              # List issuer's QR codes
GET    /api/v1/qrcodes/:token       # Get QR code details
PATCH  /api/v1/qrcodes/:token       # Update destination URL
DELETE /api/v1/qrcodes/:token       # Revoke QR code
POST   /api/v1/qrcodes/bulk         # Bulk generate QR codes
```

#### Verification (Public — No Auth Required)

```
GET    /v/[token]                   # Web verification page (edge-served)
GET    /api/v1/verify/:token        # API verification (for SDK integrations)
POST   /api/v1/verify/:token/webauthn  # WebAuthn challenge/response
```

#### Analytics

```
GET    /api/v1/analytics/scans       # Scan event history
GET    /api/v1/analytics/heatmap     # Geographic scan heatmap
GET    /api/v1/analytics/fraud       # Fraud incident log
GET    /api/v1/analytics/summary     # Dashboard summary stats
```

#### Transparency Log (Public — No Auth Required)

```
GET    /api/v1/transparency/log      # Query transparency log
GET    /api/v1/transparency/proof/:token  # Get inclusion proof for token
```

### Example: Generate a Signed QR Code

```bash
curl -X POST https://api.qrauth.io/api/v1/qrcodes \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "destination_url": "https://parking.thessaloniki.gr/pay/zone-b",
    "label": "Parking Zone B - Tsimiski Street",
    "location": {
      "lat": 40.6321,
      "lng": 22.9414,
      "radius_m": 15
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
  "issuer_id": "iss_thess_municipality",
  "created_at": "2026-04-01T12:00:00Z",
  "expires_at": "2027-01-01T00:00:00Z",
  "transparency_log_index": 48291
}
```

### Example: Verify a QR Code (API)

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
    "id": "iss_thess_municipality",
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
  "scanned_at": "2026-04-01T14:32:07Z"
}
```

---

## Mobile App

### Purpose

The mobile app serves as the **highest-security verification channel** and provides capabilities that the web verifier cannot:

- **Native QR scanning** with real-time verification overlay (verify before opening any URL)
- **WebAuthn passkey management** with biometric binding (Face ID, fingerprint)
- **Offline verification** using cached issuer public keys (no internet required at scan time)
- **Push notifications** for fraud alerts near your location
- **NFC tag reading** for future tamper-evident physical verification layer
- **Scan history** with the ability to report suspicious QR codes

### Architecture

```
┌───────────────────────────────────────────┐
│              React Native App             │
├───────────────┬───────────────────────────┤
│  UI Layer     │  Expo Router (tabs)       │
├───────────────┼───────────────────────────┤
│  Scanner      │  vision-camera + ML Kit   │
├───────────────┼───────────────────────────┤
│  Auth         │  react-native-passkeys    │
├───────────────┼───────────────────────────┤
│  Offline DB   │  WatermelonDB             │
│               │  - Issuer public keys     │
│               │  - Scan history           │
│               │  - Fraud reports cache    │
├───────────────┼───────────────────────────┤
│  Networking   │  Axios + offline queue    │
├───────────────┼───────────────────────────┤
│  NFC          │  react-native-nfc-manager │
├───────────────┼───────────────────────────┤
│  Crypto       │  expo-crypto + shared lib │
└───────────────┴───────────────────────────┘
```

### Offline Verification Flow

```
1. App periodically syncs issuer public keys from server → stores in WatermelonDB
2. User scans QR code (no internet required)
3. App parses QRAuth token from URL
4. App looks up issuer public key in local cache
5. App verifies ECDSA signature locally
6. App checks GPS against cached geospatial data
7. Displays verification result with "offline" badge
8. When connectivity returns, uploads scan event for analytics
```

### Platform Support

| Platform | Minimum Version | Passkey Support | NFC Support |
|---|---|---|---|
| iOS | 16.0+ | Yes (Keychain) | Yes (Core NFC) |
| Android | 9.0+ (API 28) | Yes (FIDO2) | Yes (NfcAdapter) |

---

## Getting Started

### Prerequisites

- Node.js 20+
- PostgreSQL 16 with PostGIS extension
- Redis 7+
- Docker (optional, for containerized development)

### Local Development Setup

```bash
# Clone the repository
git clone https://github.com/qrauth-io/qrauth.git
cd qrauth

# Install dependencies (monorepo)
npm install

# Copy environment variables
cp .env.example .env

# Generate development ECDSA key pair
./scripts/generate-keys.sh

# Start PostgreSQL + Redis (Docker)
docker compose up -d postgres redis

# Run database migrations
npm run db:migrate -w packages/api

# Seed with test data (test issuer + sample QR codes)
npm run db:seed -w packages/api

# Start all services in development mode
npm run dev
```

This starts:
- **API Gateway** at `http://localhost:3000`
- **Issuer Portal** at `http://localhost:5173`
- **Verification Page** at `http://localhost:3000/v/[token]`

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql://qrauth:qrauth@localhost:5432/qrauth
REDIS_URL=redis://localhost:6379

# Cryptography
KMS_PROVIDER=local                    # local | aws | vault
ECDSA_PRIVATE_KEY_PATH=./keys/dev.pem # Local dev only
VISUAL_PROOF_SECRET=<random-64-chars>  # HMAC secret for visual proofs

# Cloudflare (production edge deployment)
CF_ACCOUNT_ID=
CF_API_TOKEN=
CF_ZONE_ID=

# WebAuthn
WEBAUTHN_RP_NAME=QRAuth
WEBAUTHN_RP_ID=localhost              # qrauth.io in production
WEBAUTHN_ORIGIN=http://localhost:3000 # https://qrauth.io in production

# Analytics
CLICKHOUSE_URL=http://localhost:8123
CLICKHOUSE_DATABASE=qrauth_analytics

# Alerts
SMTP_HOST=
SMTP_PORT=
SMTP_USER=
SMTP_PASS=
PUSH_VAPID_PUBLIC_KEY=
PUSH_VAPID_PRIVATE_KEY=
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
    │ CF Workers  │  │ Fly.io /    │  │ Static       │
    │ (verify     │  │ Railway     │  │ (Cloudflare  │
    │  edge)      │  │ (API +      │  │  Pages)      │
    │             │  │  services)  │  │ (Portal SPA) │
    └─────────────┘  └──────┬──────┘  └──────────────┘
                            │
              ┌─────────────┼─────────────┐
              │             │             │
    ┌─────────▼──┐  ┌──────▼──────┐  ┌───▼──────────┐
    │ PostgreSQL  │  │ Redis       │  │ ClickHouse   │
    │ + PostGIS   │  │ (Upstash)   │  │ (ClickHouse  │
    │ (Neon /     │  │             │  │  Cloud)      │
    │  Supabase)  │  │             │  │              │
    └─────────────┘  └─────────────┘  └──────────────┘
```

### Estimated Infrastructure Cost (MVP)

| Service | Provider | Monthly Cost |
|---|---|---|
| Edge Verification | Cloudflare Workers (free tier) | $0 (up to 100K req/day) |
| API + Services | Fly.io (2x shared-cpu) | $10-20 |
| PostgreSQL + PostGIS | Neon (free tier) | $0 (up to 0.5 GB) |
| Redis | Upstash (free tier) | $0 (up to 10K commands/day) |
| Analytics | ClickHouse Cloud (dev tier) | $0-25 |
| Portal Hosting | Cloudflare Pages (free) | $0 |
| Domain (qrauth.io) | Registrar | ~$30/year |
| **Total MVP** | | **$10-50/month** |

---

## Business Model

### Revenue Streams

**1. SaaS Platform (Primary)**
- Free tier: up to 50 QR codes, basic verification, QRAuth branding on verification page
- Pro ($49-199/month): unlimited QR codes, geospatial binding, analytics dashboard, custom branding
- Enterprise ($500-5000/month): API access, white-label, SLA, dedicated support, bulk management

**2. API / SDK Licensing**
- $0.001 per verification call for third-party app integrations
- SDK available for: parking apps, payment platforms, event ticketing systems

**3. Fraud Intelligence**
- Analytics dashboard showing fraud hotspots, patterns, and trends
- Sold as add-on to municipal and enterprise customers

**4. Tamper-Evident Sticker Packs (Future Physical Product)**
- Pre-printed QRAuth-encoded stickers on destructible vinyl substrate
- $0.50-1.00 per sticker (BOM: $0.05-0.15)
- Ordered through the platform, shipped directly to issuers

### Target Markets (Priority Order)

1. **Municipalities** — parking systems, public signage, government services
2. **Parking operators** — EasyPark, APCOA, Q-Park, ParkMobile
3. **Financial institutions** — ATM QR codes, branch signage
4. **Restaurants / Retail** — menu QR codes, payment QR codes
5. **Event organizers** — ticket verification (bridge to iQR hardware product)

---

## Roadmap

### Phase 1 — MVP (Weeks 1-6)
- [ ] Issuer registration + KYC flow
- [ ] QR code generation with ECDSA-P256 signing
- [ ] Web verification page (edge-deployed)
- [ ] Ephemeral visual proof (server-rendered image)
- [ ] Basic geospatial binding (GPS registration + matching)
- [ ] Issuer portal (dashboard, QR management)
- [ ] Transparency log (append-only)

### Phase 2 — Security Hardening (Weeks 7-12)
- [ ] Anti-proxy detection (JA3/JA4, latency, canvas fingerprint)
- [ ] WebAuthn passkey enrollment + verification
- [ ] Fraud detection ML model v1
- [ ] Alert system (email + webhook)
- [ ] Public API + SDK for third-party integrations
- [ ] Rate limiting + abuse prevention

### Phase 3 — Mobile App (Weeks 10-16)
- [ ] React Native app (iOS + Android)
- [ ] Native QR scanner with verification overlay
- [ ] Passkey management
- [ ] Offline verification with cached keys
- [ ] Push notifications for fraud alerts
- [ ] Scan history + reporting

### Phase 4 — Scale + Monetization (Weeks 16-24)
- [ ] ClickHouse analytics pipeline
- [ ] Issuer analytics dashboard (heatmaps, trends)
- [ ] Billing integration (Stripe)
- [ ] White-label verification page (enterprise)
- [ ] Multi-language support (Greek, English, French, German)
- [ ] First municipal partnership (Thessaloniki / Athens target)

### Phase 5 — Physical Layer (Weeks 24+)
- [ ] Tamper-evident sticker product line
- [ ] NFC tag integration (dual QR + NFC verification)
- [ ] Bridge to iQR (interchangeable magnetic QR) hardware product
- [ ] EU standardization proposal (ETSI)

---

## Contributing

We welcome contributions. See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for guidelines.

### Development Workflow

```bash
# Create feature branch
git checkout -b feature/your-feature

# Run tests
npm test

# Run linter
npm run lint

# Submit PR against main branch
```

### Code Standards

- TypeScript strict mode enabled across all packages
- ESLint + Prettier for formatting
- Zod for runtime schema validation
- 80%+ test coverage target for security-critical paths (signing, verification, WebAuthn)

---

## License

This project is licensed under the [BSL 1.1](LICENSE) (Business Source License) — free for non-commercial use, with automatic conversion to Apache 2.0 after 3 years. Commercial use requires a license from QRAuth.

---

## Contact

- Website: https://qrauth.io
- Email: hello@qrauth.io
- GitHub: https://github.com/qrauth-io/qrauth

---

*Built with the conviction that every QR code in the physical world should be verifiable.*
