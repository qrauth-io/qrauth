# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

QRAuth (qrauth.io) is a cryptographically signed QR code verification and authentication platform. It creates a "Certificate Authority for physical QR codes" + a QR-based authentication SDK for third-party websites.

**Production**: https://qrauth.io

## Commands

```bash
npm install                          # Install all monorepo dependencies
npm run dev                          # Start API server (port 3000)
npm run dev:web                      # Start web dashboard (port 8081)
npm run dev:all                      # Start both
npm run build                        # Build shared → API → web
npm run test:e2e                     # Run Playwright E2E tests (39 tests)
npm run db:migrate                   # Run Prisma migrations
npm run db:seed                      # Seed test data
docker compose up -d                 # Start local Postgres + Redis
```

Workspace commands: `npm run <script> -w packages/<name>`

## Architecture

Monorepo under `packages/` with 4 packages:

- **shared/** — TypeScript types, Zod schemas, constants, crypto utilities, content type registry. Consumed by all packages.
- **api/** — Fastify 5 API server. Routes in `src/routes/`, services in `src/services/`, renderers in `src/renderers/`, AI agent in `src/agent/`. Prisma ORM with PostgreSQL+PostGIS. Entry point: `src/server.ts`
- **web/** — React 19 + MUI 7 dashboard (Vite). Minimals template. Auth, QR management, analytics, fraud detection, team management, settings.
- **e2e/** — Playwright E2E tests (API, auth, dashboard, security)

Deploy config in `deploy/` (Docker Compose, Dockerfiles, nginx).

## Key Systems

### Authentication
- JWT + API key auth (middleware/auth.ts)
- OAuth2: Google, GitHub, Microsoft, Apple (lib/oauth.ts, routes/auth.ts)
- QR-based auth SDK for third-party websites (routes/auth-sessions.ts, public/sdk/)
- Multi-tenant: Organizations → Users → Memberships with roles (OWNER/ADMIN/MANAGER/MEMBER/VIEWER)
- Onboarding flow for new users (routes/auth.ts POST /onboarding/complete)

### QR Codes & Content Types
- Content type registry in shared/src/content-types/ — modular system
- Types: URL, vCard, Coupon, Event, PDF, Feedback
- Each type: Zod schema + field definitions + server-side HTML renderer
- Adding a new type: define schema+fields in shared, add renderer in api/renderers/
- ECDSA-P256 signing with content hash (deterministic via stableStringify)
- Signature: `hashPayload(token, url, geoHash, expiry, contentHash)`

### Fraud Detection
- 6 inline signals in services/fraud.ts (duplicate location, proxy, geo-impossibility, velocity, bot, device clustering)
- Dynamic rule engine: services/dynamic-rules.ts reads JSON rules from DB
- Feature extraction: services/feature-extraction.ts computes per-scan features via Redis
- Adaptive scoring: services/adaptive-scoring.ts adjusts per-org weights
- Trust score computed in real-time on verification (getQuickTrustScore)

### AI Agent
- Daily Claude agent via GitHub Actions (agent/daily-analysis.ts)
- 8 tools: query scans, fraud, logins, orgs, features, create rules, write reports, suggest changes
- Creates dynamic fraud rules that go live in <60 seconds

### Verification Page
- Shell + renderer architecture (renderers/shell.ts + renderers/{type}.ts)
- Ephemeral visual proof: city, device, timestamp, HMAC fingerprint
- Origin integrity check (JS validates hostname)
- Domain similarity detection (services/domain.ts)
- GPS geolocation for proximity matching (only when QR has registered location)
- Content negotiation: HTML for browsers, JSON for API clients (`Accept: application/json`)

## Database

PostgreSQL 16 + PostGIS via Prisma. Key models:
- Organization, User, Membership, Invitation (multi-tenant auth)
- QRCode (contentType, content JSON, signature), Scan, FraudIncident
- App, AuthSession (QR-based auth for third-party sites)
- SigningKey (ECDSA-P256, PEM files in ./keys/)
- FraudRule, AnalyticsSnapshot, AgentRun (AI monitoring)
- LoginEvent, ContentAsset, FeedbackSubmission, TransparencyLogEntry

## Important Patterns

- **Signing keys**: PEM files stored at `config.kms.ecdsaPrivateKeyPath/{keyId}.pem`. Docker volume mounted at `/app/keys`, symlinked to working dir.
- **Content hashing**: Use `stableStringify()` from lib/crypto.ts for deterministic JSON (PostgreSQL JSONB reorders keys).
- **Date formatting**: Use `formatDate()`/`formatDateTime()` from web/src/utils/format-date.ts (European dd/mm/yyyy).
- **Domain references**: Production domain controlled by `WEBAUTHN_ORIGIN` env var. Fallback: `qrauth.io`.
- **Error boundary**: Auto-reloads on chunk load failure (handles deployments).

## Testing

39 E2E tests via Playwright:
- 7 API tests (signup, login, QR CRUD, verification, transparency)
- 7 auth browser tests (sign-in/up, validation, guards)
- 6 dashboard navigation tests
- 19 security tests (clone detection, fraud, account lockout, IDOR, signatures, rate limiting)

Note: Scan velocity tests are skipped in CI (exhaust rate limits).

## CI/CD

GitHub Actions:
- `ci.yml`: lint → typecheck → build → E2E tests → deploy (SSH to server)
- `daily-agent.yml`: daily AI security analysis (runs on server via SSH)
- SSH key: base64-encoded in `DEPLOY_SSH_KEY` secret, decoded with `base64 -d`
