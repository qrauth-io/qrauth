# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

vQR is a cryptographically signed, geospatially bound QR code verification platform. It creates a "Certificate Authority for physical QR codes" — a trust layer between QR code issuers and scanners. The project is in early development (pre-MVP).

## Commands

```bash
npm install                          # Install all monorepo dependencies
npm run dev                          # Start all services (API :3000, Portal :5173)
npm test                             # Run tests across all packages
npm run lint                         # ESLint + Prettier
npm run db:migrate -w packages/api   # Run Prisma migrations
npm run db:seed -w packages/api      # Seed test data
./scripts/generate-keys.sh           # Generate dev ECDSA key pairs
docker compose up -d postgres redis  # Start local databases
```

Run a single package's commands with workspace flag: `npm run <script> -w packages/<name>`

## Architecture

Monorepo under `packages/` with five packages:

- **api/** — Fastify API gateway (Node.js). Routes in `src/routes/`, business logic in `src/services/`, Prisma ORM with PostgreSQL+PostGIS. Entry point: `src/server.ts`
- **edge/** — Cloudflare Workers for public verification endpoint (`/v/[token]`). Handles signature verification, anti-proxy detection, ephemeral visual proof generation, and WebAuthn. Config: `wrangler.toml`
- **portal/** — React SPA (Vite + TypeScript) for issuer dashboard. Uses shadcn/ui + Tailwind CSS + Recharts
- **mobile/** — React Native + Expo app with Expo Router (file-based routing under `app/`). Offline verification via WatermelonDB cached issuer keys
- **shared/** — Shared TypeScript types, constants, Zod validation schemas, and crypto utilities used across all packages

Infrastructure lives in `infra/` (Docker, Terraform, Ansible). Dev scripts in `scripts/`.

## Key Technical Decisions

- **Crypto**: ECDSA-P256 for QR code signing. Private keys in AWS KMS / HashiCorp Vault (local file in dev). Signature = `ECDSA_Sign(issuer_key, SHA256(token + url + geohash + expiry))`
- **Validation**: Zod schemas for runtime validation (shared across packages)
- **Auth**: JWT + API key authentication for issuer endpoints. WebAuthn/passkeys for end-user verification (Tier 4 security)
- **Databases**: PostgreSQL 16 + PostGIS (relational + geo), ClickHouse (analytics), Redis (cache + rate limiting + queues via BullMQ)
- **TypeScript strict mode** enabled across all packages
- **BSL 1.1 license** — free for non-commercial use

## Four-Tier Security Model

1. **Cryptographic Signing** — ECDSA signature verification (baseline, automatic)
2. **Ephemeral Visual Proof** — Server-rendered PNG with location/device/timestamp (anti-cloning)
3. **Anti-Proxy Detection** — JA3/JA4 TLS fingerprint, latency analysis, canvas fingerprint (anti-MitM)
4. **WebAuthn Passkeys** — Origin-bound hardware-backed authentication (unphishable)

## Testing

80%+ coverage target for security-critical paths: signing, verification, WebAuthn.
