# QRAuth Developer Platform Roadmap

## Phase 0: Minimum Credible Launch

### 0.1 — `@qrauth/node` SDK
- [x] Create `packages/node-sdk/` workspace package with `package.json`, `tsconfig.json`
- [x] Implement `QRAuth` client class (constructor with `apiKey`, `baseUrl`)
- [x] Implement `create()` method (POST /api/v1/qrcodes, duration→datetime translation)
- [x] Implement `verify()` method (GET /api/v1/verify/:token with Accept: application/json)
- [x] Implement `list()`, `get()`, `revoke()`, `bulk()` methods
- [x] Implement typed error classes (QRAuthError, AuthenticationError, RateLimitError, etc.)
- [x] Add TypeScript type exports for all request/response shapes
- [x] Add SDK README with usage examples
- [x] Wire into monorepo workspace, verify `npm run build` works

### 0.2 — OpenAPI Spec + Docs Page
- [x] Write OpenAPI 3.1 spec for core endpoints (create, verify, list, get, revoke, bulk)
- [x] Add authentication section (API key, JWT)
- [x] Host interactive docs at `/docs` (Scalar or Stoplight Elements)
- [x] Add `/docs` proxy route in nginx config

### 0.3 — Port Homepage to React
- [x] Convert homepage.html design to React component (dark navy theme)
- [x] Implement all sections: hero, problem, solution, security tiers, features, protocol, CTA
- [x] Wire nav links (Docs, SDKs, Pricing, Protocol, Get API Key)
- [x] Handle trust bar (remove or soften aspirational logos)
- [x] Ensure responsive design matches the HTML version
- [x] Replace current `home.tsx` with new developer homepage

### 0.4 — API Key Self-Service
- [x] Add backend routes: POST/GET/DELETE `/api/v1/api-keys`
- [x] Create dashboard page `api-keys.tsx` with generate/list/revoke UI
- [x] Show full key once on creation with copy button
- [x] Add API keys link to dashboard navigation

---

## Phase 1: Developer Experience

### 1.1 — Webhook Event Delivery
- [x] Add `WebhookDelivery` model to Prisma schema
- [x] Create `webhookQueue` in queue infrastructure
- [x] Implement webhook worker with HMAC-SHA256 signing
- [x] Emit `qr.created`, `qr.scanned`, `qr.verified` events
- [x] Emit `auth.approved`, `auth.denied` events
- [x] Add delivery retry with exponential backoff (5 attempts, 2s exponential)

### 1.2 — Usage Metering
- [x] Add Redis counters for verifications and QR codes per org per month
- [x] Enforce FREE plan limits (100 QR codes, 1,000 verifications/mo)
- [x] Enforce PRO plan limits (unlimited QR, 50,000 verifications/mo)
- [x] Add `GET /api/v1/usage` endpoint
- [x] Show usage in dashboard (usage page with plan, meters, upgrade CTA)

### 1.3 — Quickstart Guide
- [x] Write quickstart doc (signup → API key → npm install → first QR → scan)
- [x] Host at `/docs/quickstart.html`

### 1.4 — Onboarding Flow Adjustment
- [x] Add "Developer" fast-path to onboarding
- [x] Developer use case → step 3 shows API key generation + quickstart snippet

---

## Phase 2: Platform Maturity

### 2.1 — QRVA Protocol Specification
- [x] Write formal QRVA protocol spec document (12 sections, grounded in implementation)
- [x] Host at `/docs/protocol.html`

### 2.2 — Stripe Billing
- [x] Add `stripeCustomerId`, `stripeSubscriptionId` to Organization model
- [x] Integrate Stripe Checkout for plan upgrades
- [x] Implement Stripe webhook handler (checkout.session.completed, subscription.deleted/updated)
- [x] Add billing routes (POST /checkout, /portal, /webhook)
- [ ] Add pricing page to web app

### 2.3 — Dashboard Developer Pivot
- [x] Usage charts (verification count, QR count over time)
- [x] Webhook delivery logs page
- [ ] "Getting Started" wizard on first login

### 2.4 — Python SDK
- [x] Build `qrauth` PyPI package (thin REST client with httpx)
- [ ] Publish to PyPI

---

## Phase 3: Scale & Differentiation

- [ ] 3.1 — Edge verification (Cloudflare Workers)
- [ ] 3.2 — Go, PHP, Swift, Kotlin SDKs (on demand)
- [ ] 3.3 — White-label verification pages
- [ ] 3.4 — WebAuthn passkey verification
- [ ] 3.5 — Custom domains
