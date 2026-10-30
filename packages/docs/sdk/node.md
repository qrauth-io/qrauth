---
title: Node.js SDK
description: Official Node.js / TypeScript SDK for the QRAuth API.
---

# Node.js SDK

::: warning Legacy sign-in integration — frozen for new public integrations
The SDK's QR-based **AuthSession** login methods (`createAuthSession`,
`getAuthSession`, `verifyAuthResult`, `authSessionHandlers`) are **frozen for
new public integrations** — new sign-in
integrations should use the [OIDC provider](/guide/oidc), QRAuth's certified,
standards-based sign-in surface. The SDK's other methods (QR codes, ephemeral
access, proximity, verification) are unaffected. Existing integrations keep
working.
:::

The `@qrauth/node` package is the official server-side SDK for Node.js and TypeScript. It wraps the QRAuth API with typed methods and consistent error handling.

## Installation

::: code-group

```bash [npm]
npm install @qrauth/node
```

```bash [yarn]
yarn add @qrauth/node
```

```bash [pnpm]
pnpm add @qrauth/node
```

:::

Requires Node.js 18+. Current version: **0.4.0** on [npm](https://www.npmjs.com/package/@qrauth/node).

## Initialization

```typescript
import { QRAuth } from '@qrauth/node'

// API key only (QR management, verification, proximity, ephemeral claim)
const qrauth = new QRAuth({
  apiKey: process.env.QRAUTH_API_KEY,
})

// App client credentials (auth sessions, ephemeral session management)
const qrauth = new QRAuth({
  clientId: process.env.QRAUTH_CLIENT_ID,
  clientSecret: process.env.QRAUTH_CLIENT_SECRET,
})

// Both
const qrauth = new QRAuth({
  apiKey: process.env.QRAUTH_API_KEY,
  clientId: process.env.QRAUTH_CLIENT_ID,
  clientSecret: process.env.QRAUTH_CLIENT_SECRET,
})
```

At least one of `apiKey` or `clientId` is required. API-key methods send the `X-API-Key` header; client-credential methods send `Authorization: Basic base64(clientId:clientSecret)`.

The base URL defaults to `https://qrauth.io`. Override it for testing:

```typescript
const qrauth = new QRAuth({
  apiKey: '...',
  baseUrl: 'http://localhost:3000',
})
```

---

## QR Codes

### `create(options)`

```typescript
const qr = await qrauth.create({
  destination: 'https://example.com/product',
  label: 'Product A — Shelf 4B',
  location: { lat: 52.52, lng: 13.405, radiusM: 50 },
  expiresIn: '1y', // duration ('30d', '6h') or ISO 8601 datetime
})

console.log(qr.token)         // token for the verify URL
console.log(qr.qr_image_url)  // PNG image URL
```

For non-URL content types pass `contentType` and `content`.

### `list(options?)`

```typescript
const { data, total, page, pageSize, totalPages } = await qrauth.list({
  status: 'ACTIVE',
  page: 1,
  pageSize: 50,
})
```

### `get(token)`

```typescript
const qr = await qrauth.get('abc123')
```

### `image(token, options?)`

Downloads the code drawn with its stored style ([Get QR Code Image](/api/qrcodes#get-qr-code-image)): PNG or SVG at a screen size, or a print-size PNG or vector PDF.

```typescript
import { writeFile } from 'node:fs/promises'

const png = await qrauth.image('abc123', { px: 600 })                       // screen PNG, 600 px
const print = await qrauth.image('abc123', { sizeMm: 50, dpi: 300 })        // 50 mm at 300 dpi
const pdf = await qrauth.image('abc123', { format: 'pdf', sizeMm: 50, marginMm: 3 })

await writeFile(pdf.filename ?? 'code.pdf', pdf.data)
```

The result is a `QRCodeImage`: `data` (a `Buffer`), `contentType`, `etag`, `filename` (the API's suggested name) and, for PNG, `px` (the width rendered). Options (`QRCodeImageOptions`): `format` (`'png'`, `'svg'` or `'pdf'`), `px` (64–1024), `sizeMm` (10–1000) or `sizeIn` (0.4–39.37), `dpi` (72–1200, PNG) and `marginMm` (0–50, PDF). `px` and the print options cannot be combined. Print-size PNG and PDF need a paid plan (`AuthorizationError` on the Free plan); a size whose modules would be under 0.4 mm is refused with status 422, and a PNG above 12,000 pixels per side or 100 megapixels with a `ValidationError`.

### `revoke(token)`

```typescript
await qrauth.revoke('abc123')
```

### `bulk(items)`

Up to 64 items per call.

```typescript
const result = await qrauth.bulk([
  { destination: 'https://example.com/1', label: 'Code 1' },
  { destination: 'https://example.com/2', label: 'Code 2' },
])

console.log(result.summary.succeeded) // 2
// result.summary: { total, succeeded, failed }
// result.results: one entry per item, in order; failed entries carry error and errorCode
```

### Algorithm versions

The package exports `ALG_VERSIONS` (`HYBRID_ECDSA_SLHDSA_V1` = `'hybrid-ecdsa-slhdsa-v1'`, `SLHDSA_SHA2_128S_V1` = `'slhdsa-sha2-128s-v1'`, `SLHDSA_SHA2_256S_V1` = `'slhdsa-sha2-256s-v1'`) and `isAlgDeprecated(algVersion)`, which reports whether a version is on the deprecation list.

---

## Verification

### `verify(token, options?)`

```typescript
const result = await qrauth.verify('abc123', {
  clientLat: 52.52,
  clientLng: 13.405,
})

switch (result.trust_state) {
  case 'VERIFIED':
    // Authentic, and QRAuth has verified the issuer.
    if (result.organization.verified) {
      console.log('Issued by', result.organization.name, result.organization.verified_domain)
    }
    break
  case 'SIGNED_UNVERIFIED_ISSUER':
    // Authentic, but the issuer is not verified by QRAuth. No issuer name is returned.
    console.log('Destination:', result.destination_url)
    break
  case 'UNTRUSTED':
    // Revoked, expired, flagged, lookalike destination, invalid signature, ...
    console.warn('Not trusted:', result.reason)
    break
}
```

The result is typed as `VerificationResult`; the package also exports `TrustState` and `VerificationOrganization`:

```typescript
import type { TrustState, VerificationResult } from '@qrauth/node'
```

| Field | Notes |
|---|---|
| `trust_state` | `'VERIFIED' \| 'SIGNED_UNVERIFIED_ISSUER' \| 'UNTRUSTED'`. See [Trust state](/api/verification#trust-state) |
| `verified` | `true` only when `trust_state` is `'VERIFIED'`. Kept for compatibility; switch on `trust_state` |
| `organization` | `{ verified: true, name, verified_domain? }` for `VERIFIED`, otherwise `{ verified: false }`. Narrow on `organization.verified` before reading `name` |
| `destination_url` | Optional: absent from failure responses (revoked, expired, scan limit, suspended issuer, flagged destination) |
| `reason` | Optional explanation on many `UNTRUSTED` results |
| `domain_warning` | `{ message, similar_to, verified_org, similarity }` when the destination resembles another organization's verified domain |

`security.trustScore` is a heuristic score from 0 to 100.

---

## Auth Sessions

Requires `clientId` and `clientSecret`. Legacy surface; see the notice above.

### `createAuthSession(options?)`

```typescript
const session = await qrauth.createAuthSession({
  scopes: ['identity', 'email'],
  redirectUrl: 'https://yourapp.com/dashboard/', // must be registered on the app
})

// session.qrUrl — encode in a QR code
// session.sessionId — use to poll or verify
```

### `getAuthSession(sessionId, options?)`

```typescript
const status = await qrauth.getAuthSession(session.sessionId, {
  codeVerifier: verifier, // include for PKCE sessions
})
```

### `verifyAuthResult(sessionId, signature)`

```typescript
const result = await qrauth.verifyAuthResult(sessionId, signature)

if (result.valid) {
  const user = result.session.user // { id, name?, email? }
  // issue your own session for the user
}
```

### `authSessionHandlers()`

Returns `createSession(body)`, `getSession(sessionId, query?)` and `verifyResult(sessionId, signature)` helpers that forward requests to QRAuth with your client credentials and return `{ status, body }`, for building the backend proxy used by the web components.

---

## Ephemeral Sessions

### `createEphemeralSession(options)`

Requires `clientId` and `clientSecret`.

```typescript
const session = await qrauth.createEphemeralSession({
  scopes: ['door:unlock'],
  ttl: '1h',
  maxUses: 1,
  deviceBinding: false,
  metadata: { zone: 'B2' },
})

// session.claimUrl — encode in a QR code
```

### `listEphemeralSessions(options?)`

```typescript
const { data } = await qrauth.listEphemeralSessions({ status: 'PENDING' })
```

### `claimEphemeralSession(token, options?)`

```typescript
const claim = await qrauth.claimEphemeralSession('eph_tok_...', {
  deviceFingerprint: 'fp_abc...',
})

console.log(claim.scopes, claim.useCount)
```

Returns the session's `sessionId`, `status`, `scopes`, `metadata`, `expiresAt`, `useCount` and `maxUses`. No token is issued.

### `revokeEphemeralSession(sessionId)`

```typescript
await qrauth.revokeEphemeralSession('cm...')
```

---

## Proximity

### `getProximityAttestation(token, args)`

```typescript
const attestation = await qrauth.getProximityAttestation('abc123', {
  clientLat: 52.52,
  clientLng: 13.405,
  rpId: 'yourapp.com',          // relying-party identifier, becomes the `aud` claim
  deviceFingerprint: 'fp_abc...', // hashed into the `device` claim
})

console.log(attestation.jwt)
console.log(attestation.claims) // includes proximity: { matched, distanceM, radiusM }
console.log(attestation.keyId)
```

All four arguments are required. The result contains `jwt`, `claims`, `publicKey` and `keyId`. A proximity attestation states that the device reported a location within the stated distance of the QR code's registered location, signed by the issuing organization. The location is reported by the client; the attestation is not proof of physical presence.

### `verifyProximityAttestation(jwt, publicKey?)`

```typescript
const result = await qrauth.verifyProximityAttestation(attestation.jwt, orgPublicKeyPem)

if (result.valid) {
  console.log(result.claims)
}
```

This calls the QRAuth API (`POST /api/v1/proximity/verify`); it does not verify offline. Pass the issuing organization's public key that you have obtained and stored independently, not the `publicKey` returned alongside the attestation, and check `iss`, `aud` and `proximity.matched` in the returned claims.

---

## Error Handling

All methods throw typed errors on API failure. Import the error classes to distinguish error types:

```typescript
import {
  QRAuth,
  QRAuthError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  RateLimitError,
  ValidationError,
} from '@qrauth/node'

try {
  const qr = await qrauth.get('unknown-token')
} catch (err) {
  if (err instanceof NotFoundError) {
    console.log('QR code not found')
  } else if (err instanceof RateLimitError) {
    console.log('Rate limited, retry after:', err.retryAfter, 's')
  } else if (err instanceof AuthenticationError) {
    console.log('Invalid credentials')
  } else if (err instanceof ValidationError) {
    console.log('Validation failed:', err.message)
  } else if (err instanceof QRAuthError) {
    console.log('API error:', err.statusCode, err.message)
  } else {
    throw err // unexpected
  }
}
```

| Class | HTTP status | Description |
|-------|-------------|-------------|
| `ValidationError` | 400 | Request failed validation |
| `AuthenticationError` | 401 | Missing or invalid credentials |
| `AuthorizationError` | 403 | Insufficient permissions |
| `NotFoundError` | 404 | Resource not found |
| `RateLimitError` | 429 | Rate limit exceeded — check `err.retryAfter` |
| `QRAuthError` | any | Base class for all SDK errors; other statuses are thrown as `QRAuthError` |
