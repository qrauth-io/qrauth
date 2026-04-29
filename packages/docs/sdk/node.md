---
title: Node.js SDK
description: Official Node.js / TypeScript SDK for the QRAuth API.
---

# Node.js SDK

The `@qrauth/node` package is the official server-side SDK for Node.js and TypeScript. It wraps every QRAuth API endpoint with typed methods and consistent error handling.

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

Requires Node.js 18+.

## Initialization

```typescript
import QRAuth from '@qrauth/node'

// API key only (QR management, verification)
const client = new QRAuth({
  apiKey: process.env.QRAUTH_API_KEY,
})

// API key + OAuth2 client credentials (auth sessions)
const client = new QRAuth({
  apiKey: process.env.QRAUTH_API_KEY,
  clientId: process.env.QRAUTH_CLIENT_ID,
  clientSecret: process.env.QRAUTH_CLIENT_SECRET,
})
```

The base URL defaults to `https://qrauth.io/api/v1`. Override it for testing:

```typescript
const client = new QRAuth({
  apiKey: '...',
  baseUrl: 'http://localhost:3000/api/v1',
})
```

---

## QR Codes

### `qrcodes.create(params)`

```typescript
const qr = await client.qrcodes.create({
  label: 'Product A — Shelf 4B',
  contentType: 'url',
  content: { url: 'https://example.com/product' },
  location: { lat: 52.52, lng: 13.405, radiusM: 50 },
  expiresAt: '2027-01-01T00:00:00Z',
})

console.log(qr.id)            // qr_01HXYZ...
console.log(qr.qr_image_url)  // PNG image URL
console.log(qr.token)         // short token for the verify URL
```

### `qrcodes.list(params?)`

```typescript
const { data, pagination } = await client.qrcodes.list({
  status: 'active',
  contentType: 'url',
  page: 1,
  limit: 50,
})
```

### `qrcodes.get(token)`

```typescript
const qr = await client.qrcodes.get('abc123')
```

### `qrcodes.update(token, params)`

```typescript
const updated = await client.qrcodes.update('abc123', {
  label: 'Updated label',
  content: { url: 'https://example.com/new-url' },
})
```

### `qrcodes.revoke(token)`

```typescript
await client.qrcodes.revoke('abc123')
```

### `qrcodes.bulkCreate(codes)`

```typescript
const result = await client.qrcodes.bulkCreate([
  { label: 'Code 1', contentType: 'url', content: { url: 'https://example.com/1' } },
  { label: 'Code 2', contentType: 'url', content: { url: 'https://example.com/2' } },
])

console.log(result.created) // 2
```

---

## Verification

### `verify(token, options?)`

```typescript
const result = await client.verify('abc123', {
  clientLat: 52.52,
  clientLng: 13.405,
})

if (result.verified && result.security.trustScore >= 0.8) {
  console.log('Trusted scan')
} else {
  console.warn('Suspicious:', result.security.signals)
}
```

---

## Auth Sessions

### `authSessions.create(params)`

```typescript
const session = await client.authSessions.create({
  scopes: ['openid', 'profile', 'email'],
  codeChallenge: challenge,
  codeChallengeMethod: 'S256',
})

// Display session.qrCode.qr_image_url and poll for completion
```

### `authSessions.get(id, options?)`

```typescript
const session = await client.authSessions.get('as_01HXYZ...', {
  codeVerifier: verifier, // include for PKCE
})

if (session.status === 'APPROVED') {
  const tokens = await client.authSessions.exchange({
    code: session.code!,
    redirectUri: 'https://yourapp.com/callback',
    codeVerifier: verifier,
  })
}
```

---

## Ephemeral Sessions

### `ephemeral.create(params)`

```typescript
const session = await client.ephemeral.create({
  scopes: ['door:unlock'],
  ttl: '1h',
  maxUses: 1,
  deviceBinding: false,
  metadata: { zone: 'B2' },
})
```

### `ephemeral.list(params?)`

```typescript
const { data } = await client.ephemeral.list({ status: 'PENDING' })
```

### `ephemeral.get(id)`

```typescript
const session = await client.ephemeral.get('es_01HXYZ...')
```

### `ephemeral.claim(token, params?)`

```typescript
const claim = await client.ephemeral.claim('eph_tok_...', {
  deviceFingerprint: 'fp_abc...',
})

console.log(claim.jwt) // Bearer token scoped to the session's scopes
```

### `ephemeral.revoke(id)`

```typescript
await client.ephemeral.revoke('es_01HXYZ...')
```

---

## Proximity

### `proximity.getAttestation(token, coords)`

```typescript
const attestation = await client.proximity.getAttestation('abc123', {
  clientLat: 52.52,
  clientLng: 13.405,
})

console.log(attestation.jwt)
console.log(attestation.claims.proximity.matched) // true
console.log(attestation.claims.proximity.distanceM) // 14
```

### `proximity.verifyAttestation(params)`

```typescript
const result = await client.proximity.verifyAttestation({
  jwt: attestation.jwt,
  publicKey: attestation.publicKey, // optional
})

console.log(result.valid) // true
```

---

## Error Handling

All methods throw typed errors on failure. Import the error classes to distinguish error types:

```typescript
import QRAuth, {
  QRAuthError,
  AuthenticationError,
  NotFoundError,
  RateLimitError,
  ValidationError,
} from '@qrauth/node'

try {
  const qr = await client.qrcodes.get('unknown-token')
} catch (err) {
  if (err instanceof NotFoundError) {
    console.log('QR code not found')
  } else if (err instanceof RateLimitError) {
    console.log('Rate limited, retry after:', err.retryAfter, 's')
  } else if (err instanceof AuthenticationError) {
    console.log('Invalid API key')
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
| `AuthenticationError` | 401 | Missing or invalid credentials |
| `ForbiddenError` | 403 | Insufficient permissions |
| `NotFoundError` | 404 | Resource not found |
| `ConflictError` | 409 | Duplicate resource or already-claimed session |
| `ValidationError` | 400 / 422 | Request body failed validation |
| `RateLimitError` | 429 | Rate limit exceeded — check `err.retryAfter` |
| `QRAuthError` | any | Base class for all SDK errors |
