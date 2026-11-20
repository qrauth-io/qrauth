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

// Search and filter (see List QR Codes in the API reference)
const { data: summer } = await qrauth.list({ q: 'menu', tagIds: [tag.id], folderId: 'unfiled' })
```

`q` matches the label, the destination host of a URL code, a token prefix or a content type. `contentType` filters by content type (ignoring case), `tagIds` returns codes with any of the tags, and `folderId` is a folder id or `'unfiled'`. `outsidePolicy: true` returns the codes marked outside the organization's [allowlist](/api/policies#codes-outside-the-list). List items and `get()` results carry `tags`, `folder` and `outsidePolicy`.

### Tags and folders

[Tags and folders](/api/tags-folders) organize the organization's codes. A VIEWER key can read them but not change them.

```typescript
const tag = await qrauth.createTag({ name: 'Summer', color: 'teal' }) // color: one of TAG_COLORS, default 'grey'
await qrauth.updateTag(tag.id, { name: 'Summer 2027' })
const tags = await qrauth.listTags() // [{ id, name, color, codeCount, createdAt }]
await qrauth.deleteTag(tag.id) // removed from every code

const folder = await qrauth.createFolder('Lobby')
await qrauth.renameFolder(folder.id, 'Front desk')
const { data: folders, unfiledCount } = await qrauth.listFolders()
await qrauth.deleteFolder(folder.id) // its codes become unfiled

// Up to 100 codes per call. Tokens that are not yours are returned in notFound.
const { updated, notFound } = await qrauth.bulkTag(['abc123', 'def456'], { add: [tag.id] })
await qrauth.bulkMove(['abc123'], folder.id) // null makes the codes unfiled
```

A duplicate name, or an organization at its limit (100 tags, 200 folders), throws `ConflictError` with `reason` `'name-taken'` or `'limit-reached'`.

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

### `getHistory(token, options?)`

A code's [edit history](/api/qrcodes#edit-history), newest first: one revision per change to its destination, content, style, expiry, scan mode or status. Every role can read it.

```typescript
const history = await qrauth.getHistory('abc123', { page: 1, pageSize: 50 })

for (const rev of history.data) {
  const who =
    rev.actor.type === 'USER' ? rev.actor.email
    : rev.actor.type === 'API_KEY' ? rev.actor.label
    : rev.actor.id
  console.log(rev.revision, rev.kind, who, Object.keys(rev.changes))
}
// history.total, history.page, history.pageSize, history.totalPages
```

Each `QRCodeRevision` has `revision`, `kind` (`'BASELINE' | 'CREATED' | 'UPDATED' | 'RESTORED' | 'REVOKED'`), `createdAt`, `changes` (each changed field as `{ before, after }`), `actor` (`USER`, `API_KEY` or `SYSTEM`), `requestId` and `restoredFrom`. `pageSize` defaults to 20, max 100. Another organization's code throws `NotFoundError`.

### `restoreDestination(token, revision)`

[Restores](/api/qrcodes#restore-a-destination) the destination (URL codes) or content (other types) the code had right after `revision`. The value must meet the current rules; the code is re-signed and a `RESTORED` revision is recorded. Returns the updated code (`UpdatedQRCode`). Needs an OWNER, ADMIN or MANAGER key.

```typescript
const qr = await qrauth.restoreDestination('abc123', 1)
```

A value that is already current, a revoked code, or a value no longer in the history throws a `QRAuthError` with `statusCode` 409; a value that no longer meets the rules, or a flagged destination, has `statusCode` 422. The API's message says which.

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
| `domain_warning` | `{ message, similar_to, verified_org, similarity, reason? }` when the destination is a lookalike of another organization's verified domain or a protected brand; `reason` is `'confusable'`, `'mixed_script'` or an edit-distance reason |

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

## Audit Log

Your organization's [audit log](/api/audit-log), newest first. Needs an OWNER or ADMIN key and the Business plan or above.

### `listAuditEntries(params?)`

One page. Filters: `actor`, `actorType` (`'USER' | 'API_KEY' | 'SYSTEM' | 'SUPERADMIN'`), `action`, `resourceType`, `resourceId`, `from` and `to` (a `Date` or an ISO 8601 string); paging: `cursor` and `limit` (1–100, default 50).

```typescript
const page = await qrauth.listAuditEntries({ action: 'apiKey.revoke', limit: 20 })

for (const entry of page.data) {
  console.log(entry.createdAt, entry.label, entry.actor.type, entry.ipAddress)
}
if (page.nextCursor) {
  const older = await qrauth.listAuditEntries({ action: 'apiKey.revoke', cursor: page.nextCursor })
}
```

Each `AuditEntry` has `id`, `source` (`'audit' | 'qr_revision'`), `action`, `label`, `resourceType`, `resourceId`, `resourceName`, `actor` (`AuditActorView`), `createdAt`, `requestId`, `ipAddress`, `userAgent`, `metadata` and, for QR code changes, `changes` (each field as `{ before, after }`).

### `iterateAuditEntries(params?)`

Every matching entry, fetching pages as it goes. Takes the same params; `limit` sets the page size.

```typescript
for await (const entry of qrauth.iterateAuditEntries({ actorType: 'API_KEY', from: new Date('2026-10-01') })) {
  console.log(entry.createdAt, entry.action)
}
```

### `exportAuditCsv(params)`

The matching entries as [CSV](/api/audit-log#csv-export) text, with the same filters (no `cursor` or `limit`). `from` and `to` are required; one export holds at most 100,000 entries.

```typescript
import { writeFile } from 'node:fs/promises'

await writeFile('audit.csv', await qrauth.exportAuditCsv({ from: '2026-10-01T00:00:00Z', to: '2026-10-31T23:59:59Z' }))
```

A key whose role is not OWNER or ADMIN gets an `AuthorizationError` with `reason` `'audit-role-required'`; a plan below Business, `reason` `'governance-plan-required'`.

---

## Organization Policies

The [destination allowlist and destination-edit role](/api/policies). Needs an OWNER or ADMIN key; changing a policy needs the Business plan or above.

### `getPolicy()`

```typescript
const policy = await qrauth.getPolicy()
// { allowlistMode: 'ENFORCE', allowlist: [{ domain: 'example.com', includeSubdomains: true, unicode: 'example.com' }], destinationEditMinRole: 'MANAGER', outsidePolicyCount: 1, ... }
```

### `previewPolicy(allowlist)`

How a list would be stored and which active codes it would leave outside; changes nothing.

```typescript
const preview = await qrauth.previewPolicy([{ domain: 'www.example.com' }])
console.log(preview.allowlist[0].domain, preview.affectedTotal) // 'example.com', 3
```

### `updatePolicy(options)`

Replaces the policy (all three fields) and returns it.

```typescript
await qrauth.updatePolicy({
  allowlistMode: 'ENFORCE',
  allowlist: [{ domain: 'example.com' }, { domain: 'münchen.de', includeSubdomains: false }],
  destinationEditMinRole: 'MANAGER',
})
```

An invalid entry is a `QRAuthError` with `statusCode` 422 and nothing changes. Below the Business plan only switching off is accepted; anything else is an `AuthorizationError` with `reason` `'governance-plan-required'`.

With the allowlist enforced, `create()`, `bulk()` and `restoreDestination()` refuse a destination outside it: `create()` and `restoreDestination()` throw a `QRAuthError` with `statusCode` 422 whose message names the allowed domains, and a `bulk()` item fails with `errorCode` `'DESTINATION_NOT_ALLOWED'`. Below the minimum role, `restoreDestination()` throws an `AuthorizationError` with `reason` `'destination-edit-role-required'`. A key acts with the lower of its own role and its owner's current role, so under a minimum above `MEMBER` it needs a `MANAGER` or `ADMIN` role, chosen when the key is created in the dashboard. Legacy keys (created before keys recorded an owner) cannot change destinations under such a minimum; rotate them on the API Keys page.

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
  ConflictError,
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
| `AuthorizationError` | 403 | Insufficient permissions — `err.reason` carries the API's `code` when it sends one, e.g. `'governance-plan-required'` |
| `NotFoundError` | 404 | Resource not found |
| `ConflictError` | 409 | Conflict — `err.reason` carries the API's `code`, e.g. `'name-taken'` |
| `RateLimitError` | 429 | Rate limit exceeded — check `err.retryAfter` |
| `QRAuthError` | any | Base class for all SDK errors; other statuses are thrown as `QRAuthError` |

Every error has `err.requestId`: the API's [`X-Request-Id`](/api/overview#request-ids) for the failed request, when the API sent one. Log it, and quote it when contacting support.
