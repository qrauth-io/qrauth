---
title: Authentication
description: JWT, API keys, OAuth2, QR-based auth sessions, PKCE, and multi-tenant roles.
---

# Authentication

QRAuth supports several authentication mechanisms depending on whether you are calling the management API, implementing QR-based sign-in for end users, or running browser-side code with PKCE.

## API key authentication

All server-to-server calls use a static API key issued per organization. Pass it in the `Authorization` header:

```http
Authorization: Bearer sk_live_...
```

API keys are scoped to an organization and inherit the permissions of the creating user's role. Rotate keys from **Settings → API Keys** in the dashboard.

::: warning
API keys grant full organization access. Never expose them in client-side code or public repositories. Use PKCE for browser SDKs.
:::

## JWT authentication

After a successful OAuth2 or QR login, QRAuth issues short-lived JWTs (15 minutes) plus a refresh token (30 days). Include the JWT as a Bearer token on subsequent requests:

```http
Authorization: Bearer eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...
```

The token payload includes:

```json
{
  "sub": "user_01HXYZ...",
  "org": "org_01HABC...",
  "role": "ADMIN",
  "iat": 1744300800,
  "exp": 1744301700
}
```

Refresh tokens are single-use and rotated on every exchange.

## OAuth2 providers

QRAuth supports sign-in via Google, GitHub, Microsoft, and Apple. Redirect the user to the authorization URL:

```
GET https://api.qrauth.io/auth/oauth/:provider
  ?redirect_uri=https://yourapp.com/auth/callback
  &state=<csrf-token>
```

After the provider redirects back, QRAuth exchanges the code internally and redirects to your `redirect_uri` with its own `code` parameter. Exchange that code for tokens:

```typescript
const tokens = await client.authSessions.exchange({
  code,
  redirectUri: 'https://yourapp.com/auth/callback',
})
```

Supported values for `:provider`: `google`, `github`, `microsoft`, `apple`.

## QR-based auth sessions

QR login is QRAuth's primary differentiator. Instead of a password, the user scans a QR code displayed by your application.

### Flow overview

```
1. Your server creates an auth session  →  GET /auth/sessions/:appId/qr
2. QRAuth returns a QR code + session token
3. You display the QR in the browser (or use <qrauth-login>)
4. User scans with their phone
5. QRAuth resolves the session and fires a webhook / SSE event
6. Your server exchanges the session code for tokens
```

### Server-side session creation

```typescript
const session = await client.authSessions.create({
  appId: 'app_01HXYZ...',
  redirectUri: 'https://yourapp.com/auth/callback',
  scopes: ['openid', 'profile', 'email'],
})

// session.qrImageUrl  — display this QR in your UI
// session.sessionToken — poll or listen via SSE for resolution
// session.expiresIn   — seconds until the QR expires (default 120)
```

### Polling for session resolution

If you are not using `<qrauth-login>`, poll the session status endpoint:

```typescript
const result = await client.authSessions.poll(session.sessionToken)

if (result.status === 'completed') {
  const tokens = await client.authSessions.exchange({
    code: result.code,
    redirectUri: 'https://yourapp.com/auth/callback',
  })
}
```

::: tip Server-Sent Events
For real-time updates without polling, connect to `GET /auth/sessions/:token/events`. The `<qrauth-login>` web component does this automatically.
:::

## PKCE for browser SDKs

The `<qrauth-login>` web component and any browser-side code must use **PKCE** (Proof Key for Code Exchange) to prevent authorization code interception. The SDK handles this automatically, but here is the manual flow if you need it:

```typescript
// 1. Generate a code verifier (random, 43-128 chars)
const verifier = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '')

// 2. Derive the code challenge
const encoder = new TextEncoder()
const data = encoder.encode(verifier)
const digest = await crypto.subtle.digest('SHA-256', data)
const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')

// 3. Include in the authorization request
const authUrl = new URL('https://api.qrauth.io/auth/authorize')
authUrl.searchParams.set('app_id', 'app_01HXYZ...')
authUrl.searchParams.set('redirect_uri', 'https://yourapp.com/auth/callback')
authUrl.searchParams.set('code_challenge', challenge)
authUrl.searchParams.set('code_challenge_method', 'S256')

// 4. After redirect, exchange with the verifier
const tokens = await client.authSessions.exchange({
  code,
  redirectUri: 'https://yourapp.com/auth/callback',
  codeVerifier: verifier,
})
```

## Multi-tenant model

QRAuth is multi-tenant. Every resource belongs to an **Organization**. Users join organizations through **Memberships** with one of five roles:

| Role | Permissions |
|------|-------------|
| `OWNER` | Full access including billing, org deletion, and ownership transfer |
| `ADMIN` | Manage members, apps, QR codes, and settings |
| `MANAGER` | Create and manage QR codes and apps; view analytics |
| `MEMBER` | Create QR codes; view own resources |
| `VIEWER` | Read-only access to organization resources |

### Inviting a member

```typescript
await client.organizations.inviteUser({
  email: 'colleague@example.com',
  role: 'MANAGER',
})
```

The invited user receives an email. If they do not have a QRAuth account, they complete a short onboarding flow before the membership is activated.

### Checking the current user's role

The JWT `role` claim contains the user's role in the organization that issued the token. For server-side checks:

```typescript
import { verifyJWT } from '@qrauth/node'

const payload = await verifyJWT(token, { publicKeyUrl: 'https://api.qrauth.io/.well-known/jwks.json' })

if (payload.role !== 'OWNER' && payload.role !== 'ADMIN') {
  throw new Error('Insufficient permissions')
}
```

::: tip Organization context
All SDK methods automatically scope requests to the organization that owns the API key. When a user holds memberships in multiple organizations, the JWT includes the `org` claim to identify the active context.
:::
