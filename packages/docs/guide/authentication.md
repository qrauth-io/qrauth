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
1. Browser (or your server) creates an auth session
       → POST /api/v1/auth-sessions
2. QRAuth returns { sessionId, token, qrUrl, expiresAt }
3. The page renders the QR (or <qrauth-login> does it for you)
4. User scans with their phone (or, on mobile, taps "Continue with QRAuth")
5. User signs in and approves on the QRAuth hosted page (/a/:token)
6. Polling / SSE / URL-callback delivers { sessionId, signature } to your app
7. Your server calls `verifyAuthResult(sessionId, signature)` against
   QRAuth, gets back the verified user payload, and mints its own session
```

### Server-side session creation

```typescript
import { QRAuth } from '@qrauth/node';

const qrauth = new QRAuth({ apiKey: process.env.QRAUTH_API_KEY });

const session = await qrauth.createAuthSession({
  scopes: ['identity', 'email'],
  // Optional — required for the mobile flow's hosted-page redirect to work.
  // Must match an entry in the app's registered redirectUrls.
  redirectUrl: 'https://yourapp.com/dashboard/',
});

// session.token       — embed in the QR (or use the `qrUrl` field as-is)
// session.qrUrl       — fully-qualified `https://qrauth.io/a/<token>`
// session.expiresAt   — ISO timestamp; default lifetime is 5 minutes
// session.sessionId   — primary key; use to poll status
```

### Polling for session resolution

If you are not using `<qrauth-login>`, poll the session status endpoint:

```typescript
const status = await qrauth.getAuthSession(session.sessionId, { codeVerifier });

if (status.status === 'APPROVED') {
  const result = await qrauth.verifyAuthResult(status.sessionId, status.signature);
  // result.user is the verified payload — { id, name?, email? }
  // depending on which scopes the session requested.
}
```

::: tip Server-Sent Events
For real-time updates without polling, connect to `GET /api/v1/auth-sessions/:id/sse`. The `<qrauth-login>` web component handles this automatically.
:::

### URL-callback flow (for the mobile path)

When the user completes Approve on the hosted approval page, QRAuth navigates them to the registered `redirectUrl` with two query params appended:

```
https://yourapp.com/dashboard/?qrauth_session_id=cmoxxx&qrauth_signature=base64sig
```

This means **your landing page can complete the sign-in entirely from URL params** — no dependency on any other tab being alive (a critical property for mobile, where the original tab is often suspended by the OS while the user is on qrauth.io).

```ts
// Run on every route mount, e.g. inside your auth provider's useEffect:
async function completeFromUrlIfPresent() {
  const url = new URL(window.location.href);
  const sessionId = url.searchParams.get('qrauth_session_id');
  const signature = url.searchParams.get('qrauth_signature');
  if (!sessionId || !signature) return;

  await fetch('/api/auth/qrauth-callback', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sessionId, signature }),
  });

  // Scrub the params so a refresh can't replay the consumed signature.
  url.searchParams.delete('qrauth_session_id');
  url.searchParams.delete('qrauth_signature');
  window.history.replaceState({}, '', url.pathname + url.search + url.hash);
}
```

Your `/api/auth/qrauth-callback` endpoint calls `verifyAuthResult(sessionId, signature)`, gets the verified user, mints your own session JWT, returns it.

The signature in the URL is **one-time-use** — `verifyAuthResult` consumes it and the session transitions to RESOLVED. Same risk profile as an OAuth `code` parameter.

## PKCE for browser SDKs

The `<qrauth-login>` web component uses **PKCE** (Proof Key for Code Exchange) automatically. Manual flow if you need it:

```typescript
// 1. Generate a code_verifier (random, 43-128 chars, base64url-safe alphabet).
const bytes = new Uint8Array(32);
crypto.getRandomValues(bytes);
const verifier = btoa(String.fromCharCode(...bytes))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// 2. Derive the code_challenge.
const encoder = new TextEncoder();
const digest = await crypto.subtle.digest('SHA-256', encoder.encode(verifier));
const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// 3. Send code_challenge + S256 method on session creation.
const res = await fetch('https://yourapp.com/api/v1/auth-sessions', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-Client-Id': 'qrauth_app_xxx',
  },
  body: JSON.stringify({
    scopes: ['identity', 'email'],
    codeChallenge: challenge,
    codeChallengeMethod: 'S256',
    redirectUrl: 'https://yourapp.com/dashboard/',
  }),
});
const { sessionId, token, qrUrl } = await res.json();

// 4. Display the QR (or use <qrauth-login>), poll for APPROVED.

// 5. When polling returns APPROVED, send code_verifier on the GET to prove
//    you are the original session creator before reading the signature.
const url = new URL(`https://yourapp.com/api/v1/auth-sessions/${sessionId}`);
url.searchParams.set('code_verifier', verifier);
const status = await fetch(url, { headers: { 'X-Client-Id': 'qrauth_app_xxx' } });
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
