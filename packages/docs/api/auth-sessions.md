---
title: Auth Sessions
description: QR-based authentication sessions for third-party websites — PKCE flow, status polling, and result verification.
---

# Auth Sessions

::: warning Legacy sign-in surface — frozen for new public integrations
Auth sessions are QRAuth's legacy sign-in surface, frozen for new public
integrations per [ADR-0004](https://github.com/qrauth-io/qrauth/blob/main/docs/adr/0004-signin-surface-consolidation.md).
New sign-in integrations should use the [OIDC provider](/guide/oidc) at
`https://id.qrauth.io`, which issues standard ID and access tokens from its
`/token` endpoint. Existing integrations keep working.
:::

Auth sessions power QR-based login for third-party websites. Your app displays a QRAuth-generated QR code; the user scans it and approves on the QRAuth hosted page while signed in to QRAuth; your app receives the approved user and an ECDSA signature, which it verifies with [`POST /api/v1/auth-sessions/verify-result`](#verify-result).

## Status Flow

```
PENDING → SCANNED → APPROVED
                 → DENIED
       → EXPIRED
```

| Status | Description |
|--------|-------------|
| `PENDING` | Session created, QR code displayed, awaiting scan |
| `SCANNED` | User's device has scanned the code |
| `APPROVED` | User approved the login on their device |
| `DENIED` | User denied the login on their device |
| `EXPIRED` | TTL elapsed without completion (default: 5 minutes) |

---

## Create Auth Session

`POST /api/v1/auth-sessions`

**Headers:** `Authorization: Basic base64(clientId:clientSecret)` or `X-Client-Id: <id>` (PKCE flows)

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `scopes` | string[] | No | Any of `identity`, `email`, `organization`; must be allowed for the app. Default `["identity"]` |
| `codeChallenge` | string | PKCE | SHA-256 of the `code_verifier`, Base64URL-encoded. Required for public clients |
| `codeChallengeMethod` | string | PKCE | Must be `"S256"` |
| `redirectUrl` | string | No | Where the hosted approval page sends the user after approval. Must match one of the app's registered redirect URLs |
| `metadata` | object | No | Free-form metadata stored with the session |

Sessions expire after a fixed 5 minutes.

**Response (201):**

```json
{
  "sessionId": "cm...",
  "token": "abc123...",
  "qrUrl": "https://qrauth.io/a/abc123...",
  "qrDataUrl": "https://qrauth.io/a/abc123...",
  "qrImageDataUrl": "data:image/png;base64,...",
  "status": "PENDING",
  "scopes": ["identity", "email"],
  "expiresAt": "2026-04-10T12:10:00.000Z"
}
```

Encode `qrUrl` in a QR code, display `qrImageDataUrl` as an `<img>`, or use the Web Components SDK, which handles polling automatically.

---

## Poll Auth Session

`GET /api/v1/auth-sessions/:id`

Poll this endpoint to monitor session status. When status is `APPROVED` the response includes the approved `user` and the approval `signature`.

**Headers:** `Authorization: Basic base64(clientId:clientSecret)` or `X-Client-Id: <id>`

**PKCE verifier:** send the plain-text verifier that hashes to the original
`codeChallenge` in the `X-QRAuth-Code-Verifier` header.

| Header | Type | Required | Description |
|--------|------|----------|-------------|
| `X-QRAuth-Code-Verifier` | string | PKCE | Plain-text verifier that hashes to the original `codeChallenge` |

The `code_verifier` query parameter is still accepted for older integrations,
but a query string is written to proxy and server access logs, so new code
should use the header. The Server-Sent Events endpoint takes the query
parameter only, because `EventSource` cannot set headers.

For a public client polling a PKCE session, `user` and `signature` are `null`
until a valid verifier is sent.

**Response (200) — pending:**

```json
{
  "sessionId": "cm...",
  "status": "PENDING",
  "scopes": ["identity", "email"],
  "user": null,
  "signature": null,
  "expiresAt": "2026-04-10T12:10:00.000Z",
  "scannedAt": null,
  "resolvedAt": null
}
```

**Response (200) — approved:**

```json
{
  "sessionId": "cm...",
  "status": "APPROVED",
  "scopes": ["identity", "email"],
  "user": { "id": "cm...", "name": "Jane Doe", "email": "jane@example.com" },
  "signature": "<base64 signature>",
  "expiresAt": "2026-04-10T12:10:00.000Z",
  "scannedAt": "2026-04-10T12:06:10.000Z",
  "resolvedAt": "2026-04-10T12:06:30.000Z"
}
```

`user.name` is present when the session requested `identity`, `user.email` when it requested `email`. Do not trust the polled result on its own: send `sessionId` and `signature` to your backend and verify them with [`verify-result`](#verify-result).

::: tip Polling interval
Poll every 2 seconds. The `Retry-After` response header on `429` responses indicates when to resume if you poll too aggressively.
:::

---

## Verify Result

`POST /api/v1/auth-sessions/verify-result`

Call this from your backend with the `sessionId` and `signature` your page received. QRAuth verifies the ECDSA-P256 approval signature against your organization's key.

**Headers:** `Authorization: Basic base64(clientId:clientSecret)` (or an API key of your organization)

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `sessionId` | string | Yes | The session ID |
| `signature` | string | Yes | The approval signature |

**Response (200):**

```json
{
  "valid": true,
  "session": {
    "id": "cm...",
    "status": "APPROVED",
    "appName": "Your App",
    "scopes": ["identity", "email"],
    "user": { "id": "cm...", "name": "Jane Doe", "email": "jane@example.com" },
    "signature": "<base64 signature>",
    "resolvedAt": "2026-04-10T12:06:30.000Z"
  }
}
```

With your app's credentials, `valid` is true only for an approved session of your own app. `user` and `signature` are returned only when `valid` is true. The signature stays verifiable for the life of the session; `verify-result` does not consume it.

---

## Approve Auth Session

`POST /api/v1/auth-sessions/:token/approve`

Called by the QRAuth hosted approval page after the user scans the session QR and confirms the login.

**Headers:** `Authorization: Bearer <user-jwt>` (QRAuth platform auth)

::: info Platform-internal
This endpoint is called by the QRAuth platform itself when the signed-in user approves the session. You do not need to call it from your integration.
:::

---

## Deny Auth Session

`POST /api/v1/auth-sessions/:token/deny`

Called by the platform when the user explicitly denies the session on their device.

**Headers:** `Authorization: Bearer <user-jwt>`

**Response (200):**

```json
{
  "status": "DENIED"
}
```
