---
title: Auth Sessions
description: QR-based authentication sessions for third-party websites — PKCE flow, status polling, and token exchange.
---

# Auth Sessions

Auth sessions power QR-based login for third-party websites. Your app displays a QRAuth-generated QR code; the user scans it on their registered device; your app receives an authorization code to exchange for tokens.

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
| `scopes` | string[] | Yes | Requested permission scopes, e.g. `["openid", "profile", "email"]` |
| `codeChallenge` | string | PKCE | SHA-256 of the `code_verifier`, Base64URL-encoded |
| `codeChallengeMethod` | string | PKCE | Must be `"S256"` |
| `redirectUri` | string | No | Override the App's registered redirect URI for this session |
| `ttl` | number | No | Session lifetime in seconds (default: 300, max: 600) |

**Response (201):**

```json
{
  "id": "as_01HXYZ...",
  "status": "PENDING",
  "qrCode": {
    "token": "abc123",
    "qr_image_url": "https://qrauth.io/api/v1/qrcodes/abc123/image",
    "verificationUrl": "https://qrauth.io/v/abc123"
  },
  "scopes": ["openid", "profile", "email"],
  "expiresAt": "2026-04-10T12:10:00Z",
  "createdAt": "2026-04-10T12:05:00Z"
}
```

Display `qrCode.qr_image_url` as an `<img>` tag or use the Web Components SDK which handles polling automatically.

---

## Poll Auth Session

`GET /api/v1/auth-sessions/:id`

Poll this endpoint to monitor session status. When status is `APPROVED` the response includes an authorization `code` for token exchange.

**Headers:** `Authorization: Basic base64(clientId:clientSecret)` or `X-Client-Id: <id>`

**Query parameters (PKCE only):**

| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `code_verifier` | string | PKCE | Plain-text verifier that hashes to the original `codeChallenge` |

**Response (200) — pending:**

```json
{
  "id": "as_01HXYZ...",
  "status": "PENDING",
  "expiresAt": "2026-04-10T12:10:00Z"
}
```

**Response (200) — approved:**

```json
{
  "id": "as_01HXYZ...",
  "status": "APPROVED",
  "code": "eyJhbGc...",
  "expiresAt": "2026-04-10T12:10:00Z",
  "approvedAt": "2026-04-10T12:06:30Z"
}
```

Exchange `code` immediately — authorization codes are single-use and expire after 60 seconds.

::: tip Polling interval
Poll every 2 seconds. The `Retry-After` response header on `429` responses indicates when to resume if you poll too aggressively.
:::

---

## Approve Auth Session

`POST /api/v1/auth-sessions/:id/approve`

Called by the QRAuth mobile app or a trusted device after the user scans the session QR and confirms the login.

**Headers:** `Authorization: Bearer <user-jwt>` (QRAuth platform auth)

**Response (200):**

```json
{
  "id": "as_01HXYZ...",
  "status": "APPROVED"
}
```

::: info Platform-internal
This endpoint is called by the QRAuth platform itself when a registered device approves the session. You do not need to call it from your integration.
:::

---

## Deny Auth Session

`POST /api/v1/auth-sessions/:id/deny`

Called by the platform when the user explicitly denies the session on their device.

**Headers:** `Authorization: Bearer <user-jwt>`

**Response (200):**

```json
{
  "id": "as_01HXYZ...",
  "status": "DENIED"
}
```

---

## Token Exchange

Authorization codes are exchanged for access tokens using the standard OAuth2 token endpoint:

`POST /api/v1/auth-sessions/token`

**Headers:** `Authorization: Basic base64(clientId:clientSecret)` or `X-Client-Id: <id>` (PKCE)

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `grant_type` | string | Yes | `"authorization_code"` |
| `code` | string | Yes | The authorization code from the approved session |
| `redirect_uri` | string | Yes | Must match the registered or session-level redirect URI |
| `code_verifier` | string | PKCE | Required for PKCE flows |

**Response (200):**

```json
{
  "access_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "id_token": "eyJhbGc...",
  "scope": "openid profile email"
}
```
