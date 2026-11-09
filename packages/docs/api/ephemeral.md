---
title: Ephemeral Sessions
description: Time-limited, scope-constrained access sessions — no account creation required.
---

# Ephemeral Sessions

Ephemeral sessions grant temporary, scoped access without requiring end users to have a QRAuth account. A developer creates a session server-side, encodes it in a QR code, and distributes it. When a device claims the session, the claim response returns the granted scopes and metadata, and your backend learns of the claim through the `ephemeral.claimed` webhook or by polling. QRAuth issues no token on claim; your application enforces the access it grants.

## Status Flow

```
PENDING → CLAIMED
        → EXPIRED
        → REVOKED
```

| Status | Description |
|--------|-------------|
| `PENDING` | Session created, not yet claimed |
| `CLAIMED` | A device has successfully claimed the session |
| `EXPIRED` | TTL elapsed before the session was claimed |
| `REVOKED` | Manually revoked before expiry |

---

## Create Ephemeral Session

`POST /api/v1/ephemeral`

**Headers:** `X-API-Key: <key>`

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `scopes` | string[] | Yes | Access scopes granted on claim, e.g. `["storage:read", "door:unlock"]` |
| `ttl` | string | No | Whole number plus unit `s`, `m`, `h` or `d`, e.g. `"5m"`, `"1h"`, `"2d"`. Default `"30m"`, maximum 72 hours; longer values are capped at 72 hours. |
| `maxUses` | number | No | Maximum number of claims (default: 1) |
| `deviceBinding` | boolean | No | Bind the claim to the first device fingerprint presented (default: false) |
| `metadata` | object | No | Arbitrary key-value pairs stored with the session |

**Response (201):**

```json
{
  "id": "es_01HXYZ...",
  "token": "eph_tok_...",
  "status": "PENDING",
  "scopes": ["door:unlock"],
  "ttl": "1h",
  "maxUses": 1,
  "usesRemaining": 1,
  "deviceBinding": false,
  "metadata": { "zone": "B2", "reason": "contractor-access" },
  "qr_image_url": "https://qrauth.io/api/v1/ephemeral/eph_tok_.../image",
  "claimUrl": "https://qrauth.io/claim/eph_tok_...",
  "expiresAt": "2026-04-10T13:05:00Z",
  "createdAt": "2026-04-10T12:05:00Z"
}
```

Embed `qr_image_url` as a QR code or direct users to `claimUrl` directly.

---

## List Ephemeral Sessions

`GET /api/v1/ephemeral`

**Headers:** `X-API-Key: <key>`

**Query parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `status` | string | Filter by `PENDING`, `CLAIMED`, `EXPIRED`, or `REVOKED` |
| `page` | number | Page number (default: 1) |
| `limit` | number | Results per page (default: 20, max: 100) |

**Response (200):**

```json
{
  "data": [
    {
      "id": "es_01HXYZ...",
      "status": "CLAIMED",
      "scopes": ["door:unlock"],
      "usesRemaining": 0,
      "expiresAt": "2026-04-10T13:05:00Z",
      "claimedAt": "2026-04-10T12:07:22Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 5,
    "totalPages": 1
  }
}
```

---

## Get Ephemeral Session

`GET /api/v1/ephemeral/:id`

**Headers:** `X-API-Key: <key>`

**Response (200):** The session's status, scopes, limits and timestamps (`claimedAt`, `revokedAt`, `expiresAt`, `createdAt`).

::: warning
`token` and `claimUrl` are returned only by the create response. They are bearer secrets, so neither list nor get returns them. Store the `claimUrl` when you create the session if you need to show it again.
:::

---

## Claim Ephemeral Session

`POST /api/v1/ephemeral/:token/claim`

This endpoint is called when a user scans and confirms the ephemeral session QR. It is typically invoked by the QRAuth platform or your own scanning UI, not your backend.

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `deviceFingerprint` | string | No | Device identifier for binding. Required when `deviceBinding: true`. |

When the session has `deviceBinding: true`, the server stores the SHA-256 hash of the first claimer's `deviceFingerprint`; later claims must present a fingerprint with the same hash (compared in constant time).

**Response (200):**

```json
{
  "sessionId": "clx...",
  "status": "CLAIMED",
  "scopes": ["door:unlock"],
  "metadata": { "zone": "B2" },
  "expiresAt": "2026-04-10T13:05:00Z",
  "useCount": 1,
  "maxUses": 1
}
```

No token is returned. `status` stays `PENDING` until `useCount` reaches `maxUses`.

**Errors:**

| Status | Cause |
|--------|-------|
| `400` | `deviceFingerprint` missing on a device-bound session |
| `403` | `deviceFingerprint` does not match the bound device |
| `404` | Session not found |
| `409` | Session is not `PENDING` (already claimed or revoked) |
| `410` | Session has expired |

```json
{
  "statusCode": 409,
  "error": "Conflict",
  "message": "Session cannot be claimed in status: CLAIMED"
}
```

---

## Revoke Ephemeral Session

`DELETE /api/v1/ephemeral/:id`

**Headers:** `X-API-Key: <key>`

Immediately invalidates the session. Any subsequent claim attempts will fail. Access your application granted on an earlier claim is managed by your application.

**Response (200):**

```json
{ "sessionId": "clx...", "status": "REVOKED" }
```
