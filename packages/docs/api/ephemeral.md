---
title: Ephemeral Sessions
description: Time-limited, scope-constrained access sessions — no account creation required.
---

# Ephemeral Sessions

Ephemeral sessions grant temporary, scoped access without requiring end users to have a QRAuth account. A developer creates a session server-side, encodes it in a QR code, and distributes it. When a user scans and claims the session they receive a short-lived JWT scoped to exactly the permissions you specified.

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
| `ttl` | string | Yes | Duration string: `"5m"`, `"1h"`, `"2d"`, `"7d"` (max `"30d"`) |
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

**Response (200):** Full session object (same shape as create response, plus `claimedAt` and `claimedByDevice` if claimed).

---

## Claim Ephemeral Session

`POST /api/v1/ephemeral/:token/claim`

This endpoint is called when a user scans and confirms the ephemeral session QR. It is typically invoked by the QRAuth platform or your own scanning UI, not your backend.

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `deviceFingerprint` | string | No | Device identifier for binding. Required when `deviceBinding: true`. |

**Response (200):**

```json
{
  "jwt": "eyJhbGc...",
  "scopes": ["door:unlock"],
  "expiresAt": "2026-04-10T13:05:00Z",
  "metadata": { "zone": "B2" }
}
```

The returned `jwt` is a signed Bearer token. Verify it server-side using your App's public key from `GET /api/v1/apps/:id/public-key`.

**Error (409) — already claimed:**

```json
{
  "statusCode": 409,
  "error": "Conflict",
  "message": "Session has already been claimed"
}
```

---

## Revoke Ephemeral Session

`DELETE /api/v1/ephemeral/:id`

**Headers:** `X-API-Key: <key>`

Immediately invalidates the session. Any subsequent claim attempts will fail. Already-issued JWTs remain valid until their own expiry — revoke at the resource level if immediate cut-off is required.

**Response (204):** No content.
