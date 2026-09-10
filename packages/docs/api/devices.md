---
title: Device Trust
description: Manage trusted devices, trust levels, and per-organization device policies.
---

# Device Trust

The Device Trust API lets your organization manage the registry of devices that can scan your QR codes or approve auth sessions. Devices follow a state machine: `NEW → TRUSTED → SUSPICIOUS → REVOKED`.

| Trust Level | Description |
|-------------|-------------|
| `NEW` | First seen — not yet assessed |
| `TRUSTED` | Manually approved or passed automated trust checks |
| `SUSPICIOUS` | Flagged by fraud signals — limited or blocked access |
| `REVOKED` | Permanently blocked |

---

## List Devices

`GET /api/v1/devices`

**Headers:** `X-API-Key: <key>`

**Query parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `trustLevel` | string | Filter by `NEW`, `TRUSTED`, `SUSPICIOUS`, or `REVOKED` |
| `page` | number | Page number (default: 1) |
| `limit` | number | Results per page (default: 20, max: 100) |

**Response (200):**

```json
{
  "data": [
    {
      "id": "dev_01HXYZ...",
      "name": "Jane's iPhone 15",
      "trustLevel": "TRUSTED",
      "fingerprint": "fp_abc...",
      "lastSeenAt": "2026-04-10T11:00:00Z",
      "registeredAt": "2026-01-15T08:00:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 7,
    "totalPages": 1
  }
}
```

---

## Get Current Device

`GET /api/v1/devices/current`

Identifies the calling device by fingerprint and returns its trust record. Useful for device-aware SDKs to check their own trust level before performing sensitive operations.

**Headers:** `X-API-Key: <key>`

**Response (200):** Single device object (same shape as list item).

**Response (404):** Device not yet registered.

---

## Update Device

`PATCH /api/v1/devices/:id`

**Headers:** `X-API-Key: <key>`

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | No | Human-readable device name |
| `trustLevel` | string | No | `NEW`, `TRUSTED`, `SUSPICIOUS`, or `REVOKED` |

**Response (200):** Updated device object.

---

## Revoke Device

`POST /api/v1/devices/:id/revoke`

**Headers:** `X-API-Key: <key>`

Sets `trustLevel` to `REVOKED`. The device can no longer approve auth sessions or claim ephemeral sessions. This action is permanent — use `reverify` if you want a recoverable state.

**Response (200):**

```json
{
  "id": "dev_01HXYZ...",
  "trustLevel": "REVOKED",
  "revokedAt": "2026-04-10T12:00:00Z"
}
```

---

## Re-verify Device

`POST /api/v1/devices/:id/reverify`

Transitions a `SUSPICIOUS` device back to `TRUSTED` after manual review or successful re-authentication. Has no effect on `REVOKED` devices.

**Headers:** `X-API-Key: <key>`

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `reason` | string | No | Audit note recorded on the device record |

**Response (200):**

```json
{
  "id": "dev_01HXYZ...",
  "trustLevel": "TRUSTED",
  "reverifiedAt": "2026-04-10T12:00:00Z"
}
```

---

## Get Device Policy

`GET /api/v1/devices/policy`

**Headers:** `X-API-Key: <key>`

**Response (200):**

```json
{
  "maxDevices": 5,
  "requireBiometric": false,
  "geoFence": null,
  "autoRevokeAfterDays": 90
}
```

---

## Set Device Policy

`PUT /api/v1/devices/policy`

**Headers:** `X-API-Key: <key>`

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `maxDevices` | number | No | Maximum number of trusted devices per user. `null` = unlimited. |
| `requireBiometric` | boolean | No | Require biometric confirmation before approving sessions |
| `geoFence` | object | No | `{ lat, lng, radiusKm }` — block devices outside this area. `null` = disabled. |
| `autoRevokeAfterDays` | number | No | Automatically revoke devices inactive for this many days. `null` = disabled. |

**Response (200):** Updated policy object.

::: warning Policy scope
Device policies apply to the entire organization. Changes take effect immediately for subsequent operations. Existing sessions are not invalidated retroactively.
:::
