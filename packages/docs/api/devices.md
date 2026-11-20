---
title: Device Trust
description: Manage trusted devices, trust levels, and per-organization device policies.
---

# Device Trust

The Device Trust API manages the registry of devices each user signs in from (including passkey registration and passkey sign-in). Devices follow a state machine: `NEW → TRUSTED → SUSPICIOUS → REVOKED`. Device endpoints act on the authenticated user's own devices.

| Trust Level | Description |
|-------------|-------------|
| `NEW` | First seen — not yet assessed |
| `TRUSTED` | Marked trusted by the user (`PATCH` or `reverify`) |
| `SUSPICIOUS` | Marked suspicious by the user (`PATCH`) |
| `REVOKED` | Revoked by the user or by the auto-revoke policy; linked passkeys are revoked |

A device is identified by the `X-Device-Fingerprint` request header when present; otherwise by the SHA-256 hash of the browser, OS and device type parsed from the User-Agent.

---

## List Devices

`GET /api/v1/devices`

**Headers:** `Authorization: Bearer <token>` or `X-API-Key: <key>`

Returns the user's non-revoked devices, most recently seen first.

**Response (200):**

```json
{
  "data": [
    {
      "id": "clx...",
      "name": "Jane's iPhone 15",
      "trustLevel": "TRUSTED",
      "fingerprint": "3f9a...",
      "browser": "Safari",
      "os": "iOS",
      "deviceType": "mobile",
      "ipCountry": "GR",
      "ipCity": "Athens",
      "lastSeenAt": "2026-04-10T11:00:00Z",
      "trustedAt": "2026-01-15T08:05:00Z",
      "createdAt": "2026-01-15T08:00:00Z",
      "passkeyCount": 1
    }
  ]
}
```

---

## Get Current Device

`GET /api/v1/devices/current`

Identifies the calling device by fingerprint and returns its record.

**Headers:** `Authorization: Bearer <token>` or `X-API-Key: <key>`

**Response (200):** `{ "device": { ... } }` (same shape as a list item), or `{ "device": null }` if the device is not registered.

---

## Update Device

`PATCH /api/v1/devices/:id`

**Headers:** `Authorization: Bearer <token>` or `X-API-Key: <key>`

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | No | Human-readable device name (1-100 chars) |
| `trustLevel` | string | No | `TRUSTED` or `SUSPICIOUS` |

**Response (200):** `{ "device": { ... } }`. **404** if the device is not found or already revoked.

---

## Revoke Device

`POST /api/v1/devices/:id/revoke` (also `DELETE /api/v1/devices/:id`)

**Headers:** `Authorization: Bearer <token>` or `X-API-Key: <key>`

Sets `trustLevel` to `REVOKED`, revokes the passkeys linked to the device, and ends all of the user's OIDC sessions and tokens. Revocation is permanent.

**Response (200):**

```json
{ "message": "Device revoked." }
```

**404** if the device is not found or already revoked.

---

## Re-verify Device

`POST /api/v1/devices/:id/reverify`

Moves a `SUSPICIOUS` device back to `TRUSTED` for the signed-in user. No request body.

**Headers:** `Authorization: Bearer <token>` or `X-API-Key: <key>`

**Response (200):**

```json
{ "message": "Device re-verified as trusted." }
```

**409** if the device is not in the `SUSPICIOUS` state.

---

## Get Device Policy

`GET /api/v1/devices/policy`

**Headers:** `Authorization: Bearer <token>` or `X-API-Key: <key>`

**Response (200):**

```json
{
  "policy": {
    "organizationId": "clx...",
    "maxDevices": 10,
    "requireBiometric": false,
    "geoFenceLat": null,
    "geoFenceLng": null,
    "geoFenceRadiusKm": null,
    "autoRevokeAfterDays": 90,
    "bridgePolicy": "required"
  }
}
```

Returns `{ "policy": null }` if the organization has no policy.

---

## Set Device Policy

`PUT /api/v1/devices/policy`

**Headers:** `Authorization: Bearer <token>` or `X-API-Key: <key>`. Requires the OWNER or ADMIN role.

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `autoRevokeAfterDays` | number \| null | No | Revoke devices inactive for this many days (1-365). The cleanup worker applies it hourly to devices of the organization's members. `null` = disabled. |
| `maxDevices` | number | No | Stored with the policy (1-100) |
| `requireBiometric` | boolean | No | Stored with the policy |
| `geoFenceLat`, `geoFenceLng`, `geoFenceRadiusKm` | number \| null | No | Stored with the policy |
| `bridgePolicy` | string | No | `required`, `optional` or `disabled`. Post-quantum WebAuthn bridge setting; see [ALGORITHM.md](https://github.com/qrauth-io/qrauth/blob/main/ALGORITHM.md). |

**Response (200):** `{ "policy": { ... } }`.

::: warning Policy scope
Device policies apply to the entire organization.
:::
