---
title: QR Codes
description: Create, manage, and revoke cryptographically signed QR codes.
---

# QR Codes

QR codes are the core resource of QRAuth. Every code is stored with dual cryptographic signatures: ECDSA-P256 (classical) and SLH-DSA-SHA2-128s (post-quantum, FIPS 205). Both are computed over a canonical payload covering the destination URL, geo-hash, expiry, and a deterministic hash of the content. The SLH-DSA signature is batched through a Merkle tree for throughput — each QR code stores its individual Merkle proof alongside the ECDSA signature. Verification via `GET /v/:token` requires both legs to pass.

## Content Types

| Value | Description | Scan behaviour |
|-------|-------------|----------------|
| `url` | Simple redirect URL | Routes through signed `/v/:token` |
| `vcard` | Contact card (name, phone, email, address) | **Offline** — QR encodes raw vCard 3.0 |
| `coupon` | Discount code with terms and expiry | Routes through signed `/v/:token` |
| `event` | Event details with date, location, ticket link | **Offline** — QR encodes raw iCal VEVENT |
| `pdf` | Hosted PDF asset | Routes through signed `/v/:token` |
| `feedback` | Survey / feedback form | Routes through signed `/v/:token` |

::: tip Offline content types
For printability and native handling, `vcard` and `event` QR codes encode the raw vCard 3.0 / iCal VEVENT string directly in the QR matrix instead of a `/v/:token` URL. Phones trigger the native **Add Contact** or **Add to Calendar** prompt without a network round-trip, and printed business cards or event posters keep working even if the issuer disappears. Rows are still signed and stored server-side for dashboard management, REST verification (`GET /v/:token` works), and audit, but **scanners bypass the QRAuth trust chain** — no signature check, no transparency-log lookup, no fraud signal evaluation, no Trust Reveal at scan time. Pick `url` with a custom landing page if you need per-scan trust signals for contact or event content.
:::

---

## Create QR Code

`POST /api/v1/qrcodes`

**Headers:** `X-API-Key: <key>`

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `label` | string | Yes | Human-readable name shown in the dashboard |
| `contentType` | string | Yes | One of the content type values above |
| `content` | object | Yes | Content payload — schema depends on `contentType` |
| `destinationUrl` | string | No | Override redirect URL (for `url` type this is set inside `content`) |
| `location` | object | No | `{ lat, lng, radiusM }` — enables proximity verification |
| `expiresAt` | string | No | ISO 8601 expiry datetime. Omit for no expiry. |

**`content` schema by type:**

::: code-group

```json [url]
{
  "url": "https://example.com/product"
}
```

```json [vcard]
{
  "firstName": "Jane",
  "lastName": "Doe",
  "email": "jane@example.com",
  "phone": "+1-555-0100",
  "organization": "Acme Corp",
  "url": "https://example.com"
}
```

```json [coupon]
{
  "code": "SAVE20",
  "discount": "20%",
  "terms": "Valid on orders over €50",
  "expiresAt": "2026-12-31T23:59:59Z"
}
```

```json [event]
{
  "title": "Annual Conference",
  "startDate": "2026-09-15T09:00:00Z",
  "endDate": "2026-09-15T18:00:00Z",
  "location": "Berlin, Germany",
  "url": "https://conference.example.com"
}
```

```json [pdf]
{
  "title": "Product Datasheet",
  "assetId": "asset_01HXYZ..."
}
```

```json [feedback]
{
  "title": "How was your experience?",
  "questions": ["Overall rating", "Comments"]
}
```

:::

**Response (201):**

```json
{
  "id": "qr_01HXYZ...",
  "token": "abc123",
  "label": "Product A — Shelf 4B",
  "contentType": "url",
  "content": { "url": "https://example.com/product" },
  "qr_image_url": "https://qrauth.io/api/v1/qrcodes/abc123/image",
  "verificationUrl": "https://qrauth.io/v/abc123",
  "signature": "MEUCIQD...",
  "status": "active",
  "expiresAt": null,
  "createdAt": "2026-04-10T12:00:00Z"
}
```

---

## List QR Codes

`GET /api/v1/qrcodes`

**Headers:** `X-API-Key: <key>`

**Query parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `page` | number | Page number (default: 1) |
| `limit` | number | Results per page (default: 20, max: 100) |
| `status` | string | Filter by `active`, `expired`, or `revoked` |
| `contentType` | string | Filter by content type |
| `search` | string | Full-text search on label |

**Response (200):**

```json
{
  "data": [
    {
      "id": "qr_01HXYZ...",
      "token": "abc123",
      "label": "Product A — Shelf 4B",
      "contentType": "url",
      "status": "active",
      "scanCount": 42,
      "createdAt": "2026-04-10T12:00:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 142,
    "totalPages": 8
  }
}
```

---

## Get QR Code

`GET /api/v1/qrcodes/:token`

**Headers:** `X-API-Key: <key>`

**Response (200):** Full QR code object (same shape as create response, plus `scanCount` and `lastScannedAt`).

---

## Update QR Code

`PATCH /api/v1/qrcodes/:token`

**Headers:** `X-API-Key: <key>`

**Request body:** Any subset of `label`, `content`, `location`, `expiresAt`. Updating `content` re-signs the code automatically.

**Response (200):** Updated QR code object.

---

## Revoke QR Code

`DELETE /api/v1/qrcodes/:token`

**Headers:** `X-API-Key: <key>`

Sets the QR code status to `revoked`. Subsequent scans return a revoked-state verification page. This action is irreversible.

**Response (204):** No content.

---

## Bulk Create

`POST /api/v1/qrcodes/bulk`

**Headers:** `X-API-Key: <key>`

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `codes` | array | Yes | Array of create payloads (same schema as single create). Max 64 items. |

**Response (201):**

```json
{
  "created": 50,
  "failed": 0,
  "results": [
    { "index": 0, "id": "qr_01HXYZ...", "token": "abc123" },
    { "index": 1, "id": "qr_01HABC...", "token": "def456" }
  ]
}
```

If individual items fail validation they are reported in `results` with an `error` field rather than failing the whole batch.
